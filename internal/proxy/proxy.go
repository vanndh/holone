// Package proxy implements a client-independent, inspecting reverse proxy.
//
// Any AI client that lets you override its API base URL (Claude Code, Kilo
// Code, Cline, Cursor, Aider, ...) can be pointed at this proxy instead of the
// real provider. The proxy forwards the request upstream and inspects the
// streamed response for injected tool calls / malicious payloads — the attack
// pattern used by hostile "cheap API" providers.
//
// Mode Monitor (default) forwards every byte to the client *first* and inspects
// a copy afterwards, so it adds no meaningful latency. Mode Block holds back
// only suspicious tool-call blocks until they are verified, replacing them with
// a safe note if they are malicious.
package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vanndh/holone/internal/inspect"
)

// Mode controls how the proxy treats detected payloads.
type Mode int

const (
	ModeMonitor Mode = iota // forward everything, alert on detection
	ModeBlock               // strip malicious tool calls before they reach the client
)

func (m Mode) String() string {
	if m == ModeBlock {
		return "block"
	}
	return "monitor"
}

// ParseMode maps a CLI string to a Mode.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "monitor":
		return ModeMonitor, nil
	case "block":
		return ModeBlock, nil
	default:
		return ModeMonitor, fmt.Errorf("unknown mode %q (want monitor|block)", s)
	}
}

// Decision is the audit record emitted per inspected response.
type Decision struct {
	Time        string            `json:"time"`
	Protocol    string            `json:"protocol"`
	Mode        string            `json:"mode"`
	Path        string            `json:"path"`
	ClientTools bool              `json:"client_declared_tools"`
	Verdict     string            `json:"verdict"` // clean | alert | blocked
	MaxSeverity string            `json:"max_severity"`
	Protection  string            `json:"protection"` // protected | monitor-only | unsupported
	Findings    []inspect.Finding `json:"findings,omitempty"`
}

// Protection levels reported in Decision.Protection.
const (
	// ProtectionProtected: the stream is parsed and Block mode can remove a
	// malicious or undeclared tool call before the client sees it.
	ProtectionProtected = "protected"
	// ProtectionMonitorOnly: bytes are inspected but never rewritten (Monitor
	// mode, or a protocol whose stream we do not rewrite).
	ProtectionMonitorOnly = "monitor-only"
	// ProtectionUnsupported: Block mode was requested but the stream format
	// cannot be enforced, so only detection happens.
	ProtectionUnsupported = "unsupported"
)

// Config configures a Proxy.
type Config struct {
	Upstream   *url.URL
	Engine     *inspect.Engine
	Mode       Mode
	Logger     *Logger
	OnDecision func(Decision) // optional callback (CLI prints alerts)

	// MaxRequestBytes / MaxResponseBytes cap buffered bodies; zero means the
	// defaults (32 MiB / 64 MiB). Bodies over the cap are rejected, never
	// truncated.
	MaxRequestBytes  int64
	MaxResponseBytes int64
}

// Proxy is an http.Handler.
type Proxy struct {
	cfg         Config
	client      *http.Client
	maxRequest  int64
	maxResponse int64
}

// New builds a Proxy. A streaming-friendly HTTP client (no overall timeout) is
// created so long-lived SSE responses are not cut off.
func New(cfg Config) *Proxy {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 120 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &Proxy{
		cfg:         cfg,
		client:      &http.Client{Transport: transport, Timeout: 0},
		maxRequest:  firstPositive(cfg.MaxRequestBytes, maxRequestBody),
		maxResponse: firstPositive(cfg.MaxResponseBytes, maxResponseBody),
	}
}

// firstPositive returns v when it is a usable limit, else def.
func firstPositive(v, def int64) int64 {
	if v > 0 {
		return v
	}
	return def
}

// hop-by-hop headers must not be forwarded (RFC 7230 §6.1).
var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

const (
	maxRequestBody  = 32 << 20 // default request-body cap (Config.MaxRequestBytes)
	maxResponseBody = 64 << 20 // default buffered-response cap (Config.MaxResponseBytes)

	// maxToolCallBytes bounds the tool-call data held back in Block mode. Past
	// it the call is no longer buffered: it is replaced with the safety note
	// and flagged as proto-toolcall-oversized (fail closed, bounded memory).
	maxToolCallBytes = 8 << 20
)

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Buffer the request body so we can both inspect it (to learn which tools
	// the client declared) and forward it upstream. A body over the cap is
	// rejected outright: forwarding a truncated request would corrupt it.
	body, err := readBodyLimit(r.Body, p.maxRequest)
	r.Body.Close()
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			http.Error(w, "holone: request body exceeds the "+humanBytes(p.maxRequest)+" limit", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "holone: read request: "+err.Error(), http.StatusBadGateway)
		return
	}
	declaredTools := declaredToolNames(body)
	protocol := detectProtocol(r.URL.Path)

	// Build the upstream request.
	outURL := *p.cfg.Upstream
	outURL.Path = singleJoin(p.cfg.Upstream.Path, r.URL.Path)
	outURL.RawQuery = r.URL.RawQuery
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "holone: build request: "+err.Error(), http.StatusBadGateway)
		return
	}
	copyHeaders(outReq.Header, r.Header)
	for _, h := range hopHeaders {
		outReq.Header.Del(h)
	}
	// Force identity encoding so we can parse the response stream verbatim.
	outReq.Header.Set("Accept-Encoding", "identity")
	outReq.Host = p.cfg.Upstream.Host

	resp, err := p.client.Do(outReq)
	if err != nil {
		http.Error(w, "holone: upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	st := &streamState{
		proxy:         p,
		protocol:      protocol,
		declaredTools: declaredTools,
		path:          r.URL.Path,
	}

	isSSE := strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream")

	rb, bodyErr := openResponseBody(resp)
	if bodyErr != nil {
		var encErr *encodingError
		errors.As(bodyErr, &encErr)
		name := "unknown"
		if encErr != nil {
			name = encErr.Encoding
		}
		if p.cfg.Mode == ModeBlock {
			// Fail closed: uninspected (and possibly corrupt) bytes must never
			// reach the client just because the encoding was hostile.
			st.blocked = true
			st.streaming = isSSE
			http.Error(w, "holone: upstream returned unsupported Content-Encoding: "+name+"; response cannot be safely inspected", http.StatusBadGateway)
			p.report(st)
			return
		}
		// Monitor: forward the bytes untouched with the original encoding and
		// surface the inspection gap as a finding.
		st.add(inspect.Finding{
			RuleID:      inspect.RuleAnomalyEncodingUninspected,
			Category:    "protocol-anomaly",
			Severity:    inspect.SevMedium.String(),
			Match:       "Content-Encoding: " + name,
			Source:      "protocol",
			Description: "The upstream used a Content-Encoding holone cannot decode (" + name + "); the body was forwarded uninspected. Use block mode to fail closed.",
		})
		rb = bodyStream{r: rb.r, enc: name}
	}
	defer rb.Close()

	if isSSE {
		p.serveStream(w, resp, st, rb)
	} else {
		p.serveBuffered(w, resp, st, rb)
	}
}

// serveStream copies response headers, then dispatches to a protocol-specific
// streaming inspector.
func (p *Proxy) serveStream(w http.ResponseWriter, resp *http.Response, st *streamState, body bodyStream) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		// Cannot stream; fall back to buffered handling.
		p.serveBuffered(w, resp, st, body)
		return
	}
	st.streaming = true
	writeResponseHeaders(w, resp, true, body.decoded)
	w.WriteHeader(resp.StatusCode)
	flusher.Flush()

	reader := bufio.NewReaderSize(body.r, 16<<10)
	switch st.protocol {
	case "anthropic":
		p.streamAnthropic(w, flusher, reader, st)
	case "openai":
		p.streamOpenAI(w, flusher, reader, st)
	case "responses":
		p.streamResponses(w, flusher, reader, st)
	default:
		p.streamGeneric(w, flusher, reader, st)
	}
	p.report(st)
}

// serveBuffered handles non-streaming responses: buffer, inspect, then forward
// (Monitor) or replace if malicious (Block).
func (p *Proxy) serveBuffered(w http.ResponseWriter, resp *http.Response, st *streamState, body bodyStream) {
	raw, err := readBodyLimit(body.r, p.maxResponse)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			http.Error(w, "holone: upstream response exceeds the "+humanBytes(p.maxResponse)+" limit; refusing to forward truncated data", http.StatusBadGateway)
			return
		}
		http.Error(w, "holone: read upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	st.add(p.cfg.Engine.Inspect(string(raw), "response-body")...)
	if names := responseToolNames(raw); len(names) > 0 {
		for _, n := range names {
			st.checkToolCall(n)
		}
	} else {
		st.checkAnomaly(bodyMentionsTool(raw))
	}

	blocked := false
	if p.cfg.Mode == ModeBlock && inspect.MaxSeverity(st.findings) == inspect.SevHigh {
		raw = []byte(`{"type":"error","error":{"type":"holone_blocked","message":"Response blocked by holone: suspected malicious provider injection."}}`)
		blocked = true
	}
	st.blocked = blocked

	writeResponseHeaders(w, resp, false, body.decoded)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(raw)))
	code := resp.StatusCode
	if blocked {
		w.Header().Set("Content-Type", "application/json")
		code = http.StatusOK
	}
	w.WriteHeader(code)
	w.Write(raw)
	p.report(st)
}

// report logs and surfaces the final decision for a request.
func (p *Proxy) report(st *streamState) {
	inspect.SortFindings(st.findings)
	verdict := "clean"
	if st.blocked {
		verdict = "blocked"
	} else if len(st.findings) > 0 {
		verdict = "alert"
	}
	d := Decision{
		Time:        time.Now().UTC().Format(time.RFC3339),
		Protocol:    st.protocol,
		Mode:        p.cfg.Mode.String(),
		Path:        st.path,
		ClientTools: len(st.declaredTools) > 0,
		Verdict:     verdict,
		MaxSeverity: inspect.MaxSeverity(st.findings).String(),
		Protection:  protectionFor(st.protocol, p.cfg.Mode, st.streaming),
		Findings:    st.findings,
	}
	if p.cfg.Logger != nil {
		p.cfg.Logger.Log(d)
	}
	if p.cfg.OnDecision != nil && verdict != "clean" {
		p.cfg.OnDecision(d)
	}
}

// protectionFor reports how much enforcement is actually possible for this
// response. Block mode can only rewrite a stream it understands; a buffered
// body is always fully inspected and can be replaced as a whole.
func protectionFor(protocol string, mode Mode, streaming bool) string {
	if mode != ModeBlock {
		return ProtectionMonitorOnly
	}
	if !streaming {
		return ProtectionProtected
	}
	switch protocol {
	case "anthropic", "openai", "responses":
		return ProtectionProtected
	default:
		return ProtectionUnsupported
	}
}

// streamState carries per-request inspection state.
type streamState struct {
	proxy         *Proxy
	protocol      string
	declaredTools map[string]struct{}
	path          string
	findings      []inspect.Finding
	findingKeys   map[string]struct{}
	sawTool       bool
	blocked       bool
	streaming     bool
}

// add appends findings, deduplicating by (rule id, match) so overlapping
// inspection windows and repeated stream events never duplicate a hit.
func (s *streamState) add(fs ...inspect.Finding) {
	if s.findingKeys == nil {
		s.findingKeys = make(map[string]struct{}, len(fs))
	}
	for _, f := range fs {
		key := f.RuleID + "\x00" + f.Match
		if _, ok := s.findingKeys[key]; ok {
			continue
		}
		s.findingKeys[key] = struct{}{}
		s.findings = append(s.findings, f)
	}
}

// checkAnomaly adds a high-severity finding if a tool call appeared although
// the client never advertised any tools — a strong injection signal. Used by
// paths that can detect a call but not its name (buffered bodies).
func (s *streamState) checkAnomaly(sawTool bool) {
	if sawTool {
		s.sawTool = true
	}
	if s.sawTool && len(s.declaredTools) == 0 {
		s.add(unsolicitedToolFinding())
	}
}

// checkToolCall validates a returned tool call against the tools the client
// declared and records a synthetic finding when it is anomalous. It returns the
// findings it produced so a Block-mode path can decide on them immediately.
//
// The provider returning a name the client never declared is just as strong an
// injection signal as returning any call at all; only the *name* and the
// declared names are recorded, never the tool arguments.
func (s *streamState) checkToolCall(name string) []inspect.Finding {
	s.sawTool = true
	if len(s.declaredTools) == 0 {
		f := unsolicitedToolFinding()
		s.add(f)
		return []inspect.Finding{f}
	}
	if name == "" {
		return nil
	}
	if _, ok := s.declaredTools[name]; ok {
		return nil
	}
	f := inspect.Finding{
		RuleID:      inspect.RuleAnomalyToolNameNotDeclared,
		Category:    "protocol-anomaly",
		Severity:    inspect.SevHigh.String(),
		Match:       truncate(name, 160),
		Source:      "protocol",
		Description: "The provider returned tool call \"" + truncate(name, 160) + "\", which the client never declared. Declared tools: " + declaredList(s.declaredTools) + ".",
	}
	s.add(f)
	return []inspect.Finding{f}
}

func unsolicitedToolFinding() inspect.Finding {
	return inspect.Finding{
		RuleID:      inspect.RuleAnomalyUnsolicitedTool,
		Category:    "protocol-anomaly",
		Severity:    inspect.SevHigh.String(),
		Match:       "tool call present without client-declared tools",
		Source:      "protocol",
		Description: "The provider injected a tool call the client never requested.",
	}
}

// declaredList renders sorted declared tool names (never arguments) for a
// finding description.
func declaredList(names map[string]struct{}) string {
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return "(none)"
	}
	return truncate(strings.Join(out, ", "), 300)
}

// oversizedToolFinding flags a buffered tool call that exceeded
// maxToolCallBytes and was therefore replaced with a safety note.
func oversizedToolFinding(name string) inspect.Finding {
	label := "tool call"
	if name != "" {
		label = "tool call \"" + truncate(name, 80) + "\""
	}
	return inspect.Finding{
		RuleID:      inspect.RuleAnomalyOversizedToolCall,
		Category:    "protocol-anomaly",
		Severity:    inspect.SevHigh.String(),
		Match:       label + " exceeded " + humanBytes(maxToolCallBytes),
		Source:      "protocol",
		Description: "The provider streamed a " + label + " larger than the " + humanBytes(maxToolCallBytes) + " inspection cap; it could not be verified and was replaced with a safety note.",
	}
}

// truncate bounds a finding field (bytes, ASCII-safe for our use).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\u2026"
}

// --- helpers ---------------------------------------------------------------

func detectProtocol(path string) string {
	switch {
	case strings.Contains(path, "/chat/completions"):
		return "openai"
	case strings.Contains(path, "/responses"):
		// OpenAI Responses API (/v1/responses). Checked before /messages so a
		// provider-side path prefix cannot shadow it.
		return "responses"
	case strings.Contains(path, "/messages"):
		return "anthropic"
	default:
		return "generic"
	}
}

// declaredToolNames parses the tool names a request advertises:
//
//	Anthropic        tools[].name
//	OpenAI           tools[].function.name
//	legacy OpenAI    functions[].name
//
// A nil result means the client declared no tools at all.
func declaredToolNames(body []byte) map[string]struct{} {
	var m struct {
		Tools []struct {
			Name     string `json:"name"`
			Function struct {
				Name string `json:"name"`
			} `json:"function"`
		} `json:"tools"`
		Functions []struct {
			Name string `json:"name"`
		} `json:"functions"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	names := make(map[string]struct{}, len(m.Tools)+len(m.Functions))
	for _, t := range m.Tools {
		n := t.Name
		if n == "" {
			n = t.Function.Name
		}
		if n != "" {
			names[n] = struct{}{}
		}
	}
	for _, f := range m.Functions {
		if f.Name != "" {
			names[f.Name] = struct{}{}
		}
	}
	return names
}

// responseToolNames extracts tool-call names from a buffered (non-streaming)
// response body so the same declared-name validation that runs on streams also
// applies to whole-body responses (Anthropic, Chat Completions, legacy
// function_call, Responses API).
func responseToolNames(body []byte) []string {
	var m struct {
		Content []struct {
			Type string `json:"type"`
			Name string `json:"name"`
		} `json:"content"`
		Choices []struct {
			Message struct {
				ToolCalls []struct {
					Function struct {
						Name string `json:"name"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
		FunctionCall struct {
			Name string `json:"name"`
		} `json:"function_call"`
		Output []struct {
			Type string `json:"type"`
			Name string `json:"name"`
		} `json:"output"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	var names []string
	for _, c := range m.Content {
		if c.Type == "tool_use" && c.Name != "" {
			names = append(names, c.Name)
		}
	}
	for _, ch := range m.Choices {
		for _, tc := range ch.Message.ToolCalls {
			if tc.Function.Name != "" {
				names = append(names, tc.Function.Name)
			}
		}
	}
	if m.FunctionCall.Name != "" {
		names = append(names, m.FunctionCall.Name)
	}
	for _, o := range m.Output {
		if o.Type == "function_call" && o.Name != "" {
			names = append(names, o.Name)
		}
	}
	return names
}

// bodyMentionsTool is a coarse check for a tool/function call in a buffered
// (non-streaming) response body.
func bodyMentionsTool(body []byte) bool {
	s := string(body)
	return strings.Contains(s, `"tool_use"`) ||
		strings.Contains(s, `"tool_calls"`) ||
		strings.Contains(s, `"function_call"`)
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
	dst.Del("Host")
}

// writeResponseHeaders copies upstream headers to the client. Content-Encoding
// is stripped only when we actually decoded the body — an encoding we cannot
// decode is forwarded byte-for-byte, and then the header must be preserved or
// the client would corrupt the payload.
func writeResponseHeaders(w http.ResponseWriter, resp *http.Response, streaming, decoded bool) {
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	for _, h := range hopHeaders {
		w.Header().Del(h)
	}
	if decoded {
		w.Header().Del("Content-Encoding")
		w.Header().Del("Content-Length")
	}
	if streaming {
		// Length is unknown for a stream; ensure no stale length is forwarded.
		w.Header().Del("Content-Length")
	}
}

func singleJoin(a, b string) string {
	if a == "" || a == "/" {
		return b
	}
	return strings.TrimRight(a, "/") + "/" + strings.TrimLeft(b, "/")
}

// Logger writes newline-delimited JSON audit records, concurrency-safe.
type Logger struct {
	mu sync.Mutex
	w  io.Writer
}

// NewLogger wraps an io.Writer as a jsonl audit logger.
func NewLogger(w io.Writer) *Logger { return &Logger{w: w} }

// Log marshals rec as a single JSON line.
func (l *Logger) Log(rec any) {
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.w.Write(b)
	l.w.Write([]byte("\n"))
}
