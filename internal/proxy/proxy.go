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
	"unicode/utf8"

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

// ParseProxyProtocol validates an explicit proxy wire-protocol override.
// Empty or "auto" means infer from URL path and SSE frame sniffing.
func ParseProxyProtocol(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return "auto", nil
	case "anthropic":
		return "anthropic", nil
	case "openai", "chat-completions":
		return "openai", nil
	case "responses":
		return "responses", nil
	case "gemini":
		return "gemini", nil
	default:
		return "", fmt.Errorf("unknown protocol %q (want auto|anthropic|openai|responses|gemini)", s)
	}
}

func normalizeProxyProtocol(s string) string {
	p, err := ParseProxyProtocol(s)
	if err != nil || p == "auto" {
		return ""
	}
	return p
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
	Upstream      *url.URL
	Engine        *inspect.Engine
	Mode          Mode
	Protocol      string  // optional override: auto | anthropic | openai | responses | gemini
	EgressDLP     DLPMode // optional outbound secret inspection (off | warn | block | redact)
	LogAlertsOnly bool    // skip writing clean decisions to Logger
	Logger        *Logger
	OnDecision    func(Decision) // optional callback (CLI prints alerts)

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
		// Bound a hostile upstream's response headers: without a cap the header
		// block can grow until the process runs out of memory.
		MaxResponseHeaderBytes: 1 << 20,
	}
	return &Proxy{
		cfg: cfg,
		client: &http.Client{
			Transport:     transport,
			Timeout:       0,
			CheckRedirect: checkUpstreamRedirect(cfg.Upstream),
		},
		maxRequest:  firstPositive(cfg.MaxRequestBytes, maxRequestBody),
		maxResponse: firstPositive(cfg.MaxResponseBytes, maxResponseBody),
	}
}

// maxRedirects is the longest redirect chain holone will follow.
const maxRedirects = 5

// redirectError is returned by CheckRedirect. ServeHTTP unwraps it and renders
// only its reason, which never contains the redirect target's path or query —
// a hostile Location header must not leak credentials into holone's output.
type redirectError struct{ reason string }

func (e *redirectError) Error() string { return "upstream redirect blocked: " + e.reason }

// checkUpstreamRedirect only follows same-origin redirects (scheme, host and
// effective port) and caps the chain length, so a hostile provider cannot bounce
// holone into internal services (SSRF) or re-route the request elsewhere.
func checkUpstreamRedirect(origin *url.URL) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects {
			return &redirectError{reason: fmt.Sprintf("stopped after %d redirects", maxRedirects)}
		}
		if origin == nil || !sameOrigin(origin, req.URL) {
			return &redirectError{reason: "redirect to " + req.URL.Scheme + "://" + req.URL.Host + " is not same-origin"}
		}
		return nil
	}
}

// sameOrigin reports whether two URLs share scheme, host and port.
func sameOrigin(a, b *url.URL) bool {
	if !strings.EqualFold(a.Scheme, b.Scheme) || !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	return originPort(a) == originPort(b)
}

// originPort returns the explicit port, or the scheme default.
func originPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
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

func stripHopHeaders(h http.Header) {
	for _, connVal := range h.Values("Connection") {
		for _, field := range strings.Split(connVal, ",") {
			if name := strings.TrimSpace(field); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopHeaders {
		h.Del(name)
	}
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
	// the client declared and optionally apply egress DLP) and forward it upstream.
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

	outURL := *p.cfg.Upstream
	outURL.Path = singleJoin(p.cfg.Upstream.Path, r.URL.Path)
	outURL.RawQuery = r.URL.RawQuery

	protocol := normalizeProxyProtocol(p.cfg.Protocol)
	if protocol == "" {
		protocol = detectProtocol(r.URL.Path)
		if protocol == "generic" {
			protocol = detectProtocol(outURL.Path)
		}
	}

	declaredTools := declaredToolNames(body)

	var dlpFindings []inspect.Finding
	switch p.cfg.EgressDLP {
	case DLPModeWarn:
		dlpFindings = inspect.InspectSecrets(string(body), "egress-request")
	case DLPModeRedact:
		redacted, hits := inspect.RedactSecrets(string(body), "egress-request")
		if len(hits) > 0 {
			body = []byte(redacted)
			dlpFindings = hits
		}
	case DLPModeBlock:
		dlpFindings = inspect.InspectSecrets(string(body), "egress-request")
		if len(dlpFindings) > 0 {
			st := &streamState{
				proxy:         p,
				protocol:      protocol,
				declaredTools: declaredTools,
				path:          r.URL.Path,
				blocked:       true,
			}
			st.add(dlpFindings...)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"type":"error","error":{"type":"holone_dlp_blocked","message":"Request blocked by holone egress DLP: potential secret detected in outbound prompt."}}`))
			p.report(st)
			return
		}
	}

	// Build the upstream request.
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "holone: build request: "+err.Error(), http.StatusBadGateway)
		return
	}
	copyHeaders(outReq.Header, r.Header)
	stripHopHeaders(outReq.Header)
	outReq.Header.Del("Content-Length")
	// Force identity encoding so we can parse the response stream verbatim.
	outReq.Header.Set("Accept-Encoding", "identity")
	outReq.Host = p.cfg.Upstream.Host

	resp, err := p.client.Do(outReq)
	if err != nil {
		// A blocked redirect must not echo the target URL (it may carry query
		// parameters or credentials); only the sanitized reason is surfaced.
		var re *redirectError
		if errors.As(err, &re) {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
			http.Error(w, "holone: "+re.Error(), http.StatusBadGateway)
			return
		}
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		http.Error(w, "holone: upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	st := &streamState{
		proxy:          p,
		protocol:       protocol,
		declaredTools:  declaredTools,
		path:           r.URL.Path,
		egressFindings: dlpFindings,
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
	if st.protocol == "generic" {
		var sniffed string
		sniffed, reader = sniffSSEProtocol(reader)
		if sniffed != "" {
			st.protocol = sniffed
		}
	}

	switch st.protocol {
	case "anthropic":
		p.streamAnthropic(w, flusher, reader, st)
	case "openai":
		p.streamOpenAI(w, flusher, reader, st)
	case "responses":
		p.streamResponses(w, flusher, reader, st)
	case "gemini":
		p.streamGemini(w, flusher, reader, st)
	default:
		p.streamGeneric(w, flusher, reader, st)
	}
	p.report(st)
}

// sniffSSEProtocol peeks the leading SSE lines (capped at 16 KiB) to classify
// an unrecognized path by its wire frames, replaying every byte verbatim.
func sniffSSEProtocol(r *bufio.Reader) (string, *bufio.Reader) {
	const maxSniffBytes = 16 << 10
	var buf bytes.Buffer
	var proto string
	for buf.Len() < maxSniffBytes {
		frag, err := r.ReadSlice('\n')
		if len(frag) > 0 {
			buf.Write(frag)
			line := buf.String()
			switch {
			case strings.Contains(line, `"object":"chat.completion.chunk"`),
				strings.Contains(line, `"object": "chat.completion.chunk"`):
				proto = "openai"
			case strings.Contains(line, "event: message_start"),
				strings.Contains(line, `"type":"message_start"`),
				strings.Contains(line, `"type": "message_start"`),
				strings.Contains(line, `"type":"content_block_start"`),
				strings.Contains(line, `"type": "content_block_start"`):
				proto = "anthropic"
			case strings.Contains(line, "event: response.created"),
				strings.Contains(line, `"type":"response.created"`),
				strings.Contains(line, `"type": "response.created"`),
				strings.Contains(line, `"type":"response.output_item.added"`),
				strings.Contains(line, `"type": "response.output_item.added"`):
				proto = "responses"
			case (strings.Contains(line, `"candidates":[`) || strings.Contains(line, `"candidates": [`)) &&
				(strings.Contains(line, `"parts":[`) || strings.Contains(line, `"parts": [`)):
				proto = "gemini"
			}
			if proto != "" {
				break
			}
			// Stop after the first complete frame (blank line) so unknown formats
			// do not wait for more frames on an open stream.
			if bytes.Equal(frag, []byte("\n")) || bytes.Equal(frag, []byte("\r\n")) {
				break
			}
		}
		if err != nil && err != bufio.ErrBufferFull {
			break
		}
	}
	return proto, bufio.NewReaderSize(io.MultiReader(bytes.NewReader(buf.Bytes()), r), 16<<10)
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

	toolCalls := extractBufferedToolCalls(raw)
	var toolFindings []inspect.Finding
	hasToolAnomaly := false
	if len(toolCalls) > 0 {
		if st.protocol == "generic" && toolCalls[0].protocol != "" {
			st.protocol = toolCalls[0].protocol
		}
		for _, tc := range toolCalls {
			nf := st.checkToolCall(tc.name)
			if len(nf) > 0 {
				hasToolAnomaly = true
			}
			af := p.cfg.Engine.InspectToolArgs(tc.name, tc.args, "tool_call:"+tc.name)
			st.add(af...)
			toolFindings = append(toolFindings, nf...)
			toolFindings = append(toolFindings, af...)
		}
	} else {
		st.checkAnomaly(bodyMentionsTool(raw))
		if st.sawTool && len(st.declaredTools) == 0 {
			hasToolAnomaly = true
		}
	}

	blocked := false
	if p.cfg.Mode == ModeBlock {
		if len(toolCalls) > 0 || bodyMentionsTool(raw) {
			if inspect.MaxSeverity(toolFindings) == inspect.SevHigh || hasToolAnomaly ||
				(len(toolCalls) == 0 && inspect.MaxSeverity(st.findings) == inspect.SevHigh) {
				blocked = true
			}
		} else if !isStructuredTextResponse(raw) && inspect.MaxSeverity(st.findings) == inspect.SevHigh {
			blocked = true
		}
	}

	if blocked {
		reason := firstRuleID(toolFindings, st.findings)
		raw = bufferedBlockedPayload(st.protocol, reason)
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

func bufferedBlockedPayload(protocol, reason string) []byte {
	switch protocol {
	case "openai":
		b, _ := json.Marshal(map[string]any{
			"id":     "holone",
			"object": "chat.completion",
			"choices": []any{map[string]any{
				"index": 0,
				"message": map[string]any{
					"role":    "assistant",
					"content": fmt.Sprintf("[holone blocked a suspicious tool call: %s]", reason),
				},
				"finish_reason": "stop",
			}},
		})
		return b
	case "gemini":
		b, _ := json.Marshal(map[string]any{
			"candidates": []any{map[string]any{
				"content": map[string]any{
					"role":  "model",
					"parts": []any{map[string]any{"text": fmt.Sprintf("[holone blocked a suspicious tool call: %s]", reason)}},
				},
				"finishReason": "STOP",
			}},
		})
		return b
	default:
		b, _ := json.Marshal(map[string]any{
			"type": "error",
			"error": map[string]any{
				"type":    "holone_blocked",
				"message": fmt.Sprintf("Response blocked by holone: suspected malicious provider injection (%s).", reason),
			},
		})
		return b
	}
}

// report logs and surfaces the final decision for a request.
func (p *Proxy) report(st *streamState) {
	st.add(st.egressFindings...)
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
	if p.cfg.Logger != nil && (!p.cfg.LogAlertsOnly || verdict != "clean") {
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
	case "anthropic", "openai", "responses", "gemini":
		return ProtectionProtected
	default:
		return ProtectionUnsupported
	}
}

// streamState carries per-request inspection state.
type streamState struct {
	proxy          *Proxy
	protocol       string
	declaredTools  map[string]struct{}
	path           string
	findings       []inspect.Finding
	egressFindings []inspect.Finding
	findingKeys    map[string]struct{}
	sawTool        bool
	blocked        bool
	streaming      bool
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
		s.add(s.applyEnginePolicy(unsolicitedToolFinding())...)
	}
}

// checkToolCall validates a returned tool call against the tools the client
// declared and records a synthetic finding when it is anomalous. It returns the
// findings it produced so a Block-mode path can decide on them immediately.
func (s *streamState) checkToolCall(name string) []inspect.Finding {
	s.sawTool = true
	if len(s.declaredTools) == 0 {
		fs := s.applyEnginePolicy(unsolicitedToolFinding())
		s.add(fs...)
		return fs
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
	fs := s.applyEnginePolicy(f)
	s.add(fs...)
	return fs
}

func (s *streamState) applyEnginePolicy(f inspect.Finding) []inspect.Finding {
	if s.proxy != nil && s.proxy.cfg.Engine != nil {
		pf, ok := s.proxy.cfg.Engine.ApplyPolicy(f)
		if !ok {
			return nil
		}
		f = pf
	}
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

// truncate bounds a finding field cleanly on a UTF-8 rune boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 0 {
		return "\u2026"
	}
	cut := n
	for cut > 0 && cut > n-utf8.UTFMax && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "\u2026"
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
	case strings.Contains(path, ":streamGenerateContent"), strings.Contains(path, ":generateContent"):
		return "gemini"
	default:
		return "generic"
	}
}

// declaredToolNames parses the tool names a request advertises:
//
//	Anthropic        tools[].name
//	OpenAI           tools[].function.name
//	legacy OpenAI    functions[].name
//	Gemini           tools[].functionDeclarations[].name
//	Responses built-in tools[].type (local_shell, shell, computer_use_preview, code_interpreter)
//
// A nil result means the client declared no tools at all.
func declaredToolNames(body []byte) map[string]struct{} {
	var m struct {
		Tools []struct {
			Type     string `json:"type"`
			Name     string `json:"name"`
			Function struct {
				Name string `json:"name"`
			} `json:"function"`
			FunctionDeclarations []struct {
				Name string `json:"name"`
			} `json:"functionDeclarations"`
			FunctionDeclarationsSnake []struct {
				Name string `json:"name"`
			} `json:"function_declarations"`
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
		for _, fd := range t.FunctionDeclarations {
			if fd.Name != "" {
				names[fd.Name] = struct{}{}
			}
		}
		for _, fd := range t.FunctionDeclarationsSnake {
			if fd.Name != "" {
				names[fd.Name] = struct{}{}
			}
		}
		if n == "" && t.Type != "" && t.Type != "function" {
			names[t.Type] = struct{}{}
			switch t.Type {
			case "local_shell":
				names["local_shell_call"] = struct{}{}
			case "shell":
				names["shell_call"] = struct{}{}
			case "computer_use_preview":
				names["computer_call"] = struct{}{}
			case "code_interpreter":
				names["code_interpreter_call"] = struct{}{}
			}
		}
	}
	for _, f := range m.Functions {
		if f.Name != "" {
			names[f.Name] = struct{}{}
		}
	}
	return names
}

type bufferedToolCall struct {
	protocol string
	name     string
	args     string
}

func extractBufferedToolCalls(body []byte) []bufferedToolCall {
	var m struct {
		Content []struct {
			Type  string          `json:"type"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
		Choices []struct {
			Message struct {
				ToolCalls []struct {
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
				FunctionCall *struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function_call"`
			} `json:"message"`
		} `json:"choices"`
		FunctionCall *struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function_call"`
		Output     []responsesItem `json:"output"`
		Candidates []struct {
			Content struct {
				Parts []geminiPart `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	var out []bufferedToolCall
	for _, c := range m.Content {
		if c.Type == "tool_use" {
			out = append(out, bufferedToolCall{protocol: "anthropic", name: c.Name, args: string(c.Input)})
		}
	}
	for _, ch := range m.Choices {
		for _, tc := range ch.Message.ToolCalls {
			out = append(out, bufferedToolCall{protocol: "openai", name: tc.Function.Name, args: tc.Function.Arguments})
		}
		if fc := ch.Message.FunctionCall; fc != nil && (fc.Name != "" || fc.Arguments != "") {
			out = append(out, bufferedToolCall{protocol: "openai", name: fc.Name, args: fc.Arguments})
		}
	}
	if fc := m.FunctionCall; fc != nil && (fc.Name != "" || fc.Arguments != "") {
		out = append(out, bufferedToolCall{protocol: "openai", name: fc.Name, args: fc.Arguments})
	}
	for _, o := range m.Output {
		if isResponsesToolItem(o.Type) {
			out = append(out, bufferedToolCall{protocol: "responses", name: itemCheckName(o), args: itemPayload(o)})
		}
	}
	for _, cand := range m.Candidates {
		for _, part := range cand.Content.Parts {
			if fc := part.funcCall(); fc != nil {
				out = append(out, bufferedToolCall{protocol: "gemini", name: fc.Name, args: string(fc.Args)})
			}
		}
	}
	return out
}

// isStructuredTextResponse reports whether raw is a structured LLM response
// object containing only text/message content (never executed as tools).
func isStructuredTextResponse(raw []byte) bool {
	var m struct {
		Content    []any `json:"content"`
		Choices    []any `json:"choices"`
		Output     []any `json:"output"`
		Candidates []any `json:"candidates"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return false
	}
	return len(m.Content) > 0 || len(m.Choices) > 0 || len(m.Output) > 0 || len(m.Candidates) > 0
}

// responseToolNames extracts tool-call names from a buffered (non-streaming)
// response body so the same declared-name validation that runs on streams also
// applies to whole-body responses (Anthropic, Chat Completions, legacy
// function_call, Responses API, Gemini).
func responseToolNames(body []byte) []string {
	var names []string
	for _, tc := range extractBufferedToolCalls(body) {
		if tc.name != "" {
			names = append(names, tc.name)
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
		strings.Contains(s, `"function_call"`) ||
		strings.Contains(s, `"functionCall"`)
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
	stripHopHeaders(w.Header())
	if decoded {
		w.Header().Del("Content-Encoding")
		w.Header().Del("Content-Length")
	}
	if streaming {
		// Length is unknown for a stream; ensure no stale length is forwarded.
		w.Header().Del("Content-Length")
	}
}

// singleJoin joins an upstream base path and a client request path without
// duplicating a boundary segment. Providers are commonly configured with a base
// URL that already ends in the API version ("https://host/api/v1") while the
// client still sends the versioned path ("/v1/messages"); a naive join produces
// "/api/v1/v1/messages". When the base's last segment equals the request's first
// segment (case-insensitive) the request's copy is dropped.
func singleJoin(a, b string) string {
	if a == "" || a == "/" {
		return b
	}
	base := strings.TrimRight(a, "/")
	rest := strings.TrimLeft(b, "/")

	if last := lastPathSegment(base); last != "" {
		if first, tail, ok := firstPathSegment(rest); ok && strings.EqualFold(first, last) {
			if tail == "" {
				return base
			}
			rest = tail
		}
	}
	return base + "/" + rest
}

// lastPathSegment returns the final non-empty segment of a path.
func lastPathSegment(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// firstPathSegment splits the first segment off a path and reports whether one
// existed.
func firstPathSegment(p string) (seg, rest string, ok bool) {
	if p == "" {
		return "", "", false
	}
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return p[:i], p[i+1:], true
	}
	return p, "", true
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
