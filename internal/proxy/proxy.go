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
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"holone/internal/inspect"
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
	Findings    []inspect.Finding `json:"findings,omitempty"`
}

// Config configures a Proxy.
type Config struct {
	Upstream   *url.URL
	Engine     *inspect.Engine
	Mode       Mode
	Logger     *Logger
	OnDecision func(Decision) // optional callback (CLI prints alerts)
}

// Proxy is an http.Handler.
type Proxy struct {
	cfg    Config
	client *http.Client
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
		cfg:    cfg,
		client: &http.Client{Transport: transport, Timeout: 0},
	}
}

// hop-by-hop headers must not be forwarded (RFC 7230 §6.1).
var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

const (
	maxRequestBody  = 32 << 20 // 32 MiB cap when buffering a request body
	maxResponseBody = 64 << 20 // 64 MiB cap when buffering a non-streaming response
)

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Buffer the request body so we can both inspect it (to learn whether the
	// client advertised any tools) and forward it upstream.
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
	r.Body.Close()
	if err != nil {
		http.Error(w, "holone: read request: "+err.Error(), http.StatusBadGateway)
		return
	}
	clientTools := requestDeclaresTools(body)
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
		proxy:       p,
		protocol:    protocol,
		clientTools: clientTools,
		path:        r.URL.Path,
	}

	ct := resp.Header.Get("Content-Type")
	isSSE := strings.Contains(strings.ToLower(ct), "text/event-stream")

	if isSSE {
		p.serveStream(w, resp, st)
	} else {
		p.serveBuffered(w, resp, st)
	}
}

// serveStream copies response headers, then dispatches to a protocol-specific
// streaming inspector.
func (p *Proxy) serveStream(w http.ResponseWriter, resp *http.Response, st *streamState) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		// Cannot stream; fall back to buffered handling.
		p.serveBuffered(w, resp, st)
		return
	}
	writeResponseHeaders(w, resp, true)
	w.WriteHeader(resp.StatusCode)
	flusher.Flush()

	body, closeBody := decompressedBody(resp)
	defer closeBody()
	reader := bufio.NewReaderSize(body, 16<<10)
	switch st.protocol {
	case "anthropic":
		p.streamAnthropic(w, flusher, reader, st)
	case "openai":
		p.streamOpenAI(w, flusher, reader, st)
	default:
		p.streamGeneric(w, flusher, reader, st)
	}
	p.report(st)
}

// serveBuffered handles non-streaming responses: buffer, inspect, then forward
// (Monitor) or replace if malicious (Block).
func (p *Proxy) serveBuffered(w http.ResponseWriter, resp *http.Response, st *streamState) {
	src, closeBody := decompressedBody(resp)
	defer closeBody()
	body, err := io.ReadAll(io.LimitReader(src, maxResponseBody))
	if err != nil {
		http.Error(w, "holone: read upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	st.add(p.cfg.Engine.Inspect(string(body), "response-body")...)
	st.checkAnomaly(bodyMentionsTool(body))

	blocked := false
	if p.cfg.Mode == ModeBlock && inspect.MaxSeverity(st.findings) == inspect.SevHigh {
		body = []byte(`{"type":"error","error":{"type":"holone_blocked","message":"Response blocked by holone: suspected malicious provider injection."}}`)
		blocked = true
	}
	st.blocked = blocked

	writeResponseHeaders(w, resp, false)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	code := resp.StatusCode
	if blocked {
		w.Header().Set("Content-Type", "application/json")
		code = http.StatusOK
	}
	w.WriteHeader(code)
	w.Write(body)
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
		ClientTools: st.clientTools,
		Verdict:     verdict,
		MaxSeverity: inspect.MaxSeverity(st.findings).String(),
		Findings:    st.findings,
	}
	if p.cfg.Logger != nil {
		p.cfg.Logger.Log(d)
	}
	if p.cfg.OnDecision != nil && verdict != "clean" {
		p.cfg.OnDecision(d)
	}
}

// streamState carries per-request inspection state.
type streamState struct {
	proxy       *Proxy
	protocol    string
	clientTools bool
	path        string
	findings    []inspect.Finding
	sawTool     bool
	blocked     bool
}

func (s *streamState) add(fs ...inspect.Finding) {
	s.findings = append(s.findings, fs...)
}

// checkAnomaly adds a high-severity finding if a tool call appeared although
// the client never advertised any tools — a strong injection signal.
func (s *streamState) checkAnomaly(sawTool bool) {
	if sawTool {
		s.sawTool = true
	}
	if s.sawTool && !s.clientTools {
		s.add(inspect.Finding{
			RuleID:      inspect.RuleAnomalyUnsolicitedTool,
			Category:    "protocol-anomaly",
			Severity:    "high",
			Match:       "tool call present without client-declared tools",
			Source:      "protocol",
			Description: "The provider injected a tool call the client never requested.",
		})
	}
}

// --- helpers ---------------------------------------------------------------

func detectProtocol(path string) string {
	switch {
	case strings.Contains(path, "/chat/completions"):
		return "openai"
	case strings.Contains(path, "/messages"):
		return "anthropic"
	default:
		return "generic"
	}
}

// requestDeclaresTools reports whether the request JSON advertised any tools
// (Anthropic & OpenAI both use "tools"; legacy OpenAI uses "functions").
func requestDeclaresTools(body []byte) bool {
	var m struct {
		Tools     []json.RawMessage `json:"tools"`
		Functions []json.RawMessage `json:"functions"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return false
	}
	return len(m.Tools) > 0 || len(m.Functions) > 0
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

func writeResponseHeaders(w http.ResponseWriter, resp *http.Response, streaming bool) {
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	for _, h := range hopHeaders {
		w.Header().Del(h)
	}
	// We always forward the body as identity bytes (we decompress upstream gzip
	// ourselves), so never advertise a Content-Encoding to the client.
	w.Header().Del("Content-Encoding")
	if streaming {
		// Length is unknown for a stream; ensure no stale length is forwarded.
		w.Header().Del("Content-Length")
	}
}

// decompressedBody returns a reader over the response body, transparently
// gunzipping if the upstream sent gzip despite our identity request (so the
// inspector sees plaintext and the client receives consistent identity bytes).
func decompressedBody(resp *http.Response) (io.Reader, func() error) {
	enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	if strings.Contains(enc, "gzip") {
		if gz, err := gzip.NewReader(resp.Body); err == nil {
			return gz, gz.Close
		}
	}
	return resp.Body, func() error { return nil }
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

// ensure context import is used even if future edits drop it.
var _ = context.Background
