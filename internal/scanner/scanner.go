// Package scanner actively probes an LLM provider endpoint to judge how much it
// can be trusted. It is a point-in-time "canary": it cannot prove a provider is
// safe (a passive logger looks identical to an honest one), but it reliably
// catches a provider that injects tool calls or known-bad indicators into its
// responses.
package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/vanndh/holone/internal/inspect"
)

// ProbeResult is the outcome of one request sent to the endpoint.
type ProbeResult struct {
	Name          string            `json:"name"`
	Protocol      string            `json:"protocol"`
	DeclaredTools bool              `json:"declared_tools"`
	SawToolCall   bool              `json:"saw_tool_call"`
	Findings      []inspect.Finding `json:"findings,omitempty"`
	Status        int               `json:"status"`
	DurationMs    int64             `json:"duration_ms"`
	Err           string            `json:"error,omitempty"`
}

// TLSInfo summarizes the server certificate.
type TLSInfo struct {
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	AgeDays   int    `json:"age_days"`
}

// Result is the full scan report.
type Result struct {
	Endpoint          string        `json:"endpoint"`
	Host              string        `json:"host"`
	Official          bool          `json:"official"`
	ResolvedIPs       []string      `json:"resolved_ips,omitempty"`
	BlocklistHits     []string      `json:"blocklist_hits,omitempty"`
	TLS               *TLSInfo      `json:"tls,omitempty"`
	Protocol          string        `json:"protocol"`
	Discovery         []Discovery   `json:"discovery,omitempty"`
	Probes            []ProbeResult `json:"probes"`
	RiskScore         int           `json:"risk_score"`
	Verdict           string        `json:"verdict"`
	SummaryEN         string        `json:"summary_en"`
	SummaryRU         string        `json:"summary_ru"`
	Notes             []string      `json:"notes,omitempty"`
	NotesRU           []string      `json:"notes_ru,omitempty"`
	RecommendationsEN []string      `json:"recommendations_en,omitempty"`
	RecommendationsRU []string      `json:"recommendations_ru,omitempty"`
}

var officialHosts = map[string]bool{
	"api.anthropic.com": true,
	"api.openai.com":    true,
}

// ProgressFunc is called as each probe completes so callers can show live
// feedback. probeName is "anthropic/no-tool", "openai/no-tool" etc. status is
// "ok", "fail", "error". findings is non-zero count.
type ProgressFunc func(probeName string, status string, findings int, err string)

// Endpoint protocols a scan can speak.
const (
	// ProtocolAuto discovers which layouts the endpoint answers and probes the
	// supported ones (the default).
	ProtocolAuto = "auto"
	// ProtocolChatCompletions is the OpenAI-compatible /v1/chat/completions API.
	ProtocolChatCompletions = "chat-completions"
	// ProtocolResponses is the OpenAI Responses API (/v1/responses).
	ProtocolResponses = "responses"
	// ProtocolAnthropic is the Anthropic Messages API (/v1/messages).
	ProtocolAnthropic = "anthropic"
)

// protocolOrder is the deterministic order used for auto-detection.
var protocolOrder = []string{ProtocolChatCompletions, ProtocolResponses, ProtocolAnthropic}

// protocolSuffix maps a protocol to the endpoint path appended to the base.
var protocolSuffix = map[string]string{
	ProtocolChatCompletions: "chat/completions",
	ProtocolResponses:       "responses",
	ProtocolAnthropic:       "messages",
}

// Discovery reports whether one endpoint layout answered during auto-detection.
type Discovery struct {
	Protocol  string `json:"protocol"`
	Endpoint  string `json:"endpoint"`
	Supported bool   `json:"supported"`
	Status    int    `json:"status,omitempty"`
	Err       string `json:"error,omitempty"`
}

// Options configures a scan.
type Options struct {
	BaseURL string
	APIKey  string
	// Model overrides the model id sent by every probe.
	Model string
	// Protocol selects the wire protocol: auto (default), chat-completions,
	// responses, or anthropic.
	Protocol string
	// Path overrides the endpoint path derived from the protocol. A leading
	// "/" is resolved against the base URL's host; otherwise it is appended to
	// the base URL's path. A full URL is used as-is.
	Path     string
	Engine   *inspect.Engine
	Client   *http.Client
	Progress ProgressFunc
}

// NormalizeProtocol validates a protocol name. Empty means auto.
func NormalizeProtocol(p string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "", ProtocolAuto:
		return ProtocolAuto, nil
	case ProtocolChatCompletions:
		return ProtocolChatCompletions, nil
	case ProtocolResponses:
		return ProtocolResponses, nil
	case ProtocolAnthropic:
		return ProtocolAnthropic, nil
	default:
		return "", fmt.Errorf("invalid protocol %q (want auto, %s, %s, or %s)", p, ProtocolChatCompletions, ProtocolResponses, ProtocolAnthropic)
	}
}

// normalizeBaseURL validates the user-supplied base URL, defaults a missing
// scheme to https, and drops a trailing slash, query, and fragment. It does not
// touch the path beyond trimming trailing slashes, so /v1 stays /v1.
func normalizeBaseURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty base url")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid base url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("invalid base url %q: scheme must be http or https", raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid base url %q: missing host", raw)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u, nil
}

// endpointURL builds the probe endpoint for a protocol. The /v1 segment is
// added only when the base path does not already end in /v1, so both
// https://example.com and https://example.com/v1 produce .../v1/<suffix>.
func endpointURL(base *url.URL, protocol, pathOverride string) (string, error) {
	if override := strings.TrimSpace(pathOverride); override != "" {
		return resolvePathOverride(base, override)
	}
	suffix, ok := protocolSuffix[protocol]
	if !ok {
		return "", fmt.Errorf("unknown protocol %q", protocol)
	}
	path := base.Path
	if !strings.HasSuffix(strings.ToLower(path), "/v1") {
		path += "/v1"
	}
	u := *base
	u.Path = path + "/" + suffix
	u.RawPath = ""
	return u.String(), nil
}

// resolvePathOverride resolves an explicit --path value. Absolute URLs are used
// as-is, origin-absolute paths keep their query, and relative paths are joined
// to the base URL's path.
func resolvePathOverride(base *url.URL, override string) (string, error) {
	ref, err := url.Parse(override)
	if err != nil {
		return "", fmt.Errorf("invalid path %q: %w", override, err)
	}
	if ref.IsAbs() {
		return ref.String(), nil
	}
	u := *base
	switch {
	case ref.Host != "":
		u.Scheme = base.Scheme
	case strings.HasPrefix(override, "/"):
		u.Path = ref.Path
	default:
		u.Path = base.Path + "/" + ref.Path
	}
	u.RawPath = ""
	u.RawQuery = ref.RawQuery
	u.Fragment = ""
	return u.String(), nil
}

// Scan runs all probes concurrently and returns a report.
func Scan(ctx context.Context, opt Options) (*Result, error) {
	if opt.Engine == nil {
		eng, err := inspect.Default()
		if err != nil {
			return nil, err
		}
		opt.Engine = eng
	}
	mode, err := NormalizeProtocol(opt.Protocol)
	if err != nil {
		return nil, err
	}
	u, err := normalizeBaseURL(opt.BaseURL)
	if err != nil {
		return nil, err
	}
	client := opt.Client
	if client == nil {
		client = &http.Client{Timeout: 45 * time.Second}
	}

	res := &Result{
		Endpoint: u.String(),
		Host:     u.Hostname(),
		Official: officialHosts[strings.ToLower(u.Hostname())],
		Protocol: mode,
	}

	// Phase 1: structural checks (fast, concurrent).
	bl, _ := inspect.DefaultBlocklist()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); res.ResolvedIPs = resolveIPs(ctx, u.Hostname()) }()
	go func() { defer wg.Done(); res.TLS = probeTLS(u) }()
	wg.Wait()

	res.BlocklistHits = matchBlocklist(u.Hostname(), res.ResolvedIPs, bl)

	// Phase 2: protocol discovery. Every candidate layout gets one minimal
	// no-tool request; an explicit protocol skips discovery.
	probeProtocols := protocolOrder
	if mode != ProtocolAuto {
		probeProtocols = []string{mode}
	}
	endpoints := make(map[string]string, len(probeProtocols))
	for _, p := range probeProtocols {
		ep, err := endpointURL(u, p, opt.Path)
		if err != nil {
			return nil, err
		}
		endpoints[p] = ep
	}

	prompt := "Reply with a single short sentence greeting. Do not call any tools."
	discovery := make([]Discovery, len(probeProtocols))
	noTool := make([]ProbeResult, len(probeProtocols))
	var dwg sync.WaitGroup
	for i, p := range probeProtocols {
		dwg.Add(1)
		go func(idx int, protocol string) {
			defer dwg.Done()
			pr := probe(ctx, client, opt, endpoints[protocol], protocol, "no-tool", bodyFor(protocol, modelFor(protocol, opt.Model), prompt, false))
			noTool[idx] = pr
			discovery[idx] = Discovery{
				Protocol:  protocol,
				Endpoint:  endpoints[protocol],
				Supported: discoverySupported(pr),
				Status:    pr.Status,
				Err:       pr.Err,
			}
			if opt.Progress != nil {
				opt.Progress(protocol+"/no-tool", probeStatus(pr), len(pr.Findings), pr.Err)
			}
		}(i, p)
	}
	dwg.Wait()
	res.Discovery = discovery

	// Phase 3: behavioral probes. The discovery responses double as the
	// no-tool probes; only the supported layouts get a with-tools request.
	selected := selectProtocols(mode, discovery)
	byProtocol := make(map[string]int, len(probeProtocols))
	for i, p := range probeProtocols {
		byProtocol[p] = i
	}

	res.Probes = make([]ProbeResult, 0, len(selected)*2)
	for _, p := range selected {
		res.Probes = append(res.Probes, noTool[byProtocol[p]])
	}

	withTools := make([]ProbeResult, len(selected))
	var pw sync.WaitGroup
	for i, p := range selected {
		pw.Add(1)
		go func(idx int, protocol string) {
			defer pw.Done()
			pr := probe(ctx, client, opt, endpoints[protocol], protocol, "with-tools", bodyFor(protocol, modelFor(protocol, opt.Model), prompt, true))
			withTools[idx] = pr
			if opt.Progress != nil {
				opt.Progress(protocol+"/with-tools", probeStatus(pr), len(pr.Findings), pr.Err)
			}
		}(i, p)
	}
	pw.Wait()
	res.Probes = append(res.Probes, withTools...)

	scoreResult(res)
	return res, nil
}

// modelFor returns the model id a protocol should ask for.
func modelFor(protocol, override string) string {
	if override != "" {
		return override
	}
	if protocol == ProtocolAnthropic {
		return "claude-3-5-sonnet-20241022"
	}
	return "gpt-4o-mini"
}

// bodyFor builds the request body for one protocol.
func bodyFor(protocol, model, prompt string, withTools bool) []byte {
	switch protocol {
	case ProtocolAnthropic:
		if withTools {
			return anthropicBodyWithTools(model, prompt)
		}
		return anthropicBody(model, prompt)
	case ProtocolResponses:
		if withTools {
			return responsesBodyWithTools(model, prompt)
		}
		return responsesBody(model, prompt)
	default:
		if withTools {
			return openaiBodyWithTools(model, prompt)
		}
		return openaiBody(model, prompt)
	}
}

func probeStatus(pr ProbeResult) string {
	switch {
	case pr.Err != "":
		return "error"
	case pr.SawToolCall || len(pr.Findings) > 0:
		return "fail"
	default:
		return "ok"
	}
}

// discoverySupported treats any HTTP answer other than a route-level rejection
// as the layout existing. Auth and validation errors still mean the endpoint is
// there and worth canary-probing.
func discoverySupported(pr ProbeResult) bool {
	if pr.Status == 0 {
		return false
	}
	switch pr.Status {
	case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusNotImplemented:
		return false
	}
	return true
}

// selectProtocols picks the layouts to probe deeply. In auto mode both OpenAI
// layouts are alternatives, so chat-completions wins when it answers and
// responses is used otherwise; Anthropic is additive.
func selectProtocols(mode string, discovery []Discovery) []string {
	if mode != ProtocolAuto {
		return []string{mode}
	}
	supported := make(map[string]bool, len(discovery))
	for _, d := range discovery {
		supported[d.Protocol] = d.Supported
	}
	var selected []string
	switch {
	case supported[ProtocolChatCompletions]:
		selected = append(selected, ProtocolChatCompletions)
	case supported[ProtocolResponses]:
		selected = append(selected, ProtocolResponses)
	}
	if supported[ProtocolAnthropic] {
		selected = append(selected, ProtocolAnthropic)
	}
	if len(selected) == 0 {
		// Nothing looked supported: keep the classic layouts so the report
		// shows their errors instead of an empty probe list.
		selected = []string{ProtocolChatCompletions, ProtocolAnthropic}
	}
	return selected
}

// maxProbeBody bounds how much of a probe response is inspected. A body past
// this limit is truncated for scanning only, and the truncation is reported in
// ProbeResult.Err instead of being silent.
const maxProbeBody = 4 << 20

func probe(ctx context.Context, client *http.Client, opt Options, endpoint, proto, name string, body []byte) ProbeResult {
	pr := ProbeResult{Name: name, Protocol: proto, DeclaredTools: strings.Contains(name, "with-tools")}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		pr.Err = err.Error()
		return pr
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	if opt.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+opt.APIKey)
		if proto == "anthropic" {
			req.Header.Set("x-api-key", opt.APIKey)
		}
	}
	if proto == "anthropic" {
		req.Header.Set("anthropic-version", "2023-06-01")
	}

	start := time.Now()
	resp, err := client.Do(req)
	pr.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		pr.Err = err.Error()
		return pr
	}
	defer resp.Body.Close()
	pr.Status = resp.StatusCode
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxProbeBody+1))
	truncated := len(raw) > maxProbeBody
	if truncated {
		raw = raw[:maxProbeBody]
	}
	text := string(raw)
	pr.SawToolCall = strings.Contains(text, `"tool_use"`) ||
		strings.Contains(text, `"tool_calls"`) ||
		strings.Contains(text, `"function_call"`)
	pr.Findings = opt.Engine.Inspect(text, "scan:"+proto+":"+name)
	inspect.SortFindings(pr.Findings)
	if resp.StatusCode >= 400 {
		pr.Err = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	if truncated {
		const msg = "response exceeded 4 MiB scan limit (truncated for scanning)"
		if pr.Err != "" {
			pr.Err += "; " + msg
		} else {
			pr.Err = msg
		}
	}
	return pr
}

func anthropicBody(model, prompt string) []byte {
	b, _ := json.Marshal(map[string]any{
		"model":      model,
		"max_tokens": 128,
		"messages":   []any{map[string]any{"role": "user", "content": prompt}},
	})
	return b
}

func anthropicBodyWithTools(model, prompt string) []byte {
	b, _ := json.Marshal(map[string]any{
		"model":      model,
		"max_tokens": 128,
		"messages":   []any{map[string]any{"role": "user", "content": prompt}},
		"tools":      []any{map[string]any{"name": "Bash", "description": "Run a shell command", "input_schema": map[string]any{"type": "object", "properties": map[string]any{"command": map[string]any{"type": "string"}}}}},
	})
	return b
}

func openaiBody(model, prompt string) []byte {
	b, _ := json.Marshal(map[string]any{
		"model":    model,
		"messages": []any{map[string]any{"role": "user", "content": prompt}},
	})
	return b
}

func openaiBodyWithTools(model, prompt string) []byte {
	b, _ := json.Marshal(map[string]any{
		"model":    model,
		"messages": []any{map[string]any{"role": "user", "content": prompt}},
		"tools":    []any{map[string]any{"type": "function", "function": map[string]any{"name": "run", "description": "Run a shell command", "parameters": map[string]any{"type": "object", "properties": map[string]any{"cmd": map[string]any{"type": "string"}}}}}},
	})
	return b
}

// responsesBody is the smallest valid OpenAI Responses API request.
func responsesBody(model, prompt string) []byte {
	b, _ := json.Marshal(map[string]any{
		"model": model,
		"input": prompt,
	})
	return b
}

// responsesBodyWithTools declares a tool in the Responses API's flat shape.
func responsesBodyWithTools(model, prompt string) []byte {
	b, _ := json.Marshal(map[string]any{
		"model": model,
		"input": prompt,
		"tools": []any{map[string]any{
			"type":        "function",
			"name":        "run",
			"description": "Run a shell command",
			"parameters":  map[string]any{"type": "object", "properties": map[string]any{"cmd": map[string]any{"type": "string"}}},
		}},
	})
	return b
}

func resolveIPs(ctx context.Context, host string) []string {
	var r net.Resolver
	ips, err := r.LookupHost(ctx, host)
	if err != nil {
		return nil
	}
	return ips
}

func matchBlocklist(host string, ips []string, bl inspect.Blocklist) []string {
	var hits []string
	lhost := strings.ToLower(host)
	for _, d := range bl.Domains {
		if strings.Contains(lhost, strings.ToLower(d)) {
			hits = append(hits, "domain:"+d)
		}
	}
	ipset := map[string]bool{}
	for _, ip := range ips {
		ipset[ip] = true
	}
	for _, bip := range bl.IPs {
		if ipset[bip] {
			hits = append(hits, "ip:"+bip)
		}
	}
	return hits
}

func probeTLS(u *url.URL) *TLSInfo {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if u.Scheme == "http" {
		return nil
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, port), &tls.Config{ServerName: host})
	if err != nil {
		return nil
	}
	defer conn.Close()
	cs := conn.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return nil
	}
	c := cs.PeerCertificates[0]
	return &TLSInfo{
		Subject:   c.Subject.String(),
		Issuer:    c.Issuer.String(),
		NotBefore: c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:  c.NotAfter.UTC().Format(time.RFC3339),
		AgeDays:   int(time.Since(c.NotBefore).Hours() / 24),
	}
}

func scoreResult(res *Result) {
	behavioral, structural := 0, 0

	addNote := func(en, ru string) {
		res.Notes = append(res.Notes, en)
		res.NotesRU = append(res.NotesRU, ru)
	}

	for _, h := range res.BlocklistHits {
		behavioral += 100
		addNote("Known IOC matched: "+h, "Найден известный индикатор компрометации: "+h)
	}
	if !res.Official {
		structural += 10
		addNote("Non-official endpoint: "+res.Host, "Неофициальный endpoint: "+res.Host)
	}
	if len(res.Discovery) > 1 {
		var partsEN, partsRU []string
		for _, d := range res.Discovery {
			stateEN, stateRU := "not supported", "не поддерживается"
			if d.Supported {
				stateEN, stateRU = "supported", "поддерживается"
			}
			partsEN = append(partsEN, d.Protocol+": "+stateEN)
			partsRU = append(partsRU, d.Protocol+": "+stateRU)
		}
		addNote("Endpoint layouts — "+strings.Join(partsEN, ", "), "Layout endpoint — "+strings.Join(partsRU, ", "))
	}

	reachable := 0
	failed := 0
	toolCalls := 0
	highFindings := 0
	mediumOrLowFindings := 0
	for _, p := range res.Probes {
		if p.Err != "" {
			failed++
			addNote(fmt.Sprintf("Probe %s/%s failed: %s", p.Protocol, p.Name, p.Err), fmt.Sprintf("Проба %s/%s завершилась ошибкой: %s", p.Protocol, p.Name, p.Err))
			continue
		}
		reachable++
		if p.SawToolCall {
			toolCalls++
		}
		if !p.DeclaredTools && p.SawToolCall {
			behavioral += 60
			addNote("Unsolicited tool call in "+p.Protocol+" "+p.Name+" probe — strong injection signal", "Непрошеный вызов инструмента в пробе "+p.Protocol+" "+p.Name+" — сильный признак инъекции")
		}
		if inspect.MaxSeverity(p.Findings) == inspect.SevHigh {
			behavioral += 40
			highFindings += len(p.Findings)
			addNote("High-severity payload pattern in "+p.Protocol+" response", "High-severity payload-паттерн в ответе "+p.Protocol)
		} else if len(p.Findings) > 0 {
			behavioral += 15
			mediumOrLowFindings += len(p.Findings)
			addNote("Suspicious payload pattern in "+p.Protocol+" response", "Подозрительный payload-паттерн в ответе "+p.Protocol)
		}
	}
	if res.TLS != nil && res.TLS.AgeDays >= 0 && res.TLS.AgeDays < 14 {
		structural += 5
		addNote(fmt.Sprintf("TLS certificate is only %d days old", res.TLS.AgeDays), fmt.Sprintf("TLS-сертификату всего %d дн.", res.TLS.AgeDays))
	}

	res.RiskScore = behavioral + structural
	switch {
	case reachable == 0:
		res.Verdict = "could-not-probe"
		addNote("All probes failed — could not test this endpoint (wrong model? auth? unsupported protocol?). Try --model.", "Все пробы упали — endpoint не удалось проверить (модель, авторизация или протокол могут не подходить). Попробуй --model.")
	case behavioral >= 100:
		res.Verdict = "malicious"
	case behavioral >= 50:
		res.Verdict = "high-risk"
	case behavioral >= 15:
		res.Verdict = "suspicious"
	default:
		res.Verdict = "no-active-injection-detected"
	}
	res.SummaryEN, res.SummaryRU = scanSummary(res.Verdict, reachable, failed, toolCalls, highFindings, mediumOrLowFindings)
	res.RecommendationsEN, res.RecommendationsRU = scanRecommendations(res)
	addNote("A clean result does NOT prove safety — passive prompt logging cannot be detected. Do not send secrets to non-official providers.", "Чистый результат НЕ доказывает безопасность — пассивный слив промптов не детектируется. Не отправляй секреты неофициальным провайдерам.")
}
