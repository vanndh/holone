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

// Options configures a scan.
type Options struct {
	BaseURL  string
	APIKey   string
	Model    string
	Engine   *inspect.Engine
	Client   *http.Client
	Progress ProgressFunc
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
	u, err := url.Parse(strings.TrimRight(opt.BaseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("invalid base url: %w", err)
	}
	client := opt.Client
	if client == nil {
		client = &http.Client{Timeout: 45 * time.Second}
	}

	res := &Result{
		Endpoint: opt.BaseURL,
		Host:     u.Hostname(),
		Official: officialHosts[strings.ToLower(u.Hostname())],
	}

	// Phase 1: structural checks (fast, concurrent).
	bl, _ := inspect.DefaultBlocklist()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); res.ResolvedIPs = resolveIPs(ctx, u.Hostname()) }()
	go func() { defer wg.Done(); res.TLS = probeTLS(u) }()
	wg.Wait()

	res.BlocklistHits = matchBlocklist(u.Hostname(), res.ResolvedIPs, bl)

	// Phase 2: behavioral probes.
	prompt := "Reply with a single short sentence greeting. Do not call any tools."
	amodel, omodel := opt.Model, opt.Model
	if amodel == "" {
		amodel = "claude-3-5-sonnet-20241022"
	}
	if omodel == "" {
		omodel = "gpt-4o-mini"
	}

	// Run all 4 probes concurrently for speed.
	type probeJob struct {
		name  string
		proto string
		body  []byte
	}
	jobs := []probeJob{
		{"no-tool", "anthropic", anthropicBody(amodel, prompt)},
		{"no-tool", "openai", openaiBody(omodel, prompt)},
		{"with-tools", "anthropic", anthropicBodyWithTools(amodel, prompt)},
		{"with-tools", "openai", openaiBodyWithTools(omodel, prompt)},
	}

	res.Probes = make([]ProbeResult, len(jobs))
	var pw sync.WaitGroup
	for i, j := range jobs {
		pw.Add(1)
		go func(idx int, job probeJob) {
			defer pw.Done()
			pr := probe(ctx, client, opt, u, job.proto, job.name, job.body)
			res.Probes[idx] = pr
			if opt.Progress != nil {
				status := "ok"
				if pr.Err != "" {
					status = "error"
				} else if pr.SawToolCall || len(pr.Findings) > 0 {
					status = "fail"
				}
				opt.Progress(job.proto+"/"+job.name, status, len(pr.Findings), pr.Err)
			}
		}(i, j)
	}
	pw.Wait()

	scoreResult(res)
	return res, nil
}

func probe(ctx context.Context, client *http.Client, opt Options, base *url.URL, proto, name string, body []byte) ProbeResult {
	pr := ProbeResult{Name: name, Protocol: proto, DeclaredTools: strings.Contains(name, "with-tools")}
	var endpoint string
	switch proto {
	case "openai":
		endpoint = base.String() + "/v1/chat/completions"
	default:
		endpoint = base.String() + "/v1/messages"
	}
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
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	text := string(raw)
	pr.SawToolCall = strings.Contains(text, `"tool_use"`) ||
		strings.Contains(text, `"tool_calls"`) ||
		strings.Contains(text, `"function_call"`)
	pr.Findings = opt.Engine.Inspect(text, "scan:"+proto+":"+name)
	inspect.SortFindings(pr.Findings)
	if resp.StatusCode >= 400 {
		pr.Err = fmt.Sprintf("HTTP %d", resp.StatusCode)
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
