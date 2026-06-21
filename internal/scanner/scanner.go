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
	Endpoint      string        `json:"endpoint"`
	Host          string        `json:"host"`
	Official      bool          `json:"official"`
	ResolvedIPs   []string      `json:"resolved_ips,omitempty"`
	BlocklistHits []string      `json:"blocklist_hits,omitempty"`
	TLS           *TLSInfo      `json:"tls,omitempty"`
	Probes        []ProbeResult `json:"probes"`
	RiskScore     int           `json:"risk_score"`
	Verdict       string        `json:"verdict"`
	Notes         []string      `json:"notes,omitempty"`
}

var officialHosts = map[string]bool{
	"api.anthropic.com": true,
	"api.openai.com":    true,
}

// Options configures a scan.
type Options struct {
	BaseURL string
	APIKey  string
	Model   string // model name to request; defaults applied if empty
	Engine  *inspect.Engine
	Client  *http.Client // optional override (tests)
}

// Scan runs all probes and returns a report.
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

	bl, _ := inspect.DefaultBlocklist()
	res.ResolvedIPs = resolveIPs(ctx, u.Hostname())
	res.BlocklistHits = matchBlocklist(u.Hostname(), res.ResolvedIPs, bl)
	res.TLS = probeTLS(u)

	prompt := "Reply with a single short sentence greeting. Do not call any tools."
	amodel, omodel := opt.Model, opt.Model
	if amodel == "" {
		amodel = "claude-3-5-sonnet-20241022"
	}
	if omodel == "" {
		omodel = "gpt-4o-mini"
	}

	// Probe BOTH protocols so OpenAI-compatible-only providers are covered. A
	// tool call in response to a no-tool prompt is a strong injection signal.
	res.Probes = append(res.Probes,
		probe(ctx, client, opt, u, "anthropic", "no-tool", anthropicBody(amodel, prompt)),
		probe(ctx, client, opt, u, "openai", "no-tool", openaiBody(omodel, prompt)))

	scoreResult(res)
	return res, nil
}

func probe(ctx context.Context, client *http.Client, opt Options, base *url.URL, proto, name string, body []byte) ProbeResult {
	pr := ProbeResult{Name: name, Protocol: proto}
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

	resp, err := client.Do(req)
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
	// Treat a non-2xx status as a failed probe so it cannot read as "clean".
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

func openaiBody(model, prompt string) []byte {
	b, _ := json.Marshal(map[string]any{
		"model":    model,
		"messages": []any{map[string]any{"role": "user", "content": prompt}},
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

// scoreResult derives a risk score and verdict. Behavioral signals (IOC hits,
// injected tool calls, payload patterns) are kept distinct from structural ones
// (non-official host, fresh TLS cert) so that structural signals alone — which
// are normal for honest independent providers — never cross into "suspicious".
func scoreResult(res *Result) {
	behavioral, structural := 0, 0

	for _, h := range res.BlocklistHits {
		behavioral += 100
		res.Notes = append(res.Notes, "KNOWN INDICATOR OF COMPROMISE: "+h)
	}
	if !res.Official {
		structural += 10
		res.Notes = append(res.Notes, "Non-official endpoint host: "+res.Host)
	}

	reachable := 0
	for _, p := range res.Probes {
		if p.Err != "" {
			res.Notes = append(res.Notes, fmt.Sprintf("probe %s/%s could not run: %s", p.Protocol, p.Name, p.Err))
			continue
		}
		reachable++
		if !p.DeclaredTools && p.SawToolCall {
			behavioral += 60
			res.Notes = append(res.Notes, "Endpoint returned a tool call for a prompt that declared no tools ("+p.Protocol+") — strong injection signal")
		}
		if inspect.MaxSeverity(p.Findings) == inspect.SevHigh {
			behavioral += 40
			res.Notes = append(res.Notes, "High-severity payload pattern in response ("+p.Protocol+")")
		} else if len(p.Findings) > 0 {
			behavioral += 15
		}
	}
	if res.TLS != nil && res.TLS.AgeDays >= 0 && res.TLS.AgeDays < 14 {
		structural += 5
		res.Notes = append(res.Notes, fmt.Sprintf("TLS certificate is only %d days old", res.TLS.AgeDays))
	}

	res.RiskScore = behavioral + structural
	switch {
	case reachable == 0:
		res.Verdict = "could-not-probe"
		res.Notes = append(res.Notes, "All probes failed — could not actively test this endpoint (wrong model name? auth? unsupported protocol?). Try --model.")
	case behavioral >= 100:
		res.Verdict = "malicious"
	case behavioral >= 50:
		res.Verdict = "high-risk"
	case behavioral >= 15:
		res.Verdict = "suspicious"
	default:
		// Structural-only signals never escalate past the clean band.
		res.Verdict = "no-active-injection-detected"
	}
	res.Notes = append(res.Notes,
		"NOTE: a clean result does NOT prove the provider is safe — it cannot detect passive prompt logging. Do not send secrets to non-official providers.")
}
