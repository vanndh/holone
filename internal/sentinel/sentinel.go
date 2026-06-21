// Package sentinel performs client-independent, OS-level detection of the
// post-exploitation indicators a malicious provider's payload leaves behind:
// rogue processes, scheduled-task persistence, traffic redirection, and dropped
// files. It runs entirely outside the request hot path. The same checks back
// both `holone audit` (one-shot) and `holone sentinel` (continuous watch).
package sentinel

import (
	"context"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/vanndh/holone/internal/inspect"
)

// Status classifies a check result.
const (
	StatusClean    = "clean"
	StatusInfected = "infected"
	StatusWarn     = "warn"
	StatusError    = "error"
)

// Check is the outcome of a single indicator probe.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// Audit runs every available check once and returns the results.
func Audit(ctx context.Context) []Check {
	bl, _ := inspect.DefaultBlocklist()
	checks := []Check{checkEnvProxy(bl)}
	checks = append(checks, platformChecks(ctx, bl)...)
	return checks
}

// alerting reports whether a status should surface to the operator. StatusError
// is included so a detection path that could not run (missing/renamed netstat,
// schtasks, …) is visible rather than silently dark.
func alerting(status string) bool {
	return status == StatusInfected || status == StatusWarn || status == StatusError
}

// Infected returns the subset of checks that flagged something or errored.
func Infected(checks []Check) []Check {
	var out []Check
	for _, c := range checks {
		if alerting(c.Status) {
			out = append(out, c)
		}
	}
	return out
}

// Monitor re-audits on each interval and reports newly flagged checks via
// onAlert. It blocks until ctx is cancelled.
func Monitor(ctx context.Context, interval time.Duration, onAlert func(Check)) {
	seen := map[string]string{} // name -> last reported status
	run := func() {
		for _, c := range Audit(ctx) {
			if alerting(c.Status) && seen[c.Name] != c.Status {
				onAlert(c)
			}
			seen[c.Name] = c.Status
		}
	}
	run()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

// checkEnvProxy inspects proxy environment variables (cross-platform).
func checkEnvProxy(bl inspect.Blocklist) Check {
	c := Check{Name: "proxy-env-vars", Status: StatusClean, Detail: "no suspicious proxy environment variables"}
	vars := []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"}
	var hits []string
	for _, v := range vars {
		val := os.Getenv(v)
		if val == "" {
			continue
		}
		low := strings.ToLower(val)
		if strings.Contains(low, "socks") {
			hits = append(hits, v+"="+val+" (SOCKS proxy)")
		}
		for _, ip := range bl.IPs {
			if strings.Contains(val, ip) {
				hits = append(hits, v+"="+val+" (known-bad IP)")
			}
		}
	}
	if len(hits) > 0 {
		c.Status = StatusWarn
		c.Detail = strings.Join(hits, "; ")
	}
	return c
}

// --- shared helpers used by platform check files ---------------------------

// runCmd executes a command with an 8s timeout and returns combined output.
func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).CombinedOutput()
	return string(out), err
}

var (
	ipPortRe  = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)`)
	ip6PortRe = regexp.MustCompile(`\[([0-9a-fA-F:]+)\]:(\d+)`)
)

// matchProcessNames matches blocklisted process names on a word boundary so a
// generic name like "proxy.exe" does not collide with "msedge_proxy.exe".
func matchProcessNames(out string, names []string) []string {
	var hits []string
	seen := map[string]bool{}
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" || seen[n] {
			continue
		}
		re, err := regexp.Compile(`(?i)(^|[^\w])` + regexp.QuoteMeta(n))
		if err != nil {
			continue
		}
		if re.MatchString(out) {
			hits = append(hits, n)
			seen[n] = true
		}
	}
	sort.Strings(hits)
	return hits
}

// publicSocksEndpoints returns endpoints on port 1080 whose host is a public
// (non-loopback, non-private) IPv4 or IPv6 address, indicating traffic routed
// through a remote SOCKS proxy.
func publicSocksEndpoints(out string) []string {
	var eps []string
	seen := map[string]bool{}
	add := func(ipStr, raw string) {
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
			return
		}
		if !seen[raw] {
			seen[raw] = true
			eps = append(eps, raw)
		}
	}
	for _, m := range ipPortRe.FindAllStringSubmatch(out, -1) {
		if m[2] == "1080" {
			add(m[1], m[1]+":1080")
		}
	}
	for _, m := range ip6PortRe.FindAllStringSubmatch(out, -1) {
		if m[2] == "1080" {
			add(m[1], "["+m[1]+"]:1080")
		}
	}
	return eps
}

// analyzeConnections inspects a netstat/ss dump for connections to known-bad
// IPs (infected) or to a *public* SOCKS endpoint on port 1080 (warn). Local or
// private :1080 listeners — common and benign — are deliberately ignored to
// avoid false positives.
func analyzeConnections(out string, bl inspect.Blocklist) Check {
	c := Check{Name: "connections", Status: StatusClean, Detail: "no connections to known-bad endpoints"}
	var hits []string
	infected := false

	if bad := scanFor(out, bl.IPs); len(bad) > 0 {
		infected = true
		for _, b := range bad {
			hits = append(hits, "known-bad IP "+b)
		}
	}
	for _, ep := range publicSocksEndpoints(out) {
		hits = append(hits, "public SOCKS endpoint "+ep)
	}

	if len(hits) > 0 {
		c.Detail = strings.Join(hits, "; ")
		if infected {
			c.Status = StatusInfected
		} else {
			c.Status = StatusWarn
		}
	}
	return c
}

// scanFor returns the blocklist terms (case-insensitive) found in text.
func scanFor(text string, terms []string) []string {
	low := strings.ToLower(text)
	var found []string
	seen := map[string]bool{}
	for _, t := range terms {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		if strings.Contains(low, strings.ToLower(t)) {
			found = append(found, t)
			seen[t] = true
		}
	}
	sort.Strings(found)
	return found
}
