// Command holone is a client-independent guard against malicious LLM API
// providers. It inspects provider traffic for injected tool calls / payloads
// (the attack used by hostile "cheap API" resellers) without being tied to any
// particular AI client.
//
//	holone proxy    --upstream <real provider> --listen 127.0.0.1:8787
//	holone scan     <base-url> [--key KEY]
//	holone audit
//	holone sentinel [--interval 30s]
//
// Point your client's API base URL at the proxy and traffic is inspected on the
// wire. See README for per-client setup.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/vanndh/holone/internal/inspect"
	"github.com/vanndh/holone/internal/proxy"
	"github.com/vanndh/holone/internal/scanner"
	"github.com/vanndh/holone/internal/sentinel"
)

const version = "0.2.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "proxy":
		err = cmdProxy(os.Args[2:])
	case "scan":
		err = cmdScan(os.Args[2:])
	case "audit":
		err = cmdAudit(os.Args[2:])
	case "sentinel":
		err = cmdSentinel(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("holone %s\n", version)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%serror:%s %v\n", red, reset, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`holone — client-independent guard against malicious LLM API providers

USAGE:
  holone proxy    --upstream <url> [--listen 127.0.0.1:8787] [--mode monitor|block] [--log <file>]
  holone scan     <base-url> [--key <api-key>] [--model <name>] [--json]
  holone audit    [--json]
  holone sentinel [--interval 30s]
  holone version

QUICK START:
  1) holone proxy --upstream https://api-cc.freemodel.dev
  2) point your AI client's API base URL at http://127.0.0.1:8787
  3) work as usual; holone alerts on injected tool calls / payloads

Monitor mode (default) never alters traffic and adds ~0 latency.
Block mode strips malicious tool calls before they reach the client.
`)
}

// --- proxy -----------------------------------------------------------------

func cmdProxy(args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	upstream := fs.String("upstream", "", "real provider base URL to forward to (required)")
	listen := fs.String("listen", "127.0.0.1:8787", "local address to listen on")
	modeStr := fs.String("mode", "monitor", "monitor | block")
	logPath := fs.String("log", defaultLogPath(), "audit log file (jsonl); '-' for stdout")
	rulesPath := fs.String("rules", "", "optional custom rules.json (defaults to built-in)")
	blockPath := fs.String("blocklist", "", "optional custom blocklist.json (defaults to built-in)")
	fs.Parse(args)

	if *upstream == "" {
		return fmt.Errorf("--upstream is required (e.g. --upstream https://api.anthropic.com)")
	}
	up, err := url.Parse(*upstream)
	if err != nil || up.Scheme == "" || up.Host == "" {
		return fmt.Errorf("invalid --upstream %q", *upstream)
	}
	mode, err := proxy.ParseMode(*modeStr)
	if err != nil {
		return err
	}
	eng, err := loadEngine(*rulesPath, *blockPath)
	if err != nil {
		return err
	}

	logw, closeLog, err := openLog(*logPath)
	if err != nil {
		return err
	}
	defer closeLog()

	p := proxy.New(proxy.Config{
		Upstream:   up,
		Engine:     eng,
		Mode:       mode,
		Logger:     proxy.NewLogger(logw),
		OnDecision: printDecision,
	})

	if !officialHost(up.Host) {
		fmt.Printf("%s⚠  upstream %s is NOT an official Anthropic/OpenAI endpoint — it can read every prompt you send.%s\n", yellow, up.Host, reset)
	}
	fmt.Printf("%sholone%s proxy listening on http://%s  (mode=%s, rules=%d)\n", bold, reset, *listen, mode, eng.RuleCount())
	fmt.Printf("  forwarding to %s\n", up.String())
	fmt.Printf("  point your client's API base URL at: http://%s\n", *listen)

	// ReadHeaderTimeout guards against slow-header (Slowloris) clients without
	// truncating long-lived SSE streams (ReadTimeout/WriteTimeout left unset).
	srv := &http.Server{
		Addr:              *listen,
		Handler:           p,
		ReadHeaderTimeout: 15 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	return srv.ListenAndServe()
}

// --- scan ------------------------------------------------------------------

func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	key := fs.String("key", "", "API key (default: $ANTHROPIC_API_KEY)")
	model := fs.String("model", "", "model name to request")
	asJSON := fs.Bool("json", false, "emit JSON report")
	fs.Parse(args)

	if fs.NArg() < 1 {
		return fmt.Errorf("usage: holone scan <base-url> [--key KEY]")
	}
	apiKey := *key
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := scanner.Scan(ctx, scanner.Options{BaseURL: fs.Arg(0), APIKey: apiKey, Model: *model})
	if err != nil {
		return err
	}
	if *asJSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	printScan(res)
	return nil
}

// --- audit -----------------------------------------------------------------

func cmdAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "emit JSON report")
	fs.Parse(args)

	checks := sentinel.Audit(context.Background())
	if *asJSON {
		b, _ := json.MarshalIndent(checks, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	infected := 0
	fmt.Printf("%sholone audit%s — scanning this machine for known provider-malware indicators\n\n", bold, reset)
	for _, c := range checks {
		fmt.Printf("  %s  %-18s %s\n", statusBadge(c.Status), c.Name, c.Detail)
		if c.Status == sentinel.StatusInfected || c.Status == sentinel.StatusWarn {
			infected++
		}
	}
	fmt.Println()
	if infected == 0 {
		fmt.Printf("%sClean — no indicators found.%s\n", green, reset)
	} else {
		fmt.Printf("%s%d indicator(s) found — investigate immediately.%s\n", red, infected, reset)
	}
	return nil
}

// --- sentinel --------------------------------------------------------------

func cmdSentinel(args []string) error {
	fs := flag.NewFlagSet("sentinel", flag.ExitOnError)
	interval := fs.Duration("interval", 30*time.Second, "re-scan interval")
	fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Printf("%sholone sentinel%s watching for provider-malware indicators every %s (Ctrl-C to stop)\n", bold, reset, *interval)
	for _, c := range sentinel.Infected(sentinel.Audit(ctx)) {
		fmt.Printf("  %s  %-18s %s\n", statusBadge(c.Status), c.Name, c.Detail)
	}
	sentinel.Monitor(ctx, *interval, func(c sentinel.Check) {
		fmt.Printf("%s[%s]%s %s  %-18s %s\n", dim, time.Now().Format("15:04:05"), reset, statusBadge(c.Status), c.Name, c.Detail)
	})
	fmt.Println("\nsentinel stopped.")
	return nil
}

// --- shared helpers --------------------------------------------------------

func loadEngine(rulesPath, blockPath string) (*inspect.Engine, error) {
	if rulesPath == "" && blockPath == "" {
		return inspect.Default()
	}
	// Start from embedded defaults, override whichever file the user supplied.
	rulesData, blockData := inspect.EmbeddedSources()
	if rulesPath != "" {
		b, err := os.ReadFile(rulesPath)
		if err != nil {
			return nil, fmt.Errorf("read rules %q: %w", rulesPath, err)
		}
		rulesData = b
	}
	if blockPath != "" {
		b, err := os.ReadFile(blockPath)
		if err != nil {
			return nil, fmt.Errorf("read blocklist %q: %w", blockPath, err)
		}
		blockData = b
	}
	return inspect.New(rulesData, blockData)
}

func defaultLogPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "holone.log"
	}
	dir := filepath.Join(home, ".holone")
	os.MkdirAll(dir, 0o700)
	return filepath.Join(dir, "holone.log")
}

func openLog(path string) (*os.File, func(), error) {
	if path == "-" || path == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open log %q: %w", path, err)
	}
	// Tighten perms even if the file pre-existed world-readable.
	_ = f.Chmod(0o600)
	return f, func() { f.Close() }, nil
}

func printDecision(d proxy.Decision) {
	col := yellow
	if d.MaxSeverity == "high" {
		col = red
	}
	tag := strings.ToUpper(d.Verdict)
	fmt.Printf("%s%s%s %s%s%s [%s] rules:", col, tag, reset, dim, d.Time, reset, d.Protocol)
	seen := map[string]bool{}
	for _, f := range d.Findings {
		if seen[f.RuleID] {
			continue
		}
		seen[f.RuleID] = true
		fmt.Printf(" %s", f.RuleID)
	}
	fmt.Println()
}

func printScan(r *scanner.Result) {
	fmt.Printf("%sholone scan%s — %s\n\n", bold, reset, r.Endpoint)
	fmt.Printf("  host:        %s (official: %v)\n", r.Host, r.Official)
	if len(r.ResolvedIPs) > 0 {
		fmt.Printf("  resolves to: %s\n", strings.Join(r.ResolvedIPs, ", "))
	}
	if r.TLS != nil {
		fmt.Printf("  tls issuer:  %s (cert age %d days)\n", r.TLS.Issuer, r.TLS.AgeDays)
	}
	for _, h := range r.BlocklistHits {
		fmt.Printf("  %sIOC HIT:     %s%s\n", red, h, reset)
	}
	fmt.Println("\n  probes:")
	for _, p := range r.Probes {
		line := fmt.Sprintf("    %-16s status=%d sawToolCall=%v findings=%d", p.Name, p.Status, p.SawToolCall, len(p.Findings))
		if p.Err != "" {
			line += " err=" + p.Err
		}
		fmt.Println(line)
	}
	if len(r.Notes) > 0 {
		fmt.Println("\n  notes:")
		for _, n := range r.Notes {
			fmt.Printf("    - %s\n", n)
		}
	}
	col := green
	switch r.Verdict {
	case "malicious", "high-risk":
		col = red
	case "suspicious":
		col = yellow
	}
	fmt.Printf("\n  risk score: %d  verdict: %s%s%s\n", r.RiskScore, col, r.Verdict, reset)
}

func officialHost(host string) bool {
	h := strings.ToLower(host)
	return h == "api.anthropic.com" || h == "api.openai.com"
}

// --- tiny ANSI palette (disabled when NO_COLOR is set) ---------------------

var (
	red    = color("\033[31m")
	green  = color("\033[32m")
	yellow = color("\033[33m")
	dim    = color("\033[2m")
	bold   = color("\033[1m")
	reset  = color("\033[0m")
)

func color(c string) string {
	if os.Getenv("NO_COLOR") != "" {
		return ""
	}
	return c
}

func statusBadge(status string) string {
	switch status {
	case sentinel.StatusInfected:
		return red + "INFECTED" + reset
	case sentinel.StatusWarn:
		return yellow + "  WARN  " + reset
	case sentinel.StatusError:
		return dim + " ERROR  " + reset
	default:
		return green + " clean  " + reset
	}
}
