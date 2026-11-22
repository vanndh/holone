// Command holone is a client-independent guard against malicious LLM API
// providers. It inspects provider traffic for injected tool calls / payloads
// (the attack used by hostile "cheap API" resellers) without being tied to any
// particular AI client.
//
//	holone proxy    --upstream <real provider> --listen 127.0.0.1:8787
//	holone scan     <base-url> [--key KEY] [--protocol auto|chat-completions|responses|anthropic] [--path PATH]
//	holone audit
//	holone sentinel [--interval 30s]
//	holone dashboard [--listen 127.0.0.1:9090]
//
// Point your client's API base URL at the proxy and traffic is inspected on the
// wire. See README for per-client setup.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vanndh/holone/internal/dashboard"
	"github.com/vanndh/holone/internal/inspect"
	"github.com/vanndh/holone/internal/proxy"
	"github.com/vanndh/holone/internal/scanner"
	"github.com/vanndh/holone/internal/sentinel"
)

var version = "0.5.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	checkForUpdate(os.Args)
	args := argsWithoutUpdateFlag(os.Args)
	var err error
	switch args[1] {
	case "proxy":
		err = cmdProxy(args[2:])
	case "scan":
		err = cmdScan(args[2:])
	case "audit":
		err = cmdAudit(args[2:])
	case "sentinel":
		err = cmdSentinel(args[2:])
	case "dashboard":
		err = cmdDashboard(args[2:])
	case "version", "--version", "-v":
		fmt.Printf("holone %s\n", version)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[1])
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
  holone proxy     --upstream <url> [--listen 127.0.0.1:8787] [--mode monitor|block]
                   [--protocol auto|anthropic|openai|responses|gemini] [--egress-dlp off|warn|block|redact]
                   [--disable-rule <id,id>] [--log <file>] [--log-alerts-only] [--config <file>]
                   [--max-request-size 32MiB] [--max-response-size 64MiB]
  holone scan      <base-url> [--key <api-key>] [--model <name>] [--protocol auto|chat-completions|responses|anthropic] [--path <path>] [--rules <file>] [--blocklist <file>] [--json]
  holone audit     [--rules <file>] [--blocklist <file>] [--json]
  holone sentinel  [--interval 30s] [--rules <file>] [--blocklist <file>]
  holone dashboard [--listen 127.0.0.1:9090] [--token <secret>] [--egress-dlp off|warn|block|redact]
                   [--disable-rule <id,id>] [--log <file>] [--log-alerts-only] [--allow-private-scan] [--config <file>]
  holone version

QUICK START:
  1) holone proxy --upstream https://api-cc.freemodel.dev
  2) point your AI client's API base URL at http://127.0.0.1:8787
  3) work as usual; holone alerts on injected tool calls / payloads

Monitor mode (default) never alters traffic and adds ~0 latency.
Block mode strips malicious tool calls before they reach the client.
Dashboard mode serves a web UI at http://127.0.0.1:9090 for management.
`)
}

// --- proxy -----------------------------------------------------------------

func cmdProxy(args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	upstream := fs.String("upstream", "", "real provider base URL to forward to (required)")
	listen := fs.String("listen", "127.0.0.1:8787", "local address to listen on")
	modeStr := fs.String("mode", "monitor", "monitor | block")
	protoStr := fs.String("protocol", "auto", "auto | anthropic | openai | responses | gemini")
	dlpStr := fs.String("egress-dlp", "off", "off | warn | block | redact")
	disableRulesStr := fs.String("disable-rule", "", "comma-separated rule IDs to disable")
	logPath := fs.String("log", defaultLogPath(), "audit log file (jsonl); '-' for stdout")
	logAlertsOnly := fs.Bool("log-alerts-only", false, "write only alert/blocked decisions to the jsonl log")
	rulesPath := fs.String("rules", "", "optional custom rules.json (defaults to built-in)")
	blockPath := fs.String("blocklist", "", "optional custom blocklist.json (defaults to built-in)")
	maxReqStr := fs.String("max-request-size", "", "max buffered request body, e.g. 32MiB (default 32MiB)")
	maxRespStr := fs.String("max-response-size", "", "max buffered response body, e.g. 64MiB (default 64MiB)")
	configPath := fs.String("config", "", "optional config.json (defaults to ~/.holone/config.json if present)")
	fs.Parse(args)

	if *upstream == "" {
		return fmt.Errorf("--upstream is required (e.g. --upstream https://api.anthropic.com)")
	}
	up, err := url.Parse(*upstream)
	if err != nil || up.Scheme == "" || up.Host == "" {
		return fmt.Errorf("invalid --upstream %q", *upstream)
	}

	setFlags := visitedFlags(fs)
	fcfg, err := loadConfigFile(*configPath, setFlags["config"])
	if err != nil {
		return err
	}
	effMode := pickStr(setFlags["mode"], *modeStr, fcfg.Mode, "monitor")
	effProto := pickStr(setFlags["protocol"], *protoStr, fcfg.Protocol, "auto")
	effDLP := pickStr(setFlags["egress-dlp"], *dlpStr, fcfg.EgressDLP, "off")
	effRules := pickStr(setFlags["rules"], *rulesPath, fcfg.Rules, "")
	effBlock := pickStr(setFlags["blocklist"], *blockPath, fcfg.Blocklist, "")
	effMaxReq := pickStr(setFlags["max-request-size"], *maxReqStr, fcfg.MaxRequestSize, "")
	effMaxResp := pickStr(setFlags["max-response-size"], *maxRespStr, fcfg.MaxResponseSize, "")
	effAlertsOnly := *logAlertsOnly
	if !setFlags["log-alerts-only"] && fcfg.LogAlertsOnly {
		effAlertsOnly = true
	}

	mode, err := proxy.ParseMode(effMode)
	if err != nil {
		return err
	}
	proto, err := proxy.ParseProxyProtocol(effProto)
	if err != nil {
		return err
	}
	dlpMode, err := proxy.ParseDLPMode(effDLP)
	if err != nil {
		return err
	}
	eng, err := loadEngine(effRules, effBlock)
	if err != nil {
		return err
	}
	disabled := append([]string(nil), fcfg.DisableRules...)
	disabled = append(disabled, parseRuleIDList(*disableRulesStr)...)
	eng = eng.WithPolicy(inspect.Policy{
		DisabledRules:     disabled,
		SeverityOverrides: fcfg.SeverityOverrides,
	})

	maxReq, err := parseByteSize(effMaxReq)
	if err != nil {
		return fmt.Errorf("--max-request-size: %w", err)
	}
	maxResp, err := parseByteSize(effMaxResp)
	if err != nil {
		return fmt.Errorf("--max-response-size: %w", err)
	}

	logw, closeLog, err := openLog(*logPath)
	if err != nil {
		return err
	}
	defer closeLog()

	p := proxy.New(proxy.Config{
		Upstream:         up,
		Engine:           eng,
		Mode:             mode,
		Protocol:         proto,
		EgressDLP:        dlpMode,
		LogAlertsOnly:    effAlertsOnly,
		Logger:           proxy.NewLogger(logw),
		OnDecision:       printDecision,
		MaxRequestBytes:  maxReq,
		MaxResponseBytes: maxResp,
	})

	if !officialHost(up.Host) {
		fmt.Printf("%s⚠  upstream %s is NOT an official Anthropic/OpenAI endpoint — it can read every prompt you send.%s\n", yellow, up.Host, reset)
	}
	if warning := nonLocalListenWarning(*listen); warning != "" {
		fmt.Printf("%s%s%s\n", yellow, warning, reset)
	}
	if mode == proxy.ModeBlock {
		fmt.Printf("%s⚠  block mode is enforced for anthropic/openai/responses/gemini streams and buffered tool responses; unknown stream protocols run monitor-only (protection=unsupported).%s\n", yellow, reset)
	}
	fmt.Printf("%sholone%s proxy listening on http://%s  (mode=%s, protocol=%s, egress-dlp=%s, rules=%d)\n", bold, reset, *listen, mode, proto, dlpMode, eng.RuleCount())
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
	return serveWithGracefulShutdown(srv)
}

// --- scan ------------------------------------------------------------------

func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	key := fs.String("key", "", "API key (default: $ANTHROPIC_API_KEY)")
	model := fs.String("model", "", "model name to request")
	protocol := fs.String("protocol", "auto", "wire protocol: auto | chat-completions | responses | anthropic")
	pathOverride := fs.String("path", "", "explicit endpoint path override (e.g. /v1/chat/completions)")
	rulesPath := fs.String("rules", "", "optional custom rules.json (defaults to built-in)")
	blockPath := fs.String("blocklist", "", "optional custom blocklist.json (defaults to built-in)")
	asJSON := fs.Bool("json", false, "emit JSON report")
	fs.Parse(normalizeScanArgs(args))

	if fs.NArg() < 1 {
		return fmt.Errorf("usage: holone scan <base-url> [--key KEY] [--model NAME] [--protocol auto|chat-completions|responses|anthropic] [--path PATH] [--rules FILE] [--blocklist FILE] [--json]")
	}
	if _, err := scanner.NormalizeProtocol(*protocol); err != nil {
		return err
	}
	eng, err := loadEngine(*rulesPath, *blockPath)
	if err != nil {
		return err
	}
	apiKey := *key
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	var progress scanner.ProgressFunc
	if !*asJSON {
		fmt.Printf("%sholone scan%s — %s\n", bold, reset, fs.Arg(0))
		fmt.Printf("  resolving endpoint…  ")
		progress = func(probe, status string, findings int, errMsg string) {
			icon := green + "✓" + reset
			if status == "fail" {
				icon = red + "✗" + reset
			} else if status == "error" {
				icon = dim + "!" + reset
			}
			fmt.Printf("\r  %-22s %s  %s", probe, icon, status)
			if errMsg != "" {
				fmt.Printf("  %s(%s)%s", dim, truncateStr(errMsg, 40), reset)
			}
			if findings > 0 {
				fmt.Printf("  %s%d finding(s)%s", yellow, findings, reset)
			}
			fmt.Println()
		}
	}
	res, err := scanner.Scan(ctx, scanner.Options{
		BaseURL:  fs.Arg(0),
		APIKey:   apiKey,
		Model:    *model,
		Protocol: *protocol,
		Path:     *pathOverride,
		Engine:   eng,
		Progress: progress,
	})
	if err != nil {
		if !*asJSON {
			fmt.Printf("\r  %serror:%s %v\n", red, reset, err)
		}
		return err
	}
	if !*asJSON {
		fmt.Println()
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
	rulesPath := fs.String("rules", "", "optional custom rules.json (defaults to built-in)")
	blockPath := fs.String("blocklist", "", "optional custom blocklist.json (defaults to built-in)")
	asJSON := fs.Bool("json", false, "emit JSON report")
	fs.Parse(args)

	eng, err := loadEngine(*rulesPath, *blockPath)
	if err != nil {
		return err
	}

	checks := sentinel.AuditWithOptions(context.Background(), sentinel.Options{Engine: eng})
	if *asJSON {
		b, _ := json.MarshalIndent(checks, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	issues := len(sentinel.Infected(checks))
	fmt.Printf("%sholone audit%s — scanning this machine for known provider-malware indicators\n\n", bold, reset)
	for _, c := range checks {
		fmt.Printf("  %s  %-18s %s\n", statusBadge(c.Status), c.Name, c.Detail)
	}
	fmt.Println()
	if issues == 0 {
		fmt.Printf("%sClean — no indicators found.%s\n", green, reset)
	} else {
		fmt.Printf("%s%d indicator(s) found — investigate immediately.%s\n", red, issues, reset)
	}
	return nil
}

// --- sentinel --------------------------------------------------------------

func cmdSentinel(args []string) error {
	fs := flag.NewFlagSet("sentinel", flag.ExitOnError)
	interval := fs.Duration("interval", 30*time.Second, "re-scan interval")
	rulesPath := fs.String("rules", "", "optional custom rules.json (defaults to built-in)")
	blockPath := fs.String("blocklist", "", "optional custom blocklist.json (defaults to built-in)")
	fs.Parse(args)

	eng, err := loadEngine(*rulesPath, *blockPath)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("%sholone sentinel%s watching for provider-malware indicators every %s (Ctrl-C to stop)\n", bold, reset, *interval)
	sentinel.MonitorWithOptions(ctx, *interval, sentinel.Options{Engine: eng}, func(c sentinel.Check) {
		fmt.Printf("%s[%s]%s %s  %-18s %s\n", dim, time.Now().Format("15:04:05"), reset, statusBadge(c.Status), c.Name, c.Detail)
	})
	fmt.Println("\nsentinel stopped.")
	return nil
}

// --- dashboard -------------------------------------------------------------

func cmdDashboard(args []string) error {
	fs := flag.NewFlagSet("dashboard", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:9090", "address to serve the dashboard on")
	token := fs.String("token", "", "optional dashboard token (also accepts $HOLONE_DASHBOARD_TOKEN)")
	logPath := fs.String("log", defaultLogPath(), "audit log file (jsonl); '-' for stdout")
	logAlertsOnly := fs.Bool("log-alerts-only", false, "write only alert/blocked decisions to the jsonl log")
	rulesPath := fs.String("rules", "", "optional custom rules.json (defaults to built-in)")
	blockPath := fs.String("blocklist", "", "optional custom blocklist.json (defaults to built-in)")
	dlpStr := fs.String("egress-dlp", "off", "off | warn | block | redact")
	disableRulesStr := fs.String("disable-rule", "", "comma-separated rule IDs to disable")
	maxReqStr := fs.String("max-request-size", "", "max buffered request body, e.g. 32MiB (default 32MiB)")
	maxRespStr := fs.String("max-response-size", "", "max buffered response body, e.g. 64MiB (default 64MiB)")
	allowPrivateScan := fs.Bool("allow-private-scan", false, "allow scanning localhost/private network endpoints from dashboard")
	configPath := fs.String("config", "", "optional config.json (defaults to ~/.holone/config.json if present)")
	fs.Parse(args)

	if !listenIsLocal(*listen) {
		return fmt.Errorf("dashboard --listen must be localhost or loopback")
	}
	if *token == "" {
		*token = os.Getenv("HOLONE_DASHBOARD_TOKEN")
	}

	setFlags := visitedFlags(fs)
	fcfg, err := loadConfigFile(*configPath, setFlags["config"])
	if err != nil {
		return err
	}
	effDLP := pickStr(setFlags["egress-dlp"], *dlpStr, fcfg.EgressDLP, "off")
	effRules := pickStr(setFlags["rules"], *rulesPath, fcfg.Rules, "")
	effBlock := pickStr(setFlags["blocklist"], *blockPath, fcfg.Blocklist, "")
	effMaxReq := pickStr(setFlags["max-request-size"], *maxReqStr, fcfg.MaxRequestSize, "")
	effMaxResp := pickStr(setFlags["max-response-size"], *maxRespStr, fcfg.MaxResponseSize, "")
	effAlertsOnly := *logAlertsOnly
	if !setFlags["log-alerts-only"] && fcfg.LogAlertsOnly {
		effAlertsOnly = true
	}

	dlpMode, err := proxy.ParseDLPMode(effDLP)
	if err != nil {
		return err
	}
	maxReq, err := parseByteSize(effMaxReq)
	if err != nil {
		return fmt.Errorf("--max-request-size: %w", err)
	}
	maxResp, err := parseByteSize(effMaxResp)
	if err != nil {
		return fmt.Errorf("--max-response-size: %w", err)
	}

	providers, err := dashboard.LoadProviders()
	if err != nil {
		return fmt.Errorf("load providers: %w", err)
	}
	activity := dashboard.NewActivityLog(1000)

	eng, err := loadEngine(effRules, effBlock)
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	disabled := append([]string(nil), fcfg.DisableRules...)
	disabled = append(disabled, parseRuleIDList(*disableRulesStr)...)
	eng = eng.WithPolicy(inspect.Policy{
		DisabledRules:     disabled,
		SeverityOverrides: fcfg.SeverityOverrides,
	})

	logw, closeLog, err := openLog(*logPath)
	if err != nil {
		return err
	}
	defer closeLog()

	scanFn := func(req dashboard.ScanRequest) (any, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		res, err := scanner.Scan(ctx, scanner.Options{
			BaseURL:         req.BaseURL,
			APIKey:          req.APIKey,
			Model:           req.Model,
			Protocol:        req.Protocol,
			Path:            req.Path,
			BlockPrivateIPs: !*allowPrivateScan,
			Engine:          eng,
		})
		if err != nil {
			return nil, err
		}
		activity.Add(dashboard.ActivityEntry{
			Type:    "scan",
			Verdict: res.Verdict,
			Message: fmt.Sprintf("Scanned %s — %s (score %d)", res.Host, res.Verdict, res.RiskScore),
		})
		return res, nil
	}

	auditFn := func() (any, error) {
		ctx := context.Background()
		checks := sentinel.AuditWithOptions(ctx, sentinel.Options{Engine: eng})
		infected := len(sentinel.Infected(checks))
		activity.Add(dashboard.ActivityEntry{
			Type:    "audit",
			Verdict: fmt.Sprintf("%d issues", infected),
			Message: fmt.Sprintf("System audit: %d indicator(s) found", infected),
		})
		return checks, nil
	}

	srv := dashboard.New(dashboard.Config{
		Version:          version,
		ListenAddr:       *listen,
		Token:            *token,
		Providers:        providers,
		Activity:         activity,
		Engine:           eng,
		ProxyLog:         proxy.NewLogger(logw),
		MaxRequestBytes:  maxReq,
		MaxResponseBytes: maxResp,
		EgressDLP:        dlpMode,
		LogAlertsOnly:    effAlertsOnly,
		AllowPrivateScan: *allowPrivateScan,
		ScanFn:           scanFn,
		AuditFn:          auditFn,
	})

	fmt.Printf("%sholone dashboard%s (v%s) — http://%s\n", bold, reset, version, *listen)
	fmt.Printf("  managed proxy default: http://127.0.0.1:8787\n")
	if *token != "" {
		fmt.Printf("  dashboard token: required via X-Holone-Token or ?token=...\n")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		err := <-errCh
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// --- shared helpers --------------------------------------------------------

func serveWithGracefulShutdown(srv *http.Server) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		err := <-errCh
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func visitedFlags(fs *flag.FlagSet) map[string]bool {
	m := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		m[f.Name] = true
	})
	return m
}

func pickStr(cliSet bool, cliVal, cfgVal, fallback string) string {
	if cliSet {
		return cliVal
	}
	if strings.TrimSpace(cfgVal) != "" {
		return strings.TrimSpace(cfgVal)
	}
	if cliVal != "" {
		return cliVal
	}
	return fallback
}

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

func openLog(path string) (io.Writer, func(), error) {
	if path == "-" || path == "" {
		return os.Stdout, func() {}, nil
	}
	w, err := openRotatingLog(path, defaultMaxLogBytes, defaultMaxLogBackups)
	if err != nil {
		return nil, nil, err
	}
	return w, func() { _ = w.Close() }, nil
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
	// Enforcement gaps must be visible to the operator, not only in the jsonl
	// log: "protected" is the expected state and stays quiet.
	if d.Protection != "" && d.Protection != proxy.ProtectionProtected {
		fmt.Printf("  %s[protection=%s]%s\n", yellow, d.Protection, reset)
	}
}

func printScan(r *scanner.Result) {
	fmt.Printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("  %sEndpoint / Эндпоинт%s  %s\n", bold, reset, r.Endpoint)
	fmt.Printf("  %sHost / Хост%s          %-20s  %sOfficial / Офиц.%s %v\n", dim, reset, r.Host, dim, reset, r.Official)
	if len(r.ResolvedIPs) > 0 {
		fmt.Printf("  %sResolved / IP%s        %s\n", dim, reset, strings.Join(r.ResolvedIPs, ", "))
	}
	if r.TLS != nil {
		fmt.Printf("  %sTLS%s                  %s\n", dim, reset, r.TLS.Issuer)
		fmt.Printf("  %sCert / Сертификат%s    age=%d days / возраст=%d дн., valid until / до %s\n", dim, reset, r.TLS.AgeDays, r.TLS.AgeDays, r.TLS.NotAfter)
	}
	if len(r.BlocklistHits) > 0 {
		fmt.Printf("\n  %sIOC HITS / СОВПАДЕНИЯ IOC%s\n", red+bold, reset)
		for _, h := range r.BlocklistHits {
			fmt.Printf("    %s● %s%s\n", red, h, reset)
		}
	}
	if len(r.Discovery) > 0 {
		fmt.Printf("\n  %sProtocols / Протоколы%s  (mode: %s)\n", bold, reset, r.Protocol)
		for _, d := range r.Discovery {
			label, col := "supported / поддерживается", green
			if !d.Supported {
				label, col = "not supported / не поддерживается", dim
			}
			fmt.Printf("    %-18s %s%-36s%s %s%s%s\n", d.Protocol, col, label, reset, dim, d.Endpoint, reset)
		}
	}

	fmt.Printf("\n  %sSummary / Сводка%s\n", bold, reset)
	fmt.Printf("    EN: %s\n", r.SummaryEN)
	fmt.Printf("    RU: %s\n", r.SummaryRU)

	fmt.Printf("\n  %sProbes / Пробы%s\n", bold, reset)
	for _, p := range r.Probes {
		label := fmt.Sprintf("  %-28s", p.Protocol+"/"+p.Name)
		toolPolicy := "no tools / без tools"
		if p.DeclaredTools {
			toolPolicy = "tools declared / tools объявлены"
		}
		if p.Err != "" {
			fmt.Printf("%s %sFAIL / ОШИБКА%s  %s  (%s)\n", label, dim, reset, toolPolicy, truncateStr(p.Err, 60))
			continue
		}
		status := fmt.Sprintf("%sHTTP %d%s", dim, p.Status, reset)
		dur := fmt.Sprintf("%s%4dms%s", dim, p.DurationMs, reset)
		fmt.Printf("%s %s  %s  %s", label, status, dur, toolPolicy)
		if p.SawToolCall {
			fmt.Printf("  %sTOOL_CALL / ВЫЗОВ_TOOL%s", red+bold, reset)
		}
		fmt.Println()
		if len(p.Findings) > 0 {
			for _, f := range p.Findings {
				sev := f.Severity
				col := yellow
				if sev == "high" {
					col = red
				}
				desc := f.Description
				if desc == "" {
					desc = f.Category
				}
				fmt.Printf("    %s[%s]%s %-30s  %s%s%s\n", col, sev, reset, f.RuleID, dim, f.Match, reset)
				fmt.Printf("      %s%s%s\n", dim, desc, reset)
			}
		}
	}

	if len(r.Notes) > 0 || len(r.NotesRU) > 0 {
		fmt.Printf("\n  %sNotes / Заметки%s\n", bold, reset)
		for _, n := range r.Notes {
			fmt.Printf("    EN %s•%s %s\n", dim, reset, n)
		}
		for _, n := range r.NotesRU {
			fmt.Printf("    RU %s•%s %s\n", dim, reset, n)
		}
	}

	if len(r.RecommendationsEN) > 0 || len(r.RecommendationsRU) > 0 {
		fmt.Printf("\n  %sRecommendations / Рекомендации%s\n", bold, reset)
		for _, n := range r.RecommendationsEN {
			fmt.Printf("    EN %s•%s %s\n", dim, reset, n)
		}
		for _, n := range r.RecommendationsRU {
			fmt.Printf("    RU %s•%s %s\n", dim, reset, n)
		}
	}

	col := green
	verdict := r.Verdict
	switch r.Verdict {
	case "malicious", "high-risk":
		col, verdict = red+bold, strings.ToUpper(r.Verdict)
	case "suspicious":
		col, verdict = yellow, strings.ToUpper(r.Verdict)
	case "could-not-probe":
		col, verdict = dim, strings.ToUpper(r.Verdict)
	}
	fmt.Printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("  %sScore / Риск%s  %d/∞  │  %sVerdict / Вердикт%s  %s%s%s\n", bold, reset, r.RiskScore, bold, reset, col, verdict, reset)
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
}

func officialHost(host string) bool {
	h := strings.ToLower(host)
	return h == "api.anthropic.com" || h == "api.openai.com"
}

// nonLocalListenWarning returns the warning to print when addr is reachable by
// other machines, or "" when the listener is loopback-only.
func nonLocalListenWarning(addr string) string {
	if listenIsLocal(addr) {
		return ""
	}
	return fmt.Sprintf("⚠  --listen %s is NOT loopback: other machines on your network can reach this proxy, and their traffic will be inspected and forwarded through it. Use 127.0.0.1 unless you really need remote access.", addr)
}

// listenIsLocal reports whether addr binds only to the local machine. An
// unspecified host (":8787"), 0.0.0.0, or a LAN address counts as non-local.
func listenIsLocal(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
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
