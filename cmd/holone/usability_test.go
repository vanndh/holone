package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestListenIsLocal(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8787", true},
		{"localhost:8787", true},
		{"LOCALHOST:8787", true},
		{"[::1]:8787", true},
		{"0.0.0.0:8787", false},
		{"192.168.1.5:8787", false},
		{"10.0.0.7:8787", false},
		{":8787", false},
		{"example.com:8787", false},
		{"not-an-addr", false},
	}
	for _, c := range cases {
		if got := listenIsLocal(c.addr); got != c.want {
			t.Errorf("listenIsLocal(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

func TestNonLocalListenWarning(t *testing.T) {
	if got := nonLocalListenWarning("127.0.0.1:8787"); got != "" {
		t.Fatalf("loopback listener must not warn, got %q", got)
	}
	for _, addr := range []string{"0.0.0.0:8787", "192.168.1.5:8787", "[::]:8787", ":8787"} {
		got := nonLocalListenWarning(addr)
		if !strings.Contains(got, "NOT loopback") || !strings.Contains(got, addr) {
			t.Fatalf("expected a prominent warning for %q, got %q", addr, got)
		}
	}
}

func TestCmdProxyRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"missing upstream", nil, "--upstream is required"},
		{"invalid upstream", []string{"--upstream", "not-a-url"}, "invalid --upstream"},
		{"invalid mode", []string{"--upstream", "https://api.example.com", "--mode", "bogus"}, "unknown mode"},
		{"invalid protocol", []string{"--upstream", "https://api.example.com", "--protocol", "grpc"}, "unknown protocol"},
		{"invalid egress dlp", []string{"--upstream", "https://api.example.com", "--egress-dlp", "bogus"}, "unknown egress-dlp mode"},
		{"invalid max request size", []string{"--upstream", "https://api.example.com", "--max-request-size", "12XB"}, "--max-request-size"},
		{"invalid max response size", []string{"--upstream", "https://api.example.com", "--max-response-size", "12.5MiB"}, "--max-response-size"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := cmdProxy(c.args)
			if err == nil {
				t.Fatalf("expected an error for %s", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q must mention %q", err, c.want)
			}
		})
	}
}

func TestCmdScanRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"missing url", nil, "usage: holone scan"},
		{"invalid protocol", []string{"https://api.example.com", "--protocol", "grpc"}, "invalid protocol"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := cmdScan(c.args)
			if err == nil {
				t.Fatalf("expected an error for %s", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q must mention %q", err, c.want)
			}
		})
	}
}

func TestConfigFileLoader(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.json")

	if cfg, err := loadConfigFile(missing, false); err != nil || cfg.Mode != "" {
		t.Fatalf("missing non-explicit should return zero config, got cfg=%+v err=%v", cfg, err)
	}
	if _, err := loadConfigFile(missing, true); err == nil {
		t.Fatal("missing explicit config must fail")
	}

	validPath := filepath.Join(dir, "config.json")
	raw := `{"mode":"block","protocol":"gemini","egress_dlp":"redact","disable_rules":["r1","r2"],"severity_overrides":{"r3":"critical"},"log_alerts_only":true}`
	if err := os.WriteFile(validPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfigFile(validPath, true)
	if err != nil {
		t.Fatalf("valid config failed: %v", err)
	}
	if cfg.Mode != "block" || cfg.Protocol != "gemini" || cfg.EgressDLP != "redact" || !cfg.LogAlertsOnly {
		t.Fatalf("unexpected parsed config: %+v", cfg)
	}
	if len(cfg.DisableRules) != 2 || cfg.SeverityOverrides["r3"] != "critical" {
		t.Fatalf("unexpected policy fields in config: %+v", cfg)
	}

	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte(`{bad`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfigFile(badPath, true); err == nil {
		t.Fatal("invalid JSON config must fail")
	}

	ids := parseRuleIDList(" a, , b ,c ")
	if len(ids) != 3 || ids[0] != "a" || ids[1] != "b" || ids[2] != "c" {
		t.Fatalf("parseRuleIDList unexpected: %#v", ids)
	}
}

func TestRotatingLogWriter(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "nested", "audit.log")

	w, err := openRotatingLog(logPath, 20, 2)
	if err != nil {
		t.Fatalf("openRotatingLog: %v", err)
	}
	defer func() { _ = w.Close() }()

	lines := []string{
		"123456789012345678\n", // 19 bytes -> main
		"aaaaaaaaaaaaaaaaaa\n", // rotates main -> .1
		"bbbbbbbbbbbbbbbbbb\n", // rotates .1 -> .2, main -> .1
		"cccccccccccccccccc\n", // rotates .2 deleted, .1 -> .2, main -> .1
	}
	for _, line := range lines {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatalf("Write(%q): %v", line, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	gotCur, err := os.ReadFile(logPath)
	if err != nil || string(gotCur) != lines[3] {
		t.Fatalf("current log got %q err=%v want %q", gotCur, err, lines[3])
	}
	got1, err := os.ReadFile(logPath + ".1")
	if err != nil || string(got1) != lines[2] {
		t.Fatalf(".1 backup got %q err=%v want %q", got1, err, lines[2])
	}
	got2, err := os.ReadFile(logPath + ".2")
	if err != nil || string(got2) != lines[1] {
		t.Fatalf(".2 backup got %q err=%v want %q", got2, err, lines[1])
	}
	if _, err := os.Stat(logPath + ".3"); !os.IsNotExist(err) {
		t.Fatalf(".3 backup must be pruned, stat err=%v", err)
	}
}
