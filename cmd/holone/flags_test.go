package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/vanndh/holone/internal/proxy"
)

func TestNormalizeScanArgsAllowsFlagsAfterURL(t *testing.T) {
	got := normalizeScanArgs([]string{"https://example.com", "--json", "--model", "gpt-4o", "--key", "sk-test"})
	want := []string{"--json", "--model", "gpt-4o", "--key", "sk-test", "https://example.com"}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: got %+v want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("arg %d mismatch: got %+v want %+v", i, got, want)
		}
	}
}

func TestParseByteSize(t *testing.T) {
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"   ", 0, false},
		{"0", 0, false},
		{"1024", 1024, false},
		{"1B", 1, false},
		{"1b", 1, false},
		{"32MiB", 32 << 20, false},
		{"32mib", 32 << 20, false},
		{"32MIB", 32 << 20, false},
		{"32MB", 32 << 20, false},
		{"32 mb", 32 << 20, false},
		{"64KiB", 64 << 10, false},
		{"64KB", 64 << 10, false},
		{"1GiB", 1 << 30, false},
		{"2GB", 2 << 30, false},
		{" 8MiB ", 8 << 20, false},
		{"abc", 0, true},
		{"-1", 0, true},
		{"1.5MiB", 0, true},
		{"10XB", 0, true},
		{"MiB", 0, true},
		{"99999999999999999999GiB", 0, true},
	}
	for _, c := range cases {
		got, err := parseByteSize(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseByteSize(%q) = %d, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseByteSize(%q): unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseByteSize(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// printDecision must surface enforcement gaps on the console, not only in the
// jsonl log; "protected" stays quiet.
func TestPrintDecisionShowsProtectionGap(t *testing.T) {
	capture := func(d proxy.Decision) string {
		old := os.Stdout
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		os.Stdout = w
		printDecision(d)
		w.Close()
		os.Stdout = old
		b, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	base := proxy.Decision{Verdict: "alert", MaxSeverity: "high", Protocol: "anthropic"}

	base.Protection = proxy.ProtectionProtected
	if out := capture(base); strings.Contains(out, "protection=") {
		t.Errorf("protected decision must not print a protection line: %q", out)
	}

	base.Protection = proxy.ProtectionMonitorOnly
	if out := capture(base); !strings.Contains(out, "[protection=monitor-only]") {
		t.Errorf("monitor-only decision must print the protection line: %q", out)
	}

	base.Protection = proxy.ProtectionUnsupported
	if out := capture(base); !strings.Contains(out, "[protection=unsupported]") {
		t.Errorf("unsupported decision must print the protection line: %q", out)
	}
}
