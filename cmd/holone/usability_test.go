package main

import (
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
