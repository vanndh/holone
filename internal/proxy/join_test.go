package proxy

import (
	"net/http"
	"testing"
)

func TestSingleJoin(t *testing.T) {
	cases := []struct {
		name     string
		base     string
		request  string
		expected string
	}{
		{"empty base", "", "/v1/messages", "/v1/messages"},
		{"root base", "/", "/v1/messages", "/v1/messages"},
		{"plain base", "/api", "/v1/messages", "/api/v1/messages"},
		{"base trailing slash", "/api/", "/v1/messages", "/api/v1/messages"},
		{"versioned base", "/api/v1", "/v1/messages", "/api/v1/messages"},
		{"versioned base trailing slash", "/api/v1/", "/v1/messages", "/api/v1/messages"},
		{"versioned base case-insensitive", "/api/v1", "/V1/messages", "/api/v1/messages"},
		{"version only base", "/v1", "/v1/messages", "/v1/messages"},
		{"versioned base chat", "/api/v1", "/v1/chat/completions", "/api/v1/chat/completions"},
		{"versioned base unversioned request", "/api/v1", "/messages", "/api/v1/messages"},
		{"duplicate non-version segment", "/api", "/api/items", "/api/items"},
		{"different version not deduped", "/api/v2", "/v1/messages", "/api/v2/v1/messages"},
		{"request is just the segment", "/api/v1", "/v1", "/api/v1"},
		{"request root", "/api/v1", "/", "/api/v1/"},
		{"request empty", "/api/v1", "", "/api/v1/"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := singleJoin(c.base, c.request); got != c.expected {
				t.Errorf("singleJoin(%q, %q) = %q, want %q", c.base, c.request, got, c.expected)
			}
		})
	}
}

// The joined path actually reaches the upstream without duplicating the version.
func TestUpstreamBasePathNotDuplicated(t *testing.T) {
	var gotPath string
	front, _ := customProxy(t, ModeMonitor, func(c *Config) {
		c.Upstream.Path = "/api/v1"
	}, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})

	if resp, _ := doResp(t, front, "/v1/messages", bodyNoTools); resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if gotPath != "/api/v1/messages" {
		t.Fatalf("upstream path = %q, want /api/v1/messages", gotPath)
	}
}
