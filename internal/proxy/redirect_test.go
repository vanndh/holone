package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// A redirect to a different origin must be refused and must never reach the
// target, and the diagnostic must not echo the Location's query string.
func TestUpstreamCrossOriginRedirectBlocked(t *testing.T) {
	var hits int32
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Write([]byte(`{"secret":"exfiltrated"}`))
	}))
	defer victim.Close()

	front, _ := customProxy(t, ModeMonitor, nil, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, victim.URL+"/steal?api_key=SUPERSECRET", http.StatusFound)
	})

	resp, body := doResp(t, front, "/v1/messages", bodyNoTools)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (body %q)", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "holone: upstream redirect blocked:") {
		t.Errorf("unexpected diagnostic: %q", body)
	}
	if strings.Contains(string(body), "SUPERSECRET") {
		t.Errorf("diagnostic leaked the redirect query string: %q", body)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Errorf("cross-origin target received %d request(s)", n)
	}
}

// A same-origin redirect is followed transparently.
func TestUpstreamSameOriginRedirectFollowed(t *testing.T) {
	front, _ := customProxy(t, ModeMonitor, nil, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/messages" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":"final"}`))
	})

	resp, body := doResp(t, front, "/v1/messages", bodyNoTools)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"final"`) {
		t.Errorf("final response not forwarded: %q", body)
	}
}

// A same-origin chain of exactly maxRedirects hops is allowed.
func TestUpstreamRedirectChainWithinLimit(t *testing.T) {
	front, _ := customProxy(t, ModeMonitor, nil, func(w http.ResponseWriter, r *http.Request) {
		var n int
		fmt.Sscanf(r.URL.Query().Get("n"), "%d", &n)
		if n < maxRedirects {
			http.Redirect(w, r, fmt.Sprintf("/hop?n=%d", n+1), http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})

	resp, body := doResp(t, front, "/hop?n=0", bodyNoTools)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 after %d redirects (body %q)", resp.StatusCode, maxRedirects, body)
	}
}

// One more hop than allowed must be refused.
func TestUpstreamRedirectChainTooLongBlocked(t *testing.T) {
	var hits int32
	front, _ := customProxy(t, ModeMonitor, nil, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Redirect(w, r, "/loop", http.StatusFound)
	})

	resp, body := doResp(t, front, "/v1/messages", bodyNoTools)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (body %q)", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "stopped after 5 redirects") {
		t.Errorf("unexpected diagnostic: %q", body)
	}
	if n := atomic.LoadInt32(&hits); n > int32(maxRedirects+1) {
		t.Errorf("followed %d requests, want at most %d", n, maxRedirects+1)
	}
}

func TestSameOrigin(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"https://api.example.com/v1", "https://api.example.com/other", true},
		{"https://api.example.com:443/v1", "https://api.example.com/other", true},
		{"https://api.example.com/v1", "https://api.example.com:8443/other", false},
		{"https://api.example.com/v1", "http://api.example.com/other", false},
		{"https://api.example.com/v1", "https://evil.example.com/other", false},
		{"http://127.0.0.1:8080/x", "http://127.0.0.1:8080/y", true},
		{"http://127.0.0.1:8080/x", "http://127.0.0.1:9090/y", false},
	}
	for _, c := range cases {
		a, err := url.Parse(c.a)
		if err != nil {
			t.Fatal(err)
		}
		b, err := url.Parse(c.b)
		if err != nil {
			t.Fatal(err)
		}
		if got := sameOrigin(a, b); got != c.want {
			t.Errorf("sameOrigin(%s, %s) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
