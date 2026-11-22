package dashboard

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDashboardProxyDoesNotTruncateAndRedactsPreview(t *testing.T) {
	eng := mustEngine(t)
	var receivedBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn"}`))
	}))
	defer upstream.Close()

	ps := &ProviderStore{next: 1}
	provider, err := ps.Add("Local", upstream.URL, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(Config{Version: "0.5.0", Providers: ps, Activity: NewActivityLog(100), Engine: eng})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/proxy/start", "application/json",
		strings.NewReader(`{"provider_id":"`+provider.ID+`","listen_addr":"127.0.0.1:0","mode":"monitor"}`))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("start proxy failed: status=%v err=%v", resp.StatusCode, err)
	}
	var st Status
	json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	if st.Version != "0.5.0" {
		t.Fatalf("status.Version = %q, want 0.5.0", st.Version)
	}

	const secret = "sk-proj-abcdefghijklmnop1234567890"
	largeReq := `{"secret":"` + secret + `","pad":"` + strings.Repeat("Z", 16<<10) + `"}`
	proxyResp, err := http.Post("http://"+st.ListenAddr+"/v1/messages", "application/json", strings.NewReader(largeReq))
	if err != nil {
		t.Fatal(err)
	}
	proxyResp.Body.Close()

	if receivedBody != largeReq {
		t.Fatalf("dashboard proxy truncated request body: got %d bytes, want %d bytes", len(receivedBody), len(largeReq))
	}

	actResp, _ := http.Get(ts.URL + "/api/activity")
	var entries []ActivityEntry
	json.NewDecoder(actResp.Body).Decode(&entries)
	actResp.Body.Close()
	var reqEntry *ActivityEntry
	for i := range entries {
		if entries[i].Type == "request" {
			reqEntry = &entries[i]
			break
		}
	}
	if reqEntry == nil {
		t.Fatal("missing request activity entry")
	}
	if strings.Contains(reqEntry.RequestBody, secret) || !strings.Contains(reqEntry.RequestBody, "sk-[REDACTED]") {
		t.Fatalf("activity request preview leaked raw secret: %q", reqEntry.RequestBody)
	}

	stopResp, _ := http.Post(ts.URL+"/api/proxy/stop", "application/json", strings.NewReader(`{}`))
	stopResp.Body.Close()
}

func TestDashboardCSRFAndSSRFAndSecurityHeaders(t *testing.T) {
	eng := mustEngine(t)
	ps := &ProviderStore{next: 1}
	_, _ = ps.Add("P1", "https://api.example.com", "", nil)
	srv := New(Config{
		Version:   "0.5.0",
		Providers: ps,
		Engine:    eng,
		ScanFn: func(req ScanRequest) (any, error) {
			return map[string]string{"ok": "1"}, nil
		},
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	t.Run("rejects cross-origin Origin", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/providers", strings.NewReader(`{"name":"x","base_url":"https://a.example"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "https://evil.example")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("rejects cross-site Sec-Fetch-Site", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/proxy/stop", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("rejects non-JSON POST", func(t *testing.T) {
		resp, err := http.Post(ts.URL+"/api/proxy/start", "text/plain", strings.NewReader(`{"provider_id":"1"}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnsupportedMediaType {
			t.Fatalf("status = %d, want 415", resp.StatusCode)
		}
	})

	t.Run("rejects private/loopback scan targets by default", func(t *testing.T) {
		for _, target := range []string{"http://127.0.0.1:8080", "http://169.254.169.254/latest", "http://localhost:9090"} {
			resp, err := http.Post(ts.URL+"/api/scan", "application/json", strings.NewReader(`{"base_url":"`+target+`"}`))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("scan %q status = %d, want 400", target, resp.StatusCode)
			}
		}
	})

	t.Run("sets CSP and X-Frame-Options", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.Header.Get("X-Frame-Options") != "DENY" {
			t.Errorf("missing X-Frame-Options: %q", resp.Header.Get("X-Frame-Options"))
		}
		if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Errorf("missing CSP frame-ancestors: %q", resp.Header.Get("Content-Security-Policy"))
		}
	})
}

func TestDashboardEventsSSE(t *testing.T) {
	al := NewActivityLog(20)
	srv := New(Config{Activity: al, Engine: mustEngine(t)})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("unexpected SSE response: status=%d ct=%q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	lineCh := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			lineCh <- sc.Text()
		}
		close(lineCh)
	}()

	// Wait briefly for subscription, then push an activity event.
	time.Sleep(50 * time.Millisecond)
	al.Add(ActivityEntry{Type: "alert", Message: "sse-live-test"})

	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for SSE activity event")
		case line, ok := <-lineCh:
			if !ok {
				t.Fatal("SSE stream closed unexpectedly")
			}
			if strings.Contains(line, "sse-live-test") {
				return
			}
		}
	}
}

func TestDashboardHTMLNoUnsafeInlineHandlersOrStaleVersion(t *testing.T) {
	b, err := os.ReadFile("ui/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	for _, bad := range []string{
		"onclick='showActivityDetails",
		"onclick='showRuleExplain",
		"v0.3.0",
	} {
		if strings.Contains(html, bad) {
			t.Errorf("ui/index.html still contains unsafe/stale pattern %q", bad)
		}
	}
}
