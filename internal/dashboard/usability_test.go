package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vanndh/holone/internal/inspect"
	"github.com/vanndh/holone/internal/proxy"
)

func newScanTestServer(t *testing.T, got *ScanRequest) *httptest.Server {
	t.Helper()
	srv := New(Config{
		ListenAddr: "127.0.0.1:0",
		Engine:     mustEngine(t),
		ScanFn: func(req ScanRequest) (any, error) {
			*got = req
			return map[string]string{"protocol": req.Protocol, "path": req.Path}, nil
		},
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestScanRequestProtocolAndPathPassthrough(t *testing.T) {
	var got ScanRequest
	ts := newScanTestServer(t, &got)

	body := `{"base_url":"https://api.test.com","model":"m","protocol":"Anthropic","path":"  /v1/messages  "}`
	resp, err := http.Post(ts.URL+"/api/scan", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got.Protocol != "anthropic" {
		t.Fatalf("expected normalized protocol anthropic, got %q", got.Protocol)
	}
	if got.Path != "/v1/messages" {
		t.Fatalf("expected trimmed path, got %q", got.Path)
	}

	var echo map[string]string
	json.NewDecoder(resp.Body).Decode(&echo)
	if echo["protocol"] != "anthropic" || echo["path"] != "/v1/messages" {
		t.Fatalf("unexpected echo: %+v", echo)
	}
}

func TestScanRequestProtocolDefaultsToAuto(t *testing.T) {
	var got ScanRequest
	ts := newScanTestServer(t, &got)

	resp, err := http.Post(ts.URL+"/api/scan", "application/json",
		strings.NewReader(`{"base_url":"https://api.test.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got.Protocol != "auto" {
		t.Fatalf("expected protocol auto, got %q", got.Protocol)
	}
}

func TestScanRejectsInvalidProtocol(t *testing.T) {
	var got ScanRequest
	ts := newScanTestServer(t, &got)

	resp, err := http.Post(ts.URL+"/api/scan", "application/json",
		strings.NewReader(`{"base_url":"https://api.test.com","protocol":"grpc"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	var payload map[string]any
	json.NewDecoder(resp.Body).Decode(&payload)
	msg, _ := payload["error"].(string)
	if !strings.Contains(msg, "invalid protocol") || !strings.Contains(msg, "grpc") {
		t.Fatalf("expected clear invalid-protocol error, got %q", msg)
	}
}

func TestActivityRecordsDecisionProtection(t *testing.T) {
	al := NewActivityLog(10)
	pm := NewProxyManager(nil, nil, al)
	pm.recordDecision(Provider{Name: "Test"}, proxy.Decision{
		Verdict:     "alert",
		Protocol:    "anthropic",
		Path:        "/v1/messages",
		MaxSeverity: "high",
		Protection:  proxy.ProtectionMonitorOnly,
		Findings:    []inspect.Finding{{RuleID: "dl-curl"}},
	})

	recent := al.Recent(10)
	if len(recent) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(recent))
	}
	if recent[0].Protection != proxy.ProtectionMonitorOnly {
		t.Fatalf("expected protection monitor-only, got %q", recent[0].Protection)
	}

	// Entries without a protection stay empty instead of claiming "protected".
	al.Add(ActivityEntry{Type: "request", Message: "REQUEST GET /"})
	if got := al.Recent(1)[0].Protection; got != "" {
		t.Fatalf("request entry must not carry a protection value, got %q", got)
	}
}
