package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vanndh/holone/internal/inspect"
)

func TestProviderStoreCRUD(t *testing.T) {
	dir := t.TempDir()
	ps := &ProviderStore{path: dir + "/providers.json", next: 1}

	p1, err := ps.Add("Test1", "https://api.test1.com", "claude-3-5-sonnet", []string{"anthropic"})
	if err != nil {
		t.Fatal(err)
	}
	if p1.ID != "1" || p1.Name != "Test1" || p1.Model != "claude-3-5-sonnet" {
		t.Fatalf("unexpected provider: %+v", p1)
	}
	p2, err := ps.Add("Test2", "https://api.test2.com", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if p2.ID != "2" {
		t.Fatalf("expected ID 2, got %s", p2.ID)
	}
	if len(ps.List()) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(ps.List()))
	}

	updated, ok, err := ps.Update("1", "Renamed", "https://api.new.com", "gpt-4o", []string{"openai"})
	if err != nil {
		t.Fatal(err)
	}
	if !ok || updated.Name != "Renamed" || updated.Model != "gpt-4o" {
		t.Fatalf("update failed: %+v ok=%v", updated, ok)
	}

	if !ps.Remove("2") {
		t.Fatal("remove failed")
	}
	if len(ps.List()) != 1 {
		t.Fatalf("expected 1 after remove, got %d", len(ps.List()))
	}
}

func TestProviderStoreRejectsInvalidBaseURL(t *testing.T) {
	ps := &ProviderStore{next: 1}
	if _, err := ps.Add("Bad", "file:///tmp/x", "", nil); err == nil {
		t.Fatal("expected invalid URL error")
	}
	if _, err := ps.Add("Bad", "not-a-url", "", nil); err == nil {
		t.Fatal("expected absolute URL error")
	}
}

func TestActivityLog(t *testing.T) {
	al := NewActivityLog(3)
	al.Add(ActivityEntry{Type: "alert", Message: "test1"})
	al.Add(ActivityEntry{Type: "clean", Message: "test2"})
	al.Add(ActivityEntry{Type: "blocked", Message: "test3"})
	al.Add(ActivityEntry{Type: "alert", Message: "test4"})

	recent := al.Recent(10)
	if len(recent) != 3 {
		t.Fatalf("expected 3 entries (ring buffer), got %d", len(recent))
	}
	if recent[0].Message != "test4" {
		t.Fatalf("expected newest first, got %q", recent[0].Message)
	}
	alerts, blocks := al.Stats()
	if alerts != 2 || blocks != 1 {
		t.Fatalf("expected alerts=2 blocks=1, got alerts=%d blocks=%d", alerts, blocks)
	}
	al.Clear()
	if len(al.Recent(10)) != 0 {
		t.Fatal("clear failed")
	}
}

func TestServerAPIs(t *testing.T) {
	eng, err := inspect.Default()
	if err != nil {
		t.Fatal(err)
	}
	ps := &ProviderStore{next: 1}
	if _, err := ps.Add("Test", "https://api.test.com", "claude-3-5-sonnet", nil); err != nil {
		t.Fatal(err)
	}
	al := NewActivityLog(100)
	al.Add(ActivityEntry{Type: "alert", Message: "hello"})

	srv := New(Config{
		ListenAddr: "127.0.0.1:0",
		Providers:  ps,
		Activity:   al,
		Engine:     eng,
		ScanFn: func(req ScanRequest) (any, error) {
			return map[string]any{"verdict": "clean", "host": req.BaseURL, "model": req.Model}, nil
		},
		AuditFn: func() (any, error) {
			return []map[string]string{{"name": "test", "status": "clean", "detail": "ok"}}, nil
		},
	})

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/api/status")
	if resp.StatusCode != 200 {
		t.Fatalf("status: expected 200, got %d", resp.StatusCode)
	}
	var st Status
	json.NewDecoder(resp.Body).Decode(&st)
	if st.RulesCount != eng.RuleCount() {
		t.Fatalf("expected %d rules, got %d", eng.RuleCount(), st.RulesCount)
	}
	if st.ProxyRunning {
		t.Fatal("proxy should be OFF initially")
	}

	resp, _ = http.Get(ts.URL + "/api/providers/export")
	if resp.StatusCode != 200 {
		t.Fatalf("export: expected 200, got %d", resp.StatusCode)
	}
	var exported struct {
		Providers []Provider `json:"providers"`
	}
	json.NewDecoder(resp.Body).Decode(&exported)
	if len(exported.Providers) < 1 {
		t.Fatal("expected exported providers")
	}

	resp, _ = http.Post(ts.URL+"/api/providers/import", "application/json",
		strings.NewReader(`{"providers":[{"id":"7","name":"Imported","base_url":"https://api.imported.com","model":"gpt-4o-mini","tags":["imported"]}]}`))
	if resp.StatusCode != 200 {
		t.Fatalf("import: expected 200, got %d", resp.StatusCode)
	}

	resp, _ = http.Get(ts.URL + "/api/providers")
	if resp.StatusCode != 200 {
		t.Fatalf("providers: expected 200, got %d", resp.StatusCode)
	}
	var list []Provider
	json.NewDecoder(resp.Body).Decode(&list)
	if len(list) != 1 || list[0].Name != "Imported" {
		t.Fatalf("unexpected providers after import: %+v", list)
	}

	resp, _ = http.Post(ts.URL+"/api/providers", "application/json",
		strings.NewReader(`{"name":"New","base_url":"https://api.new.com","model":"gpt-4o"}`))
	if resp.StatusCode != 200 {
		t.Fatalf("add provider: expected 200, got %d", resp.StatusCode)
	}

	resp, _ = http.Post(ts.URL+"/api/scan", "application/json",
		strings.NewReader(`{"base_url":"https://api.test.com","api_key":"sk-123","model":"gpt-4o"}`))
	if resp.StatusCode != 200 {
		t.Fatalf("scan: expected 200, got %d", resp.StatusCode)
	}

	resp, _ = http.Get(ts.URL + "/api/audit")
	if resp.StatusCode != 200 {
		t.Fatalf("audit: expected 200, got %d", resp.StatusCode)
	}

	resp, _ = http.Get(ts.URL + "/api/rules")
	if resp.StatusCode != 200 {
		t.Fatalf("rules: expected 200, got %d", resp.StatusCode)
	}
	var rules []inspect.RuleInfo
	json.NewDecoder(resp.Body).Decode(&rules)
	if len(rules) != eng.RuleCount() {
		t.Fatalf("expected %d rules, got %d", eng.RuleCount(), len(rules))
	}
	if rules[0].DescriptionEN == "" || rules[0].DescriptionRU == "" {
		t.Fatalf("rules must include bilingual descriptions: %+v", rules[0])
	}

	resp, _ = http.Get(ts.URL + "/")
	if resp.StatusCode != 200 {
		t.Fatalf("index: expected 200, got %d", resp.StatusCode)
	}
}

func TestServerRequiresTokenWhenConfigured(t *testing.T) {
	srv := New(Config{Token: "secret", Engine: mustEngine(t)})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/api/status")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/status", nil)
	req.Header.Set("X-Holone-Token", "secret")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with token, got %d", resp.StatusCode)
	}
}

func TestProxyStartStopFromDashboard(t *testing.T) {
	eng := mustEngine(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn"}`))
	}))
	defer upstream.Close()

	ps := &ProviderStore{next: 1}
	provider, err := ps.Add("Local", upstream.URL, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(Config{Providers: ps, Activity: NewActivityLog(100), Engine: eng})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, _ := http.Post(ts.URL+"/api/proxy/start", "application/json",
		strings.NewReader(`{"provider_id":"`+provider.ID+`","listen_addr":"127.0.0.1:0","mode":"block"}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("start proxy: expected 200, got %d", resp.StatusCode)
	}
	var st Status
	json.NewDecoder(resp.Body).Decode(&st)
	if !st.ProxyRunning || st.Mode != "block" || st.ProviderName != "Local" {
		t.Fatalf("unexpected proxy status: %+v", st)
	}

	proxyResp, err := http.Post("http://"+st.ListenAddr+"/v1/messages", "application/json", strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	proxyResp.Body.Close()

	resp, _ = http.Get(ts.URL + "/api/activity")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("activity after proxy request: expected 200, got %d", resp.StatusCode)
	}
	var activity []ActivityEntry
	json.NewDecoder(resp.Body).Decode(&activity)
	foundRequest := false
	for _, entry := range activity {
		if entry.Type == "request" {
			foundRequest = true
			if entry.Method != "POST" || entry.Path != "/v1/messages" || entry.RequestBody == "" {
				t.Fatalf("unexpected request activity: %+v", entry)
			}
			break
		}
	}
	if !foundRequest {
		t.Fatal("expected request activity entry")
	}

	resp, _ = http.Post(ts.URL+"/api/proxy/stop", "application/json", strings.NewReader(`{}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stop proxy: expected 200, got %d", resp.StatusCode)
	}
}

func mustEngine(t *testing.T) *inspect.Engine {
	t.Helper()
	eng, err := inspect.Default()
	if err != nil {
		t.Fatal(err)
	}
	return eng
}
