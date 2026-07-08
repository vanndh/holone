// Package dashboard provides an embedded web dashboard for managing holone:
// provider profiles, proxy lifecycle, activity monitoring, scans, audits, and
// rule catalog data — all from a single-page browser UI served on localhost.
package dashboard

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vanndh/holone/internal/inspect"
	"github.com/vanndh/holone/internal/proxy"
)

//go:embed ui/index.html
var uiFS embed.FS

const (
	defaultProxyListen = "127.0.0.1:8787"
	defaultProxyMode   = "monitor"
)

// Provider represents a configured LLM provider endpoint.
type Provider struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	BaseURL string   `json:"base_url"`
	APIKey  string   `json:"-"`
	Model   string   `json:"model,omitempty"`
	Tags    []string `json:"tags,omitempty"`
	Added   string   `json:"added"`
}

// ActivityEntry represents one logged decision or event.
type ActivityEntry struct {
	Time        string            `json:"time"`
	Type        string            `json:"type"`
	Provider    string            `json:"provider,omitempty"`
	Protocol    string            `json:"protocol,omitempty"`
	Verdict     string            `json:"verdict,omitempty"`
	MaxSeverity string            `json:"max_severity,omitempty"`
	RuleIDs     []string          `json:"rule_ids,omitempty"`
	Message     string            `json:"message,omitempty"`
	Path        string            `json:"path,omitempty"`
	Method      string            `json:"method,omitempty"`
	RequestBody string            `json:"request_body,omitempty"`
	Findings    []inspect.Finding `json:"findings,omitempty"`
}

// Status reflects the current dashboard-managed proxy state.
type Status struct {
	ProxyRunning  bool   `json:"proxy_running"`
	ListenAddr    string `json:"listen_addr"`
	ClientBaseURL string `json:"client_base_url"`
	Upstream      string `json:"upstream"`
	ProviderID    string `json:"provider_id,omitempty"`
	ProviderName  string `json:"provider_name,omitempty"`
	Mode          string `json:"mode"`
	RulesCount    int    `json:"rules_count"`
	AlertsTotal   int    `json:"alerts_total"`
	BlocksTotal   int    `json:"blocks_total"`
	Uptime        string `json:"uptime"`
}

// ScanRequest is the body for /api/scan.
type ScanRequest struct {
	BaseURL string `json:"base_url"`
	APIKey  string `json:"api_key"`
	Model   string `json:"model"`
}

// ProxyRequest controls the dashboard-managed local proxy.
type ProxyRequest struct {
	ProviderID string `json:"provider_id"`
	ListenAddr string `json:"listen_addr"`
	Mode       string `json:"mode"`
}

// Config configures the dashboard server.
type Config struct {
	ListenAddr string
	Token      string
	Providers  *ProviderStore
	Activity   *ActivityLog
	Engine     *inspect.Engine
	ProxyLog   *proxy.Logger
	ScanFn     func(req ScanRequest) (any, error)
	AuditFn    func() (any, error)
}

// Server is the dashboard HTTP server.
type Server struct {
	cfg     Config
	mux     *http.ServeMux
	http    *http.Server
	manager *ProxyManager
	started time.Time
}

// ProviderStore is a concurrency-safe in-memory provider profile store backed by
// a JSON file on disk.
type ProviderStore struct {
	mu   sync.RWMutex
	path string
	list []Provider
	next int
}

// LoadProviders reads profiles from ~/.holone/providers.json, creating an empty
// store if the file does not exist.
func LoadProviders() (*ProviderStore, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	dir := filepath.Join(home, ".holone")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return LoadProvidersFile(filepath.Join(dir, "providers.json"))
}

// LoadProvidersFile reads a provider store from a specific path.
func LoadProvidersFile(path string) (*ProviderStore, error) {
	ps := &ProviderStore{path: path, next: 1}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ps, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return ps, nil
	}
	if err := json.Unmarshal(data, &ps.list); err != nil {
		return nil, fmt.Errorf("parse providers.json: %w", err)
	}
	maxID := 0
	for _, p := range ps.list {
		var id int
		fmt.Sscanf(p.ID, "%d", &id)
		if id > maxID {
			maxID = id
		}
	}
	ps.next = maxID + 1
	return ps, nil
}

func (ps *ProviderStore) save() error {
	if ps.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(ps.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(ps.list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ps.path, data, 0o600)
}

// List returns all profiles.
func (ps *ProviderStore) List() []Provider {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	out := make([]Provider, len(ps.list))
	copy(out, ps.list)
	return out
}

// Get returns a profile by ID.
func (ps *ProviderStore) Get(id string) (Provider, bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	for _, p := range ps.list {
		if p.ID == id {
			return p, true
		}
	}
	return Provider{}, false
}

// Add inserts a new profile.
func (ps *ProviderStore) Add(name, baseURL, model string, tags []string) (Provider, error) {
	if err := validateProvider(name, baseURL); err != nil {
		return Provider{}, err
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	p := Provider{
		ID:      fmt.Sprint(ps.next),
		Name:    strings.TrimSpace(name),
		BaseURL: strings.TrimSpace(baseURL),
		Model:   strings.TrimSpace(model),
		Tags:    cleanTags(tags),
		Added:   time.Now().UTC().Format(time.RFC3339),
	}
	ps.next++
	ps.list = append(ps.list, p)
	if err := ps.save(); err != nil {
		return Provider{}, err
	}
	return p, nil
}

// Remove deletes a profile by ID.
func (ps *ProviderStore) Remove(id string) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for i, p := range ps.list {
		if p.ID == id {
			ps.list = append(ps.list[:i], ps.list[i+1:]...)
			_ = ps.save()
			return true
		}
	}
	return false
}

// Update modifies a profile.
func (ps *ProviderStore) Update(id, name, baseURL, model string, tags []string) (Provider, bool, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for i, p := range ps.list {
		if p.ID != id {
			continue
		}
		if name != "" {
			ps.list[i].Name = strings.TrimSpace(name)
		}
		if baseURL != "" {
			ps.list[i].BaseURL = strings.TrimSpace(baseURL)
		}
		if model != "" {
			ps.list[i].Model = strings.TrimSpace(model)
		}
		if tags != nil {
			ps.list[i].Tags = cleanTags(tags)
		}
		if err := validateProvider(ps.list[i].Name, ps.list[i].BaseURL); err != nil {
			ps.list[i] = p
			return Provider{}, true, err
		}
		if err := ps.save(); err != nil {
			ps.list[i] = p
			return Provider{}, true, err
		}
		return ps.list[i], true, nil
	}
	return Provider{}, false, nil
}

func (ps *ProviderStore) ReplaceAll(list []Provider) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	cleaned := make([]Provider, 0, len(list))
	maxID := 0
	for _, p := range list {
		if err := validateProvider(p.Name, p.BaseURL); err != nil {
			return err
		}
		p.ID = strings.TrimSpace(p.ID)
		if p.ID == "" {
			maxID++
			p.ID = fmt.Sprint(maxID)
		}
		if p.Added == "" {
			p.Added = time.Now().UTC().Format(time.RFC3339)
		}
		p.Name = strings.TrimSpace(p.Name)
		p.BaseURL = strings.TrimSpace(p.BaseURL)
		p.Model = strings.TrimSpace(p.Model)
		p.Tags = cleanTags(p.Tags)
		var id int
		fmt.Sscanf(p.ID, "%d", &id)
		if id > maxID {
			maxID = id
		}
		cleaned = append(cleaned, p)
	}
	ps.list = cleaned
	ps.next = maxID + 1
	return ps.save()
}

func (ps *ProviderStore) Export() []Provider {
	return ps.List()
}

func validateProvider(name, baseURL string) error {
	if strings.TrimSpace(name) == "" || strings.TrimSpace(baseURL) == "" {
		return errors.New("name and base_url are required")
	}
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("base_url must be an absolute http or https URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("base_url scheme must be http or https")
	}
	return nil
}

func cleanTags(tags []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" || seen[tag] {
			continue
		}
		seen[tag] = true
		out = append(out, tag)
	}
	sort.Strings(out)
	return out
}

// ActivityLog is a bounded, concurrency-safe ring buffer of events.
type ActivityLog struct {
	mu      sync.Mutex
	entries []ActivityEntry
	max     int
	alerts  int
	blocks  int
}

// NewActivityLog creates a ring buffer for up to max entries.
func NewActivityLog(max int) *ActivityLog {
	if max <= 0 {
		max = 500
	}
	return &ActivityLog{entries: make([]ActivityEntry, 0, max), max: max}
}

// Add pushes an entry, evicting oldest if full.
func (al *ActivityLog) Add(e ActivityEntry) {
	al.mu.Lock()
	defer al.mu.Unlock()
	if e.Time == "" {
		e.Time = time.Now().UTC().Format(time.RFC3339)
	}
	if len(al.entries) >= al.max {
		al.entries = al.entries[1:]
	}
	al.entries = append(al.entries, e)
	switch e.Type {
	case "alert":
		al.alerts++
	case "blocked":
		al.blocks++
	}
}

// Recent returns the most recent entries (newest first).
func (al *ActivityLog) Recent(limit int) []ActivityEntry {
	al.mu.Lock()
	defer al.mu.Unlock()
	if limit <= 0 || limit > len(al.entries) {
		limit = len(al.entries)
	}
	out := make([]ActivityEntry, limit)
	for i := 0; i < limit; i++ {
		out[i] = al.entries[len(al.entries)-1-i]
	}
	return out
}

// Stats returns alert/block counters.
func (al *ActivityLog) Stats() (alerts, blocks int) {
	al.mu.Lock()
	defer al.mu.Unlock()
	return al.alerts, al.blocks
}

// Clear removes all entries.
func (al *ActivityLog) Clear() {
	al.mu.Lock()
	defer al.mu.Unlock()
	al.entries = al.entries[:0]
}

// ProxyManager owns the dashboard-managed local proxy.
type ProxyManager struct {
	mu       sync.Mutex
	server   *http.Server
	provider Provider
	listen   string
	mode     proxy.Mode
	started  time.Time
	engine   *inspect.Engine
	logger   *proxy.Logger
	activity *ActivityLog
}

// NewProxyManager creates a stopped proxy manager.
func NewProxyManager(engine *inspect.Engine, logger *proxy.Logger, activity *ActivityLog) *ProxyManager {
	return &ProxyManager{engine: engine, logger: logger, activity: activity, mode: proxy.ModeMonitor, listen: defaultProxyListen}
}

// Start switches the local proxy to a provider profile.
func (pm *ProxyManager) Start(p Provider, listen, modeStr string) error {
	if err := validateProvider(p.Name, p.BaseURL); err != nil {
		return err
	}
	if listen == "" {
		listen = defaultProxyListen
	}
	if !isLocalListenAddr(listen) {
		return errors.New("proxy listen address must be localhost or loopback")
	}
	mode, err := proxy.ParseMode(modeStr)
	if err != nil {
		return err
	}
	up, err := url.Parse(p.BaseURL)
	if err != nil || up.Scheme == "" || up.Host == "" {
		return fmt.Errorf("invalid provider base_url %q", p.BaseURL)
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.stopLocked(context.Background())

	h := proxy.New(proxy.Config{
		Upstream: up,
		Engine:   pm.engine,
		Mode:     mode,
		Logger:   pm.logger,
		OnDecision: func(d proxy.Decision) {
			pm.recordDecision(p, d)
		},
	})
	recorder := proxyActivityRecorder{provider: p.Name, activity: pm.activity, next: h}
	srv := &http.Server{
		Addr:              listen,
		Handler:           recorder,
		ReadHeaderTimeout: 15 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	pm.server = srv
	pm.provider = p
	pm.listen = ln.Addr().String()
	pm.mode = mode
	pm.started = time.Now()
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			pm.activity.Add(ActivityEntry{Type: "proxy", Provider: p.Name, Verdict: "error", Message: err.Error()})
		}
	}()
	pm.activity.Add(ActivityEntry{Type: "proxy", Provider: p.Name, Verdict: "started", Message: "Proxy started for " + p.Name})
	return nil
}

// Stop shuts down the local proxy.
func (pm *ProxyManager) Stop(ctx context.Context) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.stopLocked(ctx)
}

func (pm *ProxyManager) stopLocked(ctx context.Context) error {
	if pm.server == nil {
		return nil
	}
	srv := pm.server
	provider := pm.provider.Name
	pm.server = nil
	pm.provider = Provider{}
	pm.started = time.Time{}
	err := srv.Shutdown(ctx)
	pm.activity.Add(ActivityEntry{Type: "proxy", Provider: provider, Verdict: "stopped", Message: "Proxy stopped"})
	return err
}

type proxyActivityRecorder struct {
	provider string
	activity *ActivityLog
	next     http.Handler
}

func (r proxyActivityRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(req.Body, 4096))
	req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	r.activity.Add(ActivityEntry{
		Type:        "request",
		Provider:    r.provider,
		Message:     fmt.Sprintf("REQUEST %s %s", req.Method, req.URL.Path),
		Path:        req.URL.Path,
		Method:      req.Method,
		RequestBody: truncateForActivity(string(body), 800),
	})
	r.next.ServeHTTP(w, req)
}

// Status returns the current proxy state.
func (pm *ProxyManager) Status() Status {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	running := pm.server != nil
	status := Status{
		ProxyRunning:  running,
		ListenAddr:    pm.listen,
		ClientBaseURL: "http://" + pm.listen,
		Mode:          pm.mode.String(),
	}
	if running {
		status.Upstream = pm.provider.BaseURL
		status.ProviderID = pm.provider.ID
		status.ProviderName = pm.provider.Name
		status.Uptime = time.Since(pm.started).Round(time.Second).String()
	}
	return status
}

func (pm *ProxyManager) recordDecision(p Provider, d proxy.Decision) {
	ruleIDs := make([]string, 0, len(d.Findings))
	seen := map[string]bool{}
	for _, f := range d.Findings {
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			ruleIDs = append(ruleIDs, f.RuleID)
		}
	}
	entryType := d.Verdict
	if entryType == "clean" {
		entryType = "clean"
	} else if entryType == "blocked" {
		entryType = "blocked"
	} else {
		entryType = "alert"
	}
	pm.activity.Add(ActivityEntry{
		Type:        entryType,
		Provider:    p.Name,
		Protocol:    d.Protocol,
		Verdict:     d.Verdict,
		MaxSeverity: d.MaxSeverity,
		RuleIDs:     ruleIDs,
		Message:     fmt.Sprintf("%s %s %s", strings.ToUpper(d.Verdict), d.Protocol, d.Path),
		Path:        d.Path,
		Findings:    append([]inspect.Finding(nil), d.Findings...),
	})
}

func truncateForActivity(s string, n int) string {
	s = strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func isLocalListenAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isLocalRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
