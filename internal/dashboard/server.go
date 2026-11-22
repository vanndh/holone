package dashboard

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vanndh/holone/internal/scanner"
)

const maxDashboardBodyBytes = 1 << 20 // 1 MiB

func New(cfg Config) *Server {
	if cfg.Activity == nil {
		cfg.Activity = NewActivityLog(500)
	}
	if cfg.Providers == nil {
		cfg.Providers = &ProviderStore{next: 1}
	}
	manager := newProxyManagerFromConfig(cfg)
	srv := &Server{
		cfg:     cfg,
		mux:     http.NewServeMux(),
		manager: manager,
		started: time.Now(),
	}
	srv.routes()
	srv.http = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.localOnly(srv.mux),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	return srv
}

func (s *Server) routes() {
	s.mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		status := s.manager.Status()
		status.Version = s.cfg.Version
		if status.ListenAddr == "" {
			status.ListenAddr = defaultProxyListen
			status.ClientBaseURL = "http://" + defaultProxyListen
		}
		if s.cfg.Engine != nil {
			status.RulesCount = s.cfg.Engine.RuleCount()
		}
		alerts, blocks := s.cfg.Activity.Stats()
		status.AlertsTotal = alerts
		status.BlocksTotal = blocks
		if status.Uptime == "" {
			status.Uptime = time.Since(s.started).Round(time.Second).String()
		}
		writeJSON(w, status)
	})

	s.mux.HandleFunc("/api/providers", func(w http.ResponseWriter, r *http.Request) {
		s.handleProviders(w, r)
	})

	s.mux.HandleFunc("/api/providers/import", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxDashboardBodyBytes)
		var payload struct {
			Providers []Provider `json:"providers"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.cfg.Providers.ReplaceAll(payload.Providers); err != nil {
			writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"status": "imported", "count": len(payload.Providers)})
	})

	s.mux.HandleFunc("/api/providers/export", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, map[string]any{"providers": s.cfg.Providers.Export()})
	})

	s.mux.HandleFunc("/api/proxy/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxDashboardBodyBytes)
		var req ProxyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		provider, ok := s.cfg.Providers.Get(req.ProviderID)
		if !ok {
			writeError(w, "provider not found", http.StatusNotFound)
			return
		}
		if err := s.manager.Start(provider, req.ListenAddr, req.Mode); err != nil {
			writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		st := s.manager.Status()
		st.Version = s.cfg.Version
		writeJSON(w, st)
	})

	s.mux.HandleFunc("/api/proxy/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := s.manager.Stop(ctx); err != nil {
			writeError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		st := s.manager.Status()
		st.Version = s.cfg.Version
		writeJSON(w, st)
	})

	s.mux.HandleFunc("/api/activity", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			s.cfg.Activity.Clear()
			writeJSON(w, map[string]string{"status": "cleared"})
			return
		}
		limit := 200
		if raw := r.URL.Query().Get("limit"); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 1000 {
				limit = n
			}
		}
		writeJSON(w, s.cfg.Activity.Recent(limit))
	})

	s.mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			writeError(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(": connected\n\n"))
		flusher.Flush()

		ch, unsub := s.cfg.Activity.Subscribe()
		defer unsub()

		keepalive := time.NewTicker(20 * time.Second)
		defer keepalive.Stop()

		for {
			select {
			case <-r.Context().Done():
				return
			case entry, ok := <-ch:
				if !ok {
					return
				}
				b, err := json.Marshal(entry)
				if err != nil {
					continue
				}
				if _, err := fmt.Fprintf(w, "event: activity\ndata: %s\n\n", b); err != nil {
					return
				}
				flusher.Flush()
			case <-keepalive.C:
				if _, err := w.Write([]byte(": keepalive\n\n")); err != nil {
					return
				}
				flusher.Flush()
			}
		}
	})

	s.mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Engine == nil {
			writeJSON(w, []any{})
			return
		}
		writeJSON(w, s.cfg.Engine.Rules())
	})

	s.mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		if s.cfg.ScanFn == nil {
			writeError(w, "scanner not configured", http.StatusNotImplemented)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxDashboardBodyBytes)
		var req ScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.BaseURL) == "" {
			writeError(w, "base_url required", http.StatusBadRequest)
			return
		}
		if !s.cfg.AllowPrivateScan {
			if err := validatePublicScanURL(req.BaseURL); err != nil {
				writeError(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		protocol, err := scanner.NormalizeProtocol(req.Protocol)
		if err != nil {
			writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		req.Protocol = protocol
		req.Path = strings.TrimSpace(req.Path)
		result, err := s.cfg.ScanFn(req)
		if err != nil {
			writeError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, result)
	})

	s.mux.HandleFunc("/api/audit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		if s.cfg.AuditFn == nil {
			writeError(w, "audit not configured", http.StatusNotImplemented)
			return
		}
		result, err := s.cfg.AuditFn()
		if err != nil {
			writeError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, result)
	})

	indexHTML, _ := uiFS.ReadFile("ui/index.html")
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(indexHTML)
			return
		}
		http.NotFound(w, r)
	})
}

func (s *Server) handleProviders(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.cfg.Providers.List())
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, maxDashboardBodyBytes)
		var p Provider
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		added, err := s.cfg.Providers.Add(p.Name, p.BaseURL, p.Model, p.Tags)
		if err != nil {
			writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, added)
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			writeError(w, "?id required", http.StatusBadRequest)
			return
		}
		if !s.cfg.Providers.Remove(id) {
			writeError(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]string{"status": "deleted"})
	case http.MethodPut:
		id := r.URL.Query().Get("id")
		if id == "" {
			writeError(w, "?id required", http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxDashboardBodyBytes)
		var p Provider
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		updated, ok, err := s.cfg.Providers.Update(id, p.Name, p.BaseURL, p.Model, p.Tags)
		if err != nil {
			writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !ok {
			writeError(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, updated)
	default:
		writeError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) ListenAndServe() error {
	return s.http.ListenAndServe()
}

func (s *Server) Handler() http.Handler {
	return s.localOnly(s.mux)
}

func (s *Server) Shutdown(ctx context.Context) error {
	_ = s.manager.Stop(ctx)
	return s.http.Shutdown(ctx)
}

func (s *Server) localOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")

		if !isLocalRequest(r) {
			writeError(w, "dashboard accepts localhost requests only", http.StatusForbidden)
			return
		}
		if err := checkSameOriginRequest(r); err != nil {
			writeError(w, err.Error(), http.StatusForbidden)
			return
		}
		if err := checkJSONContentType(r); err != nil {
			writeError(w, err.Error(), http.StatusUnsupportedMediaType)
			return
		}
		if s.cfg.Token != "" {
			got := r.Header.Get("X-Holone-Token")
			if got == "" {
				got = r.URL.Query().Get("token")
			}
			if subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.Token)) != 1 {
				writeError(w, "invalid dashboard token", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func checkSameOriginRequest(r *http.Request) error {
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !strings.EqualFold(u.Host, r.Host) {
			return errors.New("cross-origin request rejected")
		}
	}
	if sfs := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); sfs != "" && sfs != "same-origin" && sfs != "none" {
		if r.Method != http.MethodGet && r.Method != http.MethodHead || strings.HasPrefix(r.URL.Path, "/api/") {
			return errors.New("cross-site request rejected")
		}
	}
	return nil
}

func checkJSONContentType(r *http.Request) error {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		return nil
	}
	ct := strings.TrimSpace(r.Header.Get("Content-Type"))
	if ct == "" {
		if r.URL.Path == "/api/proxy/stop" && r.ContentLength == 0 {
			return nil
		}
		return errors.New("Content-Type: application/json required")
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return errors.New("Content-Type must be application/json")
	}
	return nil
}

func validatePublicScanURL(raw string) error {
	s := strings.TrimSpace(raw)
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return errors.New("invalid base_url")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("base_url scheme must be http or https")
	}
	host := strings.ToLower(strings.Trim(u.Hostname(), "[]"))
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") ||
		host == "metadata.google.internal" {
		return errors.New("scan target host is private/local (pass --allow-private-scan to override)")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return errors.New("scan target IP is private/loopback (pass --allow-private-scan to override)")
		}
	}
	return nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func writeError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{
		"error":  msg,
		"status": code,
	})
}
