package dashboard

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func New(cfg Config) *Server {
	if cfg.Activity == nil {
		cfg.Activity = NewActivityLog(500)
	}
	if cfg.Providers == nil {
		cfg.Providers = &ProviderStore{next: 1}
	}
	manager := NewProxyManager(cfg.Engine, cfg.ProxyLog, cfg.Activity)
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
		writeJSON(w, s.manager.Status())
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
		writeJSON(w, s.manager.Status())
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
		var req ScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.BaseURL) == "" {
			writeError(w, "base_url required", http.StatusBadRequest)
			return
		}
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
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		if !isLocalRequest(r) {
			writeError(w, "dashboard accepts localhost requests only", http.StatusForbidden)
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
