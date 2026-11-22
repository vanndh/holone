package proxy

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// ProviderLookup resolves a provider ID from /p/<id>/... into an upstream base URL.
type ProviderLookup func(id string) (*url.URL, bool)

// Router dispatches /p/<provider-id>/... requests to the corresponding
// upstream provider while forwarding all other paths to the default Proxy.
// This lets one local listener serve multiple AI clients simultaneously.
type Router struct {
	defaultProxy *Proxy
	baseCfg      Config
	lookup       ProviderLookup

	mu      sync.Mutex
	proxies map[string]cachedUpstreamProxy
}

type cachedUpstreamProxy struct {
	target string
	proxy  *Proxy
}

// NewRouter wraps a default Proxy and an optional multi-provider lookup function.
func NewRouter(defaultProxy *Proxy, baseCfg Config, lookup ProviderLookup) *Router {
	return &Router{
		defaultProxy: defaultProxy,
		baseCfg:      baseCfg,
		lookup:       lookup,
		proxies:      make(map[string]cachedUpstreamProxy),
	}
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if rt.lookup != nil && strings.HasPrefix(r.URL.Path, "/p/") {
		rest := strings.TrimPrefix(r.URL.Path, "/p/")
		id, tail, hasSlash := strings.Cut(rest, "/")
		if id != "" {
			up, ok := rt.lookup(id)
			if !ok || up == nil {
				http.Error(w, "holone: unknown provider route "+id, http.StatusNotFound)
				return
			}
			p := rt.proxyFor(id, up)
			cloned := r.Clone(r.Context())
			if hasSlash {
				cloned.URL.Path = "/" + tail
			} else {
				cloned.URL.Path = "/"
			}
			cloned.URL.RawPath = ""
			p.ServeHTTP(w, cloned)
			return
		}
	}
	if rt.defaultProxy == nil {
		http.Error(w, "holone: no default upstream configured", http.StatusBadGateway)
		return
	}
	rt.defaultProxy.ServeHTTP(w, r)
}

func (rt *Router) proxyFor(id string, up *url.URL) *Proxy {
	target := up.String()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if existing, ok := rt.proxies[id]; ok && existing.target == target {
		return existing.proxy
	}
	cfg := rt.baseCfg
	cfg.Upstream = up
	p := New(cfg)
	rt.proxies[id] = cachedUpstreamProxy{target: target, proxy: p}
	return p
}
