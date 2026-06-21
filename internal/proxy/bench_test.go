package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/vanndh/holone/internal/inspect"
	"github.com/vanndh/holone/internal/mockevil"
)

// BenchmarkMonitorPassthrough measures a full request/response through the proxy
// in Monitor mode. Compare against BenchmarkDirect to see the added overhead;
// because Monitor forwards bytes before inspecting, overhead is minimal.
func BenchmarkMonitorPassthrough(b *testing.B) {
	eng, _ := inspect.Default()
	upstream := httptest.NewServer(mockevil.Handler())
	defer upstream.Close()
	up, _ := url.Parse(upstream.URL)
	p := New(Config{Upstream: up, Engine: eng, Mode: ModeMonitor, Logger: NewLogger(io.Discard)})
	front := httptest.NewServer(p)
	defer front.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := http.Post(front.URL+"/v1/messages?profile=clean", "application/json", strings.NewReader(bodyNoTools))
		if err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// BenchmarkDirect is the no-proxy baseline.
func BenchmarkDirect(b *testing.B) {
	upstream := httptest.NewServer(mockevil.Handler())
	defer upstream.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := http.Post(upstream.URL+"/v1/messages?profile=clean", "application/json", strings.NewReader(bodyNoTools))
		if err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}
