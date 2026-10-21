package proxy

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/vanndh/holone/internal/inspect"
	"github.com/vanndh/holone/internal/mockevil"
)

// benchEngine constructs the embedded rule set or fails the benchmark.
func benchEngine(b *testing.B) *inspect.Engine {
	b.Helper()
	eng, err := inspect.Default()
	if err != nil {
		b.Fatalf("inspect.Default(): %v", err)
	}
	return eng
}

// --- streamInspector -------------------------------------------------------

func benchStreamInspectorWrite(b *testing.B, input string) {
	eng := benchEngine(b)
	b.SetBytes(int64(len(input)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		si := newStreamInspector(eng, "bench")
		si.Write(input)
		_ = si.Finish()
	}
}

func BenchmarkStreamInspectorWrite1MiB(b *testing.B) {
	benchStreamInspectorWrite(b, repeatedProse(1<<20))
}

func BenchmarkStreamInspectorWrite10MiB(b *testing.B) {
	benchStreamInspectorWrite(b, repeatedProse(10<<20))
}

func repeatedProse(n int) string {
	const para = "The quick brown fox jumps over the lazy dog. Nothing in this paragraph looks like a command or a secret. "
	return strings.Repeat(para, n/len(para)+1)[:n]
}

// --- readSSE ---------------------------------------------------------------

func benchReadSSE(b *testing.B, input []byte) {
	var lines, events, oversized int64
	onLine := func([]byte) error { lines++; return nil }
	onEvent := func(sseEvent) error { events++; return nil }
	onOversized := func(string, int) error { oversized++; return nil }

	b.SetBytes(int64(len(input)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		r := bufio.NewReaderSize(bytes.NewReader(input), 64<<10)
		if err := readSSE(r, onLine, onEvent, onOversized); err != nil {
			b.Fatalf("readSSE: %v", err)
		}
	}
}

// sse1MiB returns ~1 MiB of ordinary multi-frame SSE with ~1 KiB frames.
func sse1MiB() []byte {
	var sb strings.Builder
	sb.Grow(1<<20 + 4096)
	const head = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\""
	text := strings.Repeat("a", 900)
	for sb.Len() < 1<<20 {
		sb.WriteString(head)
		sb.WriteString(text)
		sb.WriteString("\"}}\n\n")
	}
	return []byte(sb.String())
}

// sseTinyFrames returns 1000 minimal frames.
func sseTinyFrames() []byte {
	return []byte(strings.Repeat("data: {\"x\":1}\n\n", 1000))
}

// sseOneLargeFrame returns a single frame whose data line is just under the
// 1 MiB per-line cap.
func sseOneLargeFrame() []byte {
	var sb strings.Builder
	sb.Grow(900<<10 + 16)
	sb.WriteString("data: ")
	sb.WriteString(strings.Repeat("a", 900<<10))
	sb.WriteString("\n\n")
	return []byte(sb.String())
}

func BenchmarkReadSSE1MiB(b *testing.B)           { benchReadSSE(b, sse1MiB()) }
func BenchmarkReadSSE1000TinyFrames(b *testing.B) { benchReadSSE(b, sseTinyFrames()) }
func BenchmarkReadSSEOne900KiBFrame(b *testing.B) { benchReadSSE(b, sseOneLargeFrame()) }

// --- end-to-end proxy ------------------------------------------------------

func benchProxy(b *testing.B, mode Mode, profile string, wantBlocked bool) {
	eng := benchEngine(b)
	upstream := httptest.NewServer(mockevil.Handler())
	b.Cleanup(upstream.Close)
	up, err := url.Parse(upstream.URL)
	if err != nil {
		b.Fatal(err)
	}
	p := New(Config{Upstream: up, Engine: eng, Mode: mode, Logger: NewLogger(io.Discard)})
	front := httptest.NewServer(p)
	b.Cleanup(front.Close)
	target := front.URL + "/v1/messages?profile=" + profile

	post := func() (string, error) {
		resp, err := http.Post(target, "application/json", strings.NewReader(bodyNoTools))
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		return string(body), err
	}

	// One untimed request validates the benchmark is exercising what it claims.
	out, err := post()
	if err != nil {
		b.Fatalf("warm-up request: %v", err)
	}
	if wantBlocked {
		if !strings.Contains(out, "holone blocked") {
			b.Fatalf("block mode did not block the malicious stream:\n%s", out)
		}
	} else if !strings.Contains(out, "Here is the solution") {
		b.Fatalf("clean stream was not forwarded:\n%s", out)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		resp, err := http.Post(target, "application/json", strings.NewReader(bodyNoTools))
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
	}
}

func BenchmarkProxyMonitorCleanSSE(b *testing.B) {
	benchProxy(b, ModeMonitor, "clean", false)
}

func BenchmarkProxyBlockCleanSSE(b *testing.B) {
	benchProxy(b, ModeBlock, "clean", false)
}

func BenchmarkProxyBlockMaliciousSSE(b *testing.B) {
	benchProxy(b, ModeBlock, "evil", true)
}
