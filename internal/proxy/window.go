package proxy

import "github.com/vanndh/holone/internal/inspect"

// The inspector runs over the *entire* stream, not just its head. A hostile
// provider controls how the response is framed and can therefore place its
// payload arbitrarily far into a tool-call argument; capping accumulation (the
// old 1 MiB `capWrite`) let it hide past the cap and fail open.
//
// Instead the stream is scanned in fixed-size windows that overlap: each window
// is inspected on its own, the overlap is kept and re-scanned with the next
// window, and memory stays bounded at roughly one window per inspected payload.
// The overlap must be larger than the longest rule pattern so a signature that
// straddles a window boundary is still seen in full.
const (
	inspectWindow  = 256 << 10 // 256 KiB per detection window
	inspectOverlap = 8 << 10   // 8 KiB carried into the next window
)

// streamInspector incrementally inspects an unbounded stream in overlapping
// windows. It deduplicates findings by (rule id, match) so overlapping windows
// do not report the same hit twice.
type streamInspector struct {
	eng      *inspect.Engine
	source   string
	pending  []byte
	findings []inspect.Finding
	seen     map[string]struct{}
}

func newStreamInspector(eng *inspect.Engine, source string) *streamInspector {
	return &streamInspector{eng: eng, source: source, seen: make(map[string]struct{})}
}

// Write appends streamed text and inspects every window that has filled up.
func (si *streamInspector) Write(s string) {
	if si == nil || s == "" {
		return
	}
	si.pending = append(si.pending, s...)
	for len(si.pending) >= inspectWindow {
		si.inspect(si.pending[:inspectWindow])
		// Advance past the inspected window but keep the overlap, and do not
		// drop the rest of the chunk that has not been windowed yet.
		si.pending = si.pending[inspectWindow-inspectOverlap:]
	}
	// Do not pin a large chunk's backing array for the small tail that is left.
	if cap(si.pending) > 2*inspectWindow {
		si.pending = append([]byte(nil), si.pending...)
	}
}

// Finish inspects the remaining tail and returns every finding collected for
// this stream. It is safe to call more than once; the tail is only scanned once.
func (si *streamInspector) Finish() []inspect.Finding {
	if si == nil {
		return nil
	}
	if len(si.pending) > 0 {
		si.inspect(si.pending)
		si.pending = nil
	}
	return si.findings
}

// Findings returns the findings collected so far (without scanning the tail).
func (si *streamInspector) Findings() []inspect.Finding {
	if si == nil {
		return nil
	}
	return si.findings
}

func (si *streamInspector) inspect(b []byte) {
	if len(b) == 0 {
		return
	}
	for _, f := range si.eng.Inspect(string(b), si.source) {
		key := f.RuleID + "\x00" + f.Match
		if _, ok := si.seen[key]; ok {
			continue
		}
		si.seen[key] = struct{}{}
		si.findings = append(si.findings, f)
	}
}
