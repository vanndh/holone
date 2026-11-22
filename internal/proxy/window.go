package proxy

import (
	"strings"

	"github.com/vanndh/holone/internal/inspect"
)

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
	inspectWindow   = 256 << 10 // 256 KiB per detection window
	inspectOverlap  = 8 << 10   // 8 KiB carried into the next window
	maxToolRawBytes = 256 << 10 // 256 KiB bounded JSON accumulation for structured tool-arg checks
)

// streamInspector incrementally inspects an unbounded stream in overlapping
// windows. It deduplicates findings by (rule id, match) so overlapping windows
// do not report the same hit twice.
type streamInspector struct {
	eng      *inspect.Engine
	source   string
	toolName string
	isTool   bool
	toolRaw  []byte
	pending  []byte
	findings []inspect.Finding
	seen     map[string]struct{}
}

func newStreamInspector(eng *inspect.Engine, source string) *streamInspector {
	return &streamInspector{eng: eng, source: source, seen: make(map[string]struct{})}
}

func newToolStreamInspector(eng *inspect.Engine, source, toolName string) *streamInspector {
	return &streamInspector{
		eng:      eng,
		source:   source,
		toolName: toolName,
		isTool:   true,
		seen:     make(map[string]struct{}),
	}
}

// SetToolName updates the associated tool name (for protocols where the name
// arrives in a chunk after argument accumulation began).
func (si *streamInspector) SetToolName(name string) {
	if si == nil || name == "" {
		return
	}
	si.toolName = name
	if strings.HasSuffix(si.source, ":") {
		si.source += name
	}
}

// Write appends streamed text and inspects every window that has filled up.
func (si *streamInspector) Write(s string) {
	if si == nil || s == "" {
		return
	}
	if si.isTool && len(si.toolRaw) < maxToolRawBytes {
		rem := maxToolRawBytes - len(si.toolRaw)
		if len(s) > rem {
			si.toolRaw = append(si.toolRaw, s[:rem]...)
		} else {
			si.toolRaw = append(si.toolRaw, s...)
		}
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
	if si.isTool && len(si.toolRaw) > 0 {
		si.addFindings(si.eng.InspectToolArgs(si.toolName, string(si.toolRaw), si.source))
		si.toolRaw = nil
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
	s := string(b)
	si.addFindings(si.eng.Inspect(s, si.source))
	if strings.ContainsRune(s, '\\') {
		if unescaped := inspect.UnescapeJSONEscapes(s); unescaped != s {
			si.addFindings(si.eng.Inspect(unescaped, si.source))
		}
	}
}

func (si *streamInspector) addFindings(fs []inspect.Finding) {
	for _, f := range fs {
		key := f.RuleID + "\x00" + f.Match
		if _, ok := si.seen[key]; ok {
			continue
		}
		si.seen[key] = struct{}{}
		si.findings = append(si.findings, f)
	}
}
