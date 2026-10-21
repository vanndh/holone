package proxy

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"github.com/vanndh/holone/internal/inspect"
)

// FuzzReadSSE asserts the parser is total over arbitrary bytes and that the
// Monitor-mode contract holds: every input byte reaches onLine, an uninspectable
// line or frame is reported at most once, and the rule id is one of the two
// oversize anomalies.
func FuzzReadSSE(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("data: {\"x\":1}\n\n"))
	f.Add([]byte("event: message_stop\ndata: {}\n\n"))
	f.Add([]byte("data: one\ndata: two\n\n"))
	f.Add([]byte("data: unterminated"))
	f.Add([]byte("no separator data: x\nno separator data: y\n"))
	f.Add([]byte("\x00\xff\xfe binary \r\n\r\n"))
	// A line over the 1 MiB cap, with no newline anywhere.
	f.Add([]byte("data: " + strings.Repeat("x", 2<<20)))
	// A frame over the 4 MiB cap: five sub-cap lines without a blank separator.
	var frame strings.Builder
	for range 5 {
		frame.WriteString("data: ")
		frame.WriteString(strings.Repeat("y", 900<<10))
		frame.WriteString("\n")
	}
	f.Add([]byte(frame.String()))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8<<20 {
			t.Skip("input exceeds the 8 MiB fuzz budget")
		}

		var forwarded bytes.Buffer
		var oversized []string

		onLine := func(p []byte) error {
			forwarded.Write(p)
			return nil
		}
		onEvent := func(sseEvent) error { return nil }
		onOversized := func(ruleID string, total int) error {
			if total < 0 {
				t.Fatalf("negative oversized total %d", total)
			}
			oversized = append(oversized, ruleID)
			return nil
		}

		r := bufio.NewReaderSize(bytes.NewReader(data), 64<<10)
		if err := readSSE(r, onLine, onEvent, onOversized); err != nil {
			t.Fatalf("readSSE returned %v for %d bytes of input", err, len(data))
		}

		if got := forwarded.Bytes(); !bytes.Equal(got, data) {
			t.Fatalf("onLine fragments do not reconstruct the input: got %d bytes, want %d", len(got), len(data))
		}
		if len(oversized) > 1 {
			t.Fatalf("onOversized called %d times, want at most once: %v", len(oversized), oversized)
		}
		for _, id := range oversized {
			if id != inspect.RuleAnomalyOversizedSSELine && id != inspect.RuleAnomalyOversizedSSEFrame {
				t.Fatalf("unexpected oversize rule id %q", id)
			}
		}
	})
}

// FuzzDeclaredToolNames asserts arbitrary request bodies never panic the
// tool-name parser and never yield an empty declared name.
func FuzzDeclaredToolNames(f *testing.F) {
	f.Add([]byte(``))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"tools":[{"name":"Bash"}]}`))
	f.Add([]byte(`{"tools":[{"function":{"name":"run"}}]}`))
	f.Add([]byte(`{"functions":[{"name":"legacy"}]}`))
	f.Add([]byte(`{"tools":[{"name":""}],"functions":[{"name":""}]}`))
	f.Add([]byte(`{"tools":null,"functions":null}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip("input exceeds the 1 MiB fuzz budget")
		}
		for name := range declaredToolNames(data) {
			if name == "" {
				t.Fatalf("declaredToolNames returned an empty name: %+v", declaredToolNames(data))
			}
		}
	})
}

// FuzzResponseToolNames asserts arbitrary response bodies never panic the
// tool-name extractor and never yield an empty name.
func FuzzResponseToolNames(f *testing.F) {
	f.Add([]byte(``))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"content":[{"type":"tool_use","name":"Bash"},{"type":"text","name":"ignored"}]}`))
	f.Add([]byte(`{"choices":[{"message":{"tool_calls":[{"function":{"name":"f"}}]}}]}`))
	f.Add([]byte(`{"function_call":{"name":"f"}}`))
	f.Add([]byte(`{"output":[{"type":"function_call","name":"g"},{"type":"message","name":"x"}]}`))
	f.Add([]byte(`{"content":[{"type":"tool_use","name":""}],"output":[{"type":"function_call","name":""}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip("input exceeds the 1 MiB fuzz budget")
		}
		names := responseToolNames(data)
		for i, name := range names {
			if name == "" {
				t.Fatalf("responseToolNames[%d] is empty: %q", i, names)
			}
		}
	})
}
