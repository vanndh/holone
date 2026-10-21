package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/vanndh/holone/internal/inspect"
)

// anthropicEvent is the subset of the Anthropic streaming schema we inspect.
type anthropicEvent struct {
	Type         string `json:"type"`
	Index        int    `json:"index"`
	ContentBlock struct {
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"content_block"`
	Delta struct {
		Type        string `json:"type"`
		Text        string `json:"text"`
		PartialJSON string `json:"partial_json"`
		StopReason  string `json:"stop_reason"`
	} `json:"delta"`
}

// streamAnthropic handles an Anthropic Messages SSE response.
func (p *Proxy) streamAnthropic(w http.ResponseWriter, flusher http.Flusher, r *bufio.Reader, st *streamState) {
	if p.cfg.Mode == ModeBlock {
		p.streamAnthropicBlock(w, flusher, r, st)
		return
	}

	// Monitor: forward each line immediately, inspect a copy. Inspection runs
	// over the whole stream in rolling windows, so a payload placed past the
	// old 1 MiB cap cannot slip through.
	toolBuf := map[int]*streamInspector{}
	text := newStreamInspector(p.cfg.Engine, "text")

	onLine := func(b []byte) error { return writeAndFlush(w, flusher, b) }
	onEvent := func(ev sseEvent) error {
		ae, ok := parseAnthropic(ev)
		if !ok {
			return nil
		}
		switch ae.Type {
		case "content_block_start":
			if ae.ContentBlock.Type == "tool_use" {
				st.checkToolCall(ae.ContentBlock.Name)
				toolBuf[ae.Index] = newStreamInspector(p.cfg.Engine, "tool_use:"+ae.ContentBlock.Name)
			}
		case "content_block_delta":
			switch ae.Delta.Type {
			case "input_json_delta":
				if si := toolBuf[ae.Index]; si != nil {
					si.Write(ae.Delta.PartialJSON)
				}
			case "text_delta":
				text.Write(ae.Delta.Text)
			}
		case "content_block_stop":
			if si := toolBuf[ae.Index]; si != nil {
				st.add(si.Finish()...)
				delete(toolBuf, ae.Index)
			}
		case "error":
			st.add(p.cfg.Engine.Inspect(ev.data, "error-frame")...)
		}
		return nil
	}

	_ = readSSE(r, onLine, onEvent)
	// Inspect any tool blocks that never received content_block_stop (truncation).
	for _, si := range toolBuf {
		st.add(si.Finish()...)
	}
	st.add(text.Finish()...)
}

// streamAnthropicBlock forwards text immediately but holds back tool_use blocks
// until verified, replacing malicious, undersized, oversized or undeclared ones
// with a safe note.
func (p *Proxy) streamAnthropicBlock(w http.ResponseWriter, flusher http.Flusher, r *bufio.Reader, st *streamState) {
	text := newStreamInspector(p.cfg.Engine, "text")

	buffering := false
	var bufIndex int
	var bufName string
	var bufRaw [][]byte
	var bufBytes int
	var bufInspect *streamInspector
	var nameFindings []inspect.Finding
	oversized := false
	droppedTool := false

	emit := func(b []byte) error { return writeAndFlush(w, flusher, b) }

	// finalizeTool inspects the buffered tool_use block and either flushes it
	// (clean) or replaces it with a safe note (malicious / undeclared /
	// oversized). Used at content_block_stop and again at EOF for a truncated,
	// never-stopped block.
	finalizeTool := func() error {
		findings := bufInspect.Finish()
		st.add(findings...)
		drop := inspect.MaxSeverity(findings) == inspect.SevHigh ||
			inspect.MaxSeverity(nameFindings) == inspect.SevHigh ||
			len(st.declaredTools) == 0 || oversized
		buffering = false
		if !drop {
			for _, raw := range bufRaw {
				if e := emit(raw); e != nil {
					return e
				}
			}
			return nil
		}
		droppedTool = true
		reason := "unsolicited tool call"
		switch {
		case oversized:
			f := oversizedToolFinding(bufName)
			st.add(f)
			reason = f.RuleID
		case len(findings) > 0:
			reason = findings[0].RuleID
		case len(nameFindings) > 0:
			reason = nameFindings[0].RuleID
		}
		return emitAnthropicNote(w, flusher, bufIndex, reason)
	}

	onEvent := func(ev sseEvent) error {
		ae, ok := parseAnthropic(ev)
		if !ok {
			return emit(ev.raw) // unknown frame: pass through untouched
		}

		if buffering {
			delta := ""
			if ae.Type == "content_block_delta" && ae.Delta.Type == "input_json_delta" {
				delta = ae.Delta.PartialJSON
			}
			if !oversized {
				bufBytes += len(ev.raw) + len(delta)
				if bufBytes > maxToolCallBytes {
					// Fail closed: stop retaining the call, keep consuming the
					// stream until the block closes so the client stream stays
					// well-formed, and drop it at finalize.
					oversized = true
					bufRaw = nil
					bufBytes = 0
				} else {
					bufRaw = append(bufRaw, ev.raw)
					bufInspect.Write(delta)
				}
			}
			if ae.Type == "content_block_stop" && ae.Index == bufIndex {
				return finalizeTool()
			}
			return nil
		}

		switch ae.Type {
		case "content_block_start":
			if ae.ContentBlock.Type == "tool_use" {
				buffering = true
				bufIndex = ae.Index
				bufName = ae.ContentBlock.Name
				bufRaw = [][]byte{ev.raw}
				bufBytes = len(ev.raw)
				bufInspect = newStreamInspector(p.cfg.Engine, "tool_use:"+bufName)
				nameFindings = st.checkToolCall(bufName)
				oversized = false
				return nil
			}
		case "content_block_delta":
			if ae.Delta.Type == "text_delta" {
				text.Write(ae.Delta.Text)
			}
		case "message_delta":
			if droppedTool && ae.Delta.StopReason == "tool_use" {
				return emit(rewriteStopReason(ev.data))
			}
		case "error":
			st.add(p.cfg.Engine.Inspect(ev.data, "error-frame")...)
		}
		return emit(ev.raw)
	}

	_ = readSSE(r, nil, onEvent)
	// A tool_use block left open at EOF (truncated stream) must still be
	// inspected and resolved, or it would be both undetected and silently lost.
	if buffering {
		_ = finalizeTool()
	}
	st.add(text.Finish()...)
	if droppedTool {
		st.blocked = true
	}
}

func parseAnthropic(ev sseEvent) (anthropicEvent, bool) {
	if ev.data == "" {
		return anthropicEvent{}, false
	}
	var ae anthropicEvent
	if err := json.Unmarshal([]byte(ev.data), &ae); err != nil {
		return anthropicEvent{}, false
	}
	return ae, true
}

// emitAnthropicNote writes a text content block (replacing a blocked tool_use)
// at the given index so the client's content array stays contiguous.
func emitAnthropicNote(w http.ResponseWriter, flusher http.Flusher, index int, reason string) error {
	note := fmt.Sprintf("[holone blocked a suspicious tool call: %s]", reason)
	frames := [][]byte{
		jsonFrame("content_block_start", map[string]any{
			"type": "content_block_start", "index": index,
			"content_block": map[string]any{"type": "text", "text": ""},
		}),
		jsonFrame("content_block_delta", map[string]any{
			"type": "content_block_delta", "index": index,
			"delta": map[string]any{"type": "text_delta", "text": note},
		}),
		jsonFrame("content_block_stop", map[string]any{
			"type": "content_block_stop", "index": index,
		}),
	}
	for _, f := range frames {
		if e := writeAndFlush(w, flusher, f); e != nil {
			return e
		}
	}
	return nil
}

// rewriteStopReason rebuilds a message_delta frame with stop_reason=end_turn.
func rewriteStopReason(data string) []byte {
	var m map[string]any
	if err := json.Unmarshal([]byte(data), &m); err != nil {
		return jsonFrame("message_delta", map[string]any{
			"type":  "message_delta",
			"delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil},
		})
	}
	if delta, ok := m["delta"].(map[string]any); ok {
		delta["stop_reason"] = "end_turn"
	}
	return jsonFrame("message_delta", m)
}

// jsonFrame builds an SSE frame "event: <event>\ndata: <json>\n\n".
func jsonFrame(event string, v any) []byte {
	b, _ := json.Marshal(v)
	var sb strings.Builder
	if event != "" {
		sb.WriteString("event: ")
		sb.WriteString(event)
		sb.WriteByte('\n')
	}
	sb.WriteString("data: ")
	sb.Write(b)
	sb.WriteString("\n\n")
	return []byte(sb.String())
}
