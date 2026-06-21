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

	// Monitor: forward each line immediately, inspect a copy.
	toolName := map[int]string{}
	toolBuf := map[int]*strings.Builder{}
	var textBuf strings.Builder

	onLine := func(b []byte) error { return writeAndFlush(w, flusher, b) }
	onEvent := func(ev sseEvent) error {
		ae, ok := parseAnthropic(ev)
		if !ok {
			return nil
		}
		switch ae.Type {
		case "content_block_start":
			if ae.ContentBlock.Type == "tool_use" {
				st.sawTool = true
				toolName[ae.Index] = ae.ContentBlock.Name
				toolBuf[ae.Index] = &strings.Builder{}
			}
		case "content_block_delta":
			switch ae.Delta.Type {
			case "input_json_delta":
				if b := toolBuf[ae.Index]; b != nil {
					capWrite(b, ae.Delta.PartialJSON)
				}
			case "text_delta":
				capWrite(&textBuf, ae.Delta.Text)
			}
		case "content_block_stop":
			if b := toolBuf[ae.Index]; b != nil {
				st.add(p.cfg.Engine.Inspect(b.String(), "tool_use:"+toolName[ae.Index])...)
				delete(toolBuf, ae.Index)
				delete(toolName, ae.Index)
			}
		case "error":
			st.add(p.cfg.Engine.Inspect(ev.data, "error-frame")...)
		}
		return nil
	}

	_ = readSSE(r, onLine, onEvent)
	// Inspect any tool blocks that never received content_block_stop (truncation).
	for idx, b := range toolBuf {
		st.add(p.cfg.Engine.Inspect(b.String(), "tool_use:"+toolName[idx])...)
	}
	st.add(p.cfg.Engine.Inspect(textBuf.String(), "text")...)
	st.checkAnomaly(false)
}

// streamAnthropicBlock forwards text immediately but holds back tool_use blocks
// until verified, replacing malicious or unsolicited ones with a safe note.
func (p *Proxy) streamAnthropicBlock(w http.ResponseWriter, flusher http.Flusher, r *bufio.Reader, st *streamState) {
	var textBuf strings.Builder

	buffering := false
	var bufIndex int
	var bufName string
	var bufRaw [][]byte
	var bufInput strings.Builder
	droppedTool := false

	emit := func(b []byte) error { return writeAndFlush(w, flusher, b) }

	// finalizeTool inspects the buffered tool_use block and either flushes it
	// (clean) or replaces it with a safe note (malicious / unsolicited). Used at
	// content_block_stop and again at EOF for a truncated, never-stopped block.
	finalizeTool := func() error {
		findings := p.cfg.Engine.Inspect(bufInput.String(), "tool_use:"+bufName)
		st.add(findings...)
		drop := inspect.MaxSeverity(findings) == inspect.SevHigh || !st.clientTools
		buffering = false
		if drop {
			droppedTool = true
			reason := "unsolicited tool call"
			if len(findings) > 0 {
				reason = findings[0].RuleID
			}
			return emitAnthropicNote(w, flusher, bufIndex, reason)
		}
		for _, raw := range bufRaw {
			if e := emit(raw); e != nil {
				return e
			}
		}
		return nil
	}

	onEvent := func(ev sseEvent) error {
		ae, ok := parseAnthropic(ev)
		if !ok {
			return emit(ev.raw) // unknown frame: pass through untouched
		}

		if buffering {
			bufRaw = append(bufRaw, ev.raw)
			if ae.Type == "content_block_delta" && ae.Delta.Type == "input_json_delta" {
				capWrite(&bufInput, ae.Delta.PartialJSON)
			}
			if ae.Type == "content_block_stop" && ae.Index == bufIndex {
				return finalizeTool()
			}
			return nil
		}

		switch ae.Type {
		case "content_block_start":
			if ae.ContentBlock.Type == "tool_use" {
				st.sawTool = true
				buffering = true
				bufIndex = ae.Index
				bufName = ae.ContentBlock.Name
				bufRaw = [][]byte{ev.raw}
				bufInput.Reset()
				return nil
			}
		case "content_block_delta":
			if ae.Delta.Type == "text_delta" {
				capWrite(&textBuf, ae.Delta.Text)
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
	st.add(p.cfg.Engine.Inspect(textBuf.String(), "text")...)
	st.checkAnomaly(false)
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
