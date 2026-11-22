package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/vanndh/holone/internal/inspect"
)

// anthropicEvent is the subset of the Anthropic streaming schema we inspect.
type anthropicEvent struct {
	Type         string `json:"type"`
	Index        int    `json:"index"`
	ContentBlock struct {
		Type     string          `json:"type"`
		Name     string          `json:"name"`
		Text     string          `json:"text"`
		Thinking string          `json:"thinking"`
		Input    json.RawMessage `json:"input"`
	} `json:"content_block"`
	Delta struct {
		Type        string `json:"type"`
		Text        string `json:"text"`
		Thinking    string `json:"thinking"`
		Signature   string `json:"signature"`
		PartialJSON string `json:"partial_json"`
		StopReason  string `json:"stop_reason"`
	} `json:"delta"`
}

const maxSignatureSample = 16 << 10

// inlineToolInput returns the JSON string of an inline content_block.input if
// it carries actual arguments (not empty, null, or "{}").
func inlineToolInput(raw json.RawMessage) string {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" || s == "{}" {
		return ""
	}
	return s
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
	thinking := newStreamInspector(p.cfg.Engine, "thinking")
	var sigBuf strings.Builder

	onLine := func(b []byte) error { return writeAndFlush(w, flusher, b) }
	onEvent := func(ev sseEvent) error {
		ae, ok := parseAnthropic(ev)
		if !ok {
			return nil
		}
		switch ae.Type {
		case "content_block_start":
			switch ae.ContentBlock.Type {
			case "tool_use":
				st.checkToolCall(ae.ContentBlock.Name)
				si := newToolStreamInspector(p.cfg.Engine, "tool_use:"+ae.ContentBlock.Name, ae.ContentBlock.Name)
				if in := inlineToolInput(ae.ContentBlock.Input); in != "" {
					si.Write(in)
				}
				toolBuf[ae.Index] = si
			case "thinking":
				thinking.Write(`"thinking": "`)
				if ae.ContentBlock.Thinking != "" {
					thinking.Write(ae.ContentBlock.Thinking)
				}
			case "text":
				if ae.ContentBlock.Text != "" {
					text.Write(ae.ContentBlock.Text)
				}
			}
		case "content_block_delta":
			switch ae.Delta.Type {
			case "input_json_delta":
				if si := toolBuf[ae.Index]; si != nil {
					si.Write(ae.Delta.PartialJSON)
				}
			case "text_delta":
				text.Write(ae.Delta.Text)
			case "thinking_delta":
				if ae.Delta.Thinking != "" {
					thinking.Write(ae.Delta.Thinking)
					st.add(p.cfg.Engine.Inspect(ev.data, "thinking")...)
				}
			case "signature_delta":
				if ae.Delta.Signature != "" && sigBuf.Len() < maxSignatureSample {
					rem := maxSignatureSample - sigBuf.Len()
					if len(ae.Delta.Signature) > rem {
						sigBuf.WriteString(ae.Delta.Signature[:rem])
					} else {
						sigBuf.WriteString(ae.Delta.Signature)
					}
				}
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

	_ = readSSE(r, onLine, onEvent, p.monitorOversized(st))
	// Inspect any tool blocks that never received content_block_stop (truncation).
	for _, si := range toolBuf {
		st.add(si.Finish()...)
	}
	if sigBuf.Len() > 0 {
		st.add(p.cfg.Engine.Inspect(`"signature":"`+sigBuf.String()+`"`, "thinking-signature")...)
	}
	st.add(thinking.Finish()...)
	st.add(text.Finish()...)
}

type anthropicBlockBuf struct {
	index        int
	name         string
	raw          [][]byte
	bytes        int
	insp         *streamInspector
	inlineInsp   *streamInspector
	nameFindings []inspect.Finding
	oversized    bool
}

// streamAnthropicBlock forwards text immediately but holds back tool_use blocks
// until verified, replacing malicious, undersized, oversized or undeclared ones
// with a safe note.
func (p *Proxy) streamAnthropicBlock(w http.ResponseWriter, flusher http.Flusher, r *bufio.Reader, st *streamState) {
	text := newStreamInspector(p.cfg.Engine, "text")
	thinking := newStreamInspector(p.cfg.Engine, "thinking")
	var sigBuf strings.Builder

	active := map[int]*anthropicBlockBuf{}
	emittedTools := 0
	droppedTools := 0
	terminated := false

	emit := func(b []byte) error { return writeAndFlush(w, flusher, b) }

	// finalizeTool inspects the buffered tool_use block and either flushes it
	// (clean) or replaces it with a safe note (malicious / undeclared /
	// oversized). Used at content_block_stop and again at EOF for a truncated,
	// never-stopped block.
	finalizeTool := func(b *anthropicBlockBuf) error {
		findings := b.insp.Finish()
		if b.inlineInsp != nil {
			findings = append(findings, b.inlineInsp.Finish()...)
		}
		st.add(findings...)
		drop := inspect.MaxSeverity(findings) == inspect.SevHigh ||
			inspect.MaxSeverity(b.nameFindings) == inspect.SevHigh ||
			len(st.declaredTools) == 0 || b.oversized
		if !drop {
			emittedTools++
			for _, raw := range b.raw {
				if e := emit(raw); e != nil {
					return e
				}
			}
			return nil
		}
		droppedTools++
		reason := "unsolicited tool call"
		switch {
		case b.oversized:
			f := oversizedToolFinding(b.name)
			st.add(f)
			reason = f.RuleID
		case len(findings) > 0:
			reason = firstRuleID(findings, b.nameFindings)
		case len(b.nameFindings) > 0:
			reason = b.nameFindings[0].RuleID
		}
		return emitAnthropicNote(w, flusher, b.index, reason)
	}

	finalizeAllOpen := func() error {
		if len(active) == 0 {
			return nil
		}
		idxs := make([]int, 0, len(active))
		for idx := range active {
			idxs = append(idxs, idx)
		}
		sort.Ints(idxs)
		for _, idx := range idxs {
			b := active[idx]
			delete(active, idx)
			if err := finalizeTool(b); err != nil {
				return err
			}
		}
		return nil
	}

	onEvent := func(ev sseEvent) error {
		ae, ok := parseAnthropic(ev)
		if !ok {
			return emit(ev.raw) // unknown frame: pass through untouched
		}

		if b := active[ae.Index]; b != nil && (ae.Type == "content_block_delta" || ae.Type == "content_block_stop") {
			delta := ""
			if ae.Type == "content_block_delta" && ae.Delta.Type == "input_json_delta" {
				delta = ae.Delta.PartialJSON
			}
			if !b.oversized {
				b.bytes += len(ev.raw) + len(delta)
				if b.bytes > maxToolCallBytes {
					// Fail closed: stop retaining the call, keep consuming the
					// stream until the block closes so the client stream stays
					// well-formed, and drop it at finalize.
					b.oversized = true
					b.raw = nil
					b.bytes = 0
				} else {
					b.raw = append(b.raw, ev.raw)
					b.insp.Write(delta)
				}
			}
			if ae.Type == "content_block_stop" {
				delete(active, ae.Index)
				return finalizeTool(b)
			}
			return nil
		}

		switch ae.Type {
		case "content_block_start":
			switch ae.ContentBlock.Type {
			case "tool_use":
				b := &anthropicBlockBuf{
					index:        ae.Index,
					name:         ae.ContentBlock.Name,
					raw:          [][]byte{ev.raw},
					bytes:        len(ev.raw),
					insp:         newToolStreamInspector(p.cfg.Engine, "tool_use:"+ae.ContentBlock.Name, ae.ContentBlock.Name),
					nameFindings: st.checkToolCall(ae.ContentBlock.Name),
				}
				if in := inlineToolInput(ae.ContentBlock.Input); in != "" {
					b.inlineInsp = newToolStreamInspector(p.cfg.Engine, "tool_use:"+ae.ContentBlock.Name, ae.ContentBlock.Name)
					b.inlineInsp.Write(in)
				}
				active[ae.Index] = b
				return nil
			case "thinking":
				thinking.Write(`"thinking": "`)
				if ae.ContentBlock.Thinking != "" {
					thinking.Write(ae.ContentBlock.Thinking)
				}
			case "text":
				if ae.ContentBlock.Text != "" {
					text.Write(ae.ContentBlock.Text)
				}
			}
		case "content_block_delta":
			switch ae.Delta.Type {
			case "text_delta":
				text.Write(ae.Delta.Text)
			case "thinking_delta":
				if ae.Delta.Thinking != "" {
					thinking.Write(ae.Delta.Thinking)
					st.add(p.cfg.Engine.Inspect(ev.data, "thinking")...)
				}
			case "signature_delta":
				if ae.Delta.Signature != "" && sigBuf.Len() < maxSignatureSample {
					rem := maxSignatureSample - sigBuf.Len()
					if len(ae.Delta.Signature) > rem {
						sigBuf.WriteString(ae.Delta.Signature[:rem])
					} else {
						sigBuf.WriteString(ae.Delta.Signature)
					}
				}
			}
		case "message_delta":
			if err := finalizeAllOpen(); err != nil {
				return err
			}
			if droppedTools > 0 && emittedTools == 0 && ae.Delta.StopReason == "tool_use" {
				return emit(rewriteStopReason(ev.data))
			}
		case "message_stop":
			if err := finalizeAllOpen(); err != nil {
				return err
			}
		case "error":
			st.add(p.cfg.Engine.Inspect(ev.data, "error-frame")...)
		}
		return emit(ev.raw)
	}

	// An uninspectable line cannot be safely rewritten, so fail closed: drop the
	// buffered call, replace it with a safety note and close the turn with
	// message_stop so the client does not hang waiting for the stream to end.
	onOversized := func(ruleID string, n int) error {
		st.add(oversizedSSEFinding(ruleID, n))
		st.blocked = true
		terminated = true
		idx := 0
		if len(active) > 0 {
			for k := range active {
				idx = k
				break
			}
		}
		active = map[int]*anthropicBlockBuf{}
		if e := emitAnthropicNote(w, flusher, idx, ruleID); e != nil {
			return e
		}
		if e := emit(jsonFrame("message_stop", map[string]any{"type": "message_stop"})); e != nil {
			return e
		}
		return errSSELineOversized
	}

	_ = readSSE(r, nil, onEvent, onOversized)
	// A tool_use block left open at EOF (truncated stream) must still be
	// inspected and resolved, or it would be both undetected and silently lost.
	if !terminated {
		_ = finalizeAllOpen()
	}
	if sigBuf.Len() > 0 {
		st.add(p.cfg.Engine.Inspect(`"signature":"`+sigBuf.String()+`"`, "thinking-signature")...)
	}
	st.add(thinking.Finish()...)
	st.add(text.Finish()...)
	if droppedTools > 0 {
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
