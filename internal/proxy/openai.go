package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/vanndh/holone/internal/inspect"
)

// openaiChunk is the subset of an OpenAI Chat Completions stream chunk we read.
type openaiChunk struct {
	Choices []struct {
		Delta struct {
			Content          string `json:"content"`
			ReasoningContent string `json:"reasoning_content"`
			Reasoning        string `json:"reasoning"`
			FunctionCall     *struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			} `json:"function_call"`
			ToolCalls []struct {
				Index    int    `json:"index"`
				ID       string `json:"id"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
}

// streamOpenAI handles an OpenAI Chat Completions SSE response.
func (p *Proxy) streamOpenAI(w http.ResponseWriter, flusher http.Flusher, r *bufio.Reader, st *streamState) {
	toolArgs := map[int]*streamInspector{}
	toolName := map[int]string{}
	content := newStreamInspector(p.cfg.Engine, "text")
	reasoning := newStreamInspector(p.cfg.Engine, "thinking")
	startedReasoning := false
	// oversized is only meaningful in Block mode, where tool-call chunks are
	// buffered; it bounds the held-back data.
	oversized := false

	feedReasoning := func(txt string) {
		if txt == "" {
			return
		}
		if !startedReasoning {
			startedReasoning = true
			reasoning.Write(`"thinking": "`)
		}
		reasoning.Write(txt)
	}

	accumulate := func(c openaiChunk) (hasTool bool, finish string) {
		for _, ch := range c.Choices {
			content.Write(ch.Delta.Content)
			feedReasoning(ch.Delta.ReasoningContent)
			feedReasoning(ch.Delta.Reasoning)

			if fc := ch.Delta.FunctionCall; fc != nil {
				hasTool = true
				const fcIdx = -1
				if fc.Name != "" {
					if _, seen := toolName[fcIdx]; !seen || toolName[fcIdx] != fc.Name {
						toolName[fcIdx] = fc.Name
						st.checkToolCall(fc.Name)
					}
				} else if toolArgs[fcIdx] == nil {
					st.checkToolCall("")
				}
				if !oversized {
					if toolArgs[fcIdx] == nil {
						toolArgs[fcIdx] = newToolStreamInspector(p.cfg.Engine, "function_call:"+fc.Name, fc.Name)
					} else if fc.Name != "" {
						toolArgs[fcIdx].SetToolName(fc.Name)
					}
					toolArgs[fcIdx].Write(fc.Arguments)
				}
			}

			for _, tc := range ch.Delta.ToolCalls {
				hasTool = true
				if tc.Function.Name != "" {
					if _, seen := toolName[tc.Index]; !seen || toolName[tc.Index] != tc.Function.Name {
						toolName[tc.Index] = tc.Function.Name
						st.checkToolCall(tc.Function.Name)
					}
				} else if toolArgs[tc.Index] == nil {
					// Tool call with no name yet: still an unsolicited call if
					// the client declared nothing.
					st.checkToolCall("")
				}
				if !oversized {
					if toolArgs[tc.Index] == nil {
						toolArgs[tc.Index] = newToolStreamInspector(p.cfg.Engine, "tool_call:"+tc.Function.Name, tc.Function.Name)
					} else if tc.Function.Name != "" {
						toolArgs[tc.Index].SetToolName(tc.Function.Name)
					}
					toolArgs[tc.Index].Write(tc.Function.Arguments)
				}
			}
			if ch.FinishReason != nil && *ch.FinishReason != "" {
				finish = *ch.FinishReason
			}
		}
		return
	}
	inspectTools := func() []inspect.Finding {
		var out []inspect.Finding
		for _, si := range toolArgs {
			out = append(out, si.Finish()...)
		}
		st.add(out...)
		return out
	}

	if p.cfg.Mode != ModeBlock {
		// Monitor: forward each line immediately, inspect a copy.
		onLine := func(b []byte) error { return writeAndFlush(w, flusher, b) }
		onEvent := func(ev sseEvent) error {
			data := strings.TrimSpace(ev.data)
			if data == "" || data == "[DONE]" {
				return nil
			}
			var c openaiChunk
			if json.Unmarshal([]byte(data), &c) != nil || len(c.Choices) == 0 {
				st.add(p.cfg.Engine.Inspect(data, "error-frame")...) // error/unknown frame
				return nil
			}
			accumulate(c)
			return nil
		}
		_ = readSSE(r, onLine, onEvent, p.monitorOversized(st))
		inspectTools()
		st.add(reasoning.Finish()...)
		st.add(content.Finish()...)
		return
	}

	// Block: forward content immediately, hold tool-call chunks until verified.
	var bufChunks [][]byte
	var bufContent []string // assistant text carried inside each buffered chunk
	var bufBytes int
	droppedTool := false
	terminated := false
	emit := func(b []byte) error { return writeAndFlush(w, flusher, b) }

	firstToolName := func(names map[int]string) string {
		for i := range len(names) {
			if n := names[i]; n != "" {
				return n
			}
		}
		for _, n := range names {
			if n != "" {
				return n
			}
		}
		return ""
	}

	// finalize resolves the buffered tool-call chunks. finishRaw (if non-nil) is
	// a finish chunk that was NOT buffered and must be emitted on the clean path;
	// finishContent is its assistant text, preserved on the drop path.
	finalize := func(finishRaw []byte, finishContent string) error {
		findings := inspectTools()
		drop := inspect.MaxSeverity(findings) == inspect.SevHigh ||
			inspect.MaxSeverity(st.findings) == inspect.SevHigh ||
			(st.sawTool && len(st.declaredTools) == 0) || oversized
		wasOversized := oversized
		oversized = false
		bufBytes = 0
		if st.sawTool && drop {
			droppedTool = true
			reason := "unsolicited tool call"
			switch {
			case wasOversized:
				f := oversizedToolFinding(firstToolName(toolName))
				st.add(f)
				reason = f.RuleID
			case len(findings) > 0:
				reason = firstRuleID(findings)
			default:
				for _, f := range st.findings {
					if f.Severity == inspect.SevHigh.String() {
						reason = f.RuleID
						break
					}
				}
			}
			// Preserve legitimate assistant text that shared a chunk with a tool call.
			for _, c := range bufContent {
				if c != "" {
					if e := emit(openaiContentChunk(c)); e != nil {
						return e
					}
				}
			}
			if finishContent != "" {
				if e := emit(openaiContentChunk(finishContent)); e != nil {
					return e
				}
			}
			if e := emit(openaiNoteChunk(reason)); e != nil {
				return e
			}
			err := emit(openaiFinishChunk("stop"))
			bufChunks, bufContent = nil, nil
			toolArgs = map[int]*streamInspector{}
			return err
		}
		for _, raw := range bufChunks {
			if e := emit(raw); e != nil {
				return e
			}
		}
		bufChunks, bufContent = nil, nil
		toolArgs = map[int]*streamInspector{}
		if finishRaw != nil {
			return emit(finishRaw)
		}
		return nil
	}

	onEvent := func(ev sseEvent) error {
		data := strings.TrimSpace(ev.data)
		if data == "[DONE]" {
			if len(bufChunks) > 0 || oversized {
				if e := finalize(nil, ""); e != nil {
					return e
				}
			}
			return emit(ev.raw)
		}
		var c openaiChunk
		if json.Unmarshal([]byte(data), &c) != nil || len(c.Choices) == 0 {
			st.add(p.cfg.Engine.Inspect(data, "error-frame")...)
			return emit(ev.raw)
		}
		hasTool, finish := accumulate(c)
		chunkText := chunkContent(c)

		if hasTool && !oversized {
			bufBytes += len(ev.raw)
			if bufBytes > maxToolCallBytes {
				// Hard cap on held-back tool-call data: drop it, flag it, and
				// let finalize replace it with the safety note.
				oversized = true
				bufChunks, bufContent = nil, nil
				bufBytes = 0
			}
		}

		if finish == "" {
			if hasTool && !oversized {
				bufChunks = append(bufChunks, ev.raw)
				bufContent = append(bufContent, chunkText)
				return nil
			}
			if oversized {
				return nil
			}
			return emit(ev.raw)
		}

		// Finish chunk: if it also carried tool-call data, include it in the buffer.
		if hasTool && !oversized {
			bufChunks = append(bufChunks, ev.raw)
			bufContent = append(bufContent, chunkText)
			return finalize(nil, "")
		}
		return finalize(ev.raw, chunkText)
	}

	// An uninspectable line cannot be safely rewritten, so fail closed: drop the
	// buffered tool call, emit a safety note plus a normal finish chunk and the
	// [DONE] sentinel so the client stream terminates cleanly.
	onOversized := func(ruleID string, n int) error {
		st.add(oversizedSSEFinding(ruleID, n))
		st.blocked = true
		terminated = true
		bufChunks, bufContent = nil, nil
		toolArgs = map[int]*streamInspector{}
		if e := emit(openaiNoteChunk(ruleID)); e != nil {
			return e
		}
		if e := emit(openaiFinishChunk("stop")); e != nil {
			return e
		}
		if e := emit([]byte("data: [DONE]\n\n")); e != nil {
			return e
		}
		return errSSELineOversized
	}

	_ = readSSE(r, nil, onEvent, onOversized)
	// Buffered tool calls with no finish chunk (EOF/disconnect) must still be
	// inspected and resolved, not silently dropped.
	if !terminated && (len(bufChunks) > 0 || oversized) {
		_ = finalize(nil, "")
	}
	st.add(reasoning.Finish()...)
	st.add(content.Finish()...)
	if droppedTool {
		st.blocked = true
	}
}

func chunkContent(c openaiChunk) string {
	var sb strings.Builder
	for _, ch := range c.Choices {
		sb.WriteString(ch.Delta.Content)
	}
	return sb.String()
}

func openaiContentChunk(content string) []byte {
	return dataFrame(map[string]any{
		"id": "holone", "object": "chat.completion.chunk",
		"choices": []any{map[string]any{
			"index": 0, "delta": map[string]any{"content": content}, "finish_reason": nil,
		}},
	})
}

func openaiNoteChunk(reason string) []byte {
	note := fmt.Sprintf("[holone blocked a suspicious tool call: %s]", reason)
	return dataFrame(map[string]any{
		"id": "holone", "object": "chat.completion.chunk",
		"choices": []any{map[string]any{
			"index": 0, "delta": map[string]any{"content": note}, "finish_reason": nil,
		}},
	})
}

func openaiFinishChunk(reason string) []byte {
	return dataFrame(map[string]any{
		"id": "holone", "object": "chat.completion.chunk",
		"choices": []any{map[string]any{
			"index": 0, "delta": map[string]any{}, "finish_reason": reason,
		}},
	})
}

func dataFrame(v any) []byte {
	b, _ := json.Marshal(v)
	return []byte("data: " + string(b) + "\n\n")
}
