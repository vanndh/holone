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
			Content   string `json:"content"`
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
	// oversized is only meaningful in Block mode, where tool-call chunks are
	// buffered; it bounds the held-back data.
	oversized := false

	accumulate := func(c openaiChunk) (hasTool bool, finish string) {
		for _, ch := range c.Choices {
			content.Write(ch.Delta.Content)
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
						toolArgs[tc.Index] = newStreamInspector(p.cfg.Engine, "tool_call:"+tc.Function.Name)
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
		_ = readSSE(r, onLine, onEvent)
		inspectTools()
		st.add(content.Finish()...)
		return
	}

	// Block: forward content immediately, hold tool-call chunks until verified.
	var bufChunks [][]byte
	var bufContent []string // assistant text carried inside each buffered chunk
	var bufBytes int
	droppedTool := false
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
		if st.sawTool && drop {
			droppedTool = true
			reason := "unsolicited tool call"
			switch {
			case oversized:
				f := oversizedToolFinding(firstToolName(toolName))
				st.add(f)
				reason = f.RuleID
			case len(findings) > 0:
				reason = findings[0].RuleID
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
			return err
		}
		for _, raw := range bufChunks {
			if e := emit(raw); e != nil {
				return e
			}
		}
		bufChunks, bufContent = nil, nil
		if finishRaw != nil {
			return emit(finishRaw)
		}
		return nil
	}

	onEvent := func(ev sseEvent) error {
		data := strings.TrimSpace(ev.data)
		if data == "[DONE]" {
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

	_ = readSSE(r, nil, onEvent)
	// Buffered tool calls with no finish chunk (EOF/disconnect) must still be
	// inspected and resolved, not silently dropped.
	if len(bufChunks) > 0 || oversized {
		_ = finalize(nil, "")
	}
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
