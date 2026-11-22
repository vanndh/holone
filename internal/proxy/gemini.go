package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/vanndh/holone/internal/inspect"
)

type geminiFunctionCall struct {
	Name string          `json:"name"`
	Args json.RawMessage `json:"args"`
}

type geminiPart struct {
	Text              string              `json:"text"`
	Thought           bool                `json:"thought,omitempty"`
	FunctionCall      *geminiFunctionCall `json:"functionCall"`
	FunctionCallSnake *geminiFunctionCall `json:"function_call"`
}

func (p geminiPart) funcCall() *geminiFunctionCall {
	if p.FunctionCall != nil {
		return p.FunctionCall
	}
	return p.FunctionCallSnake
}

type geminiStreamChunk struct {
	Candidates []struct {
		Content struct {
			Role  string       `json:"role"`
			Parts []geminiPart `json:"parts"`
		} `json:"content"`
		FinishReason string `json:"finishReason"`
	} `json:"candidates"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// streamGemini handles a Google Gemini :streamGenerateContent SSE response.
func (p *Proxy) streamGemini(w http.ResponseWriter, flusher http.Flusher, r *bufio.Reader, st *streamState) {
	textInsp := newStreamInspector(p.cfg.Engine, "text")
	thoughtInsp := newStreamInspector(p.cfg.Engine, "thinking")

	if p.cfg.Mode != ModeBlock {
		onLine := func(b []byte) error { return writeAndFlush(w, flusher, b) }
		onEvent := func(ev sseEvent) error {
			data := strings.TrimSpace(ev.data)
			if data == "" || data == "[DONE]" {
				return nil
			}
			var gc geminiStreamChunk
			if json.Unmarshal([]byte(data), &gc) != nil || len(gc.Candidates) == 0 {
				st.add(p.cfg.Engine.Inspect(data, "error-frame")...)
				return nil
			}
			for _, cand := range gc.Candidates {
				for _, part := range cand.Content.Parts {
					if part.Text != "" {
						if part.Thought {
							thoughtInsp.Write(part.Text)
						} else {
							textInsp.Write(part.Text)
						}
					}
					if fc := part.funcCall(); fc != nil {
						st.checkToolCall(fc.Name)
						st.add(p.cfg.Engine.InspectToolArgs(fc.Name, string(fc.Args), "functionCall:"+fc.Name)...)
					}
				}
			}
			return nil
		}
		_ = readSSE(r, onLine, onEvent, p.monitorOversized(st))
		st.add(thoughtInsp.Finish()...)
		st.add(textInsp.Finish()...)
		return
	}

	emit := func(b []byte) error { return writeAndFlush(w, flusher, b) }

	onEvent := func(ev sseEvent) error {
		data := strings.TrimSpace(ev.data)
		if data == "" || data == "[DONE]" {
			return emit(ev.raw)
		}
		var gc geminiStreamChunk
		if json.Unmarshal([]byte(data), &gc) != nil || len(gc.Candidates) == 0 {
			st.add(p.cfg.Engine.Inspect(data, "error-frame")...)
			return emit(ev.raw)
		}

		frameBlocked := false
		var blockReason string
		var safeTexts []string

		for _, cand := range gc.Candidates {
			for _, part := range cand.Content.Parts {
				if part.Text != "" {
					if part.Thought {
						thoughtInsp.Write(part.Text)
					} else {
						textInsp.Write(part.Text)
					}
					safeTexts = append(safeTexts, part.Text)
				}
				if fc := part.funcCall(); fc != nil {
					nf := st.checkToolCall(fc.Name)
					af := p.cfg.Engine.InspectToolArgs(fc.Name, string(fc.Args), "functionCall:"+fc.Name)
					st.add(af...)
					all := append(append([]inspect.Finding(nil), nf...), af...)
					if inspect.MaxSeverity(all) == inspect.SevHigh || len(st.declaredTools) == 0 {
						frameBlocked = true
						if blockReason == "" {
							blockReason = firstRuleID(af, nf)
						}
					}
				}
			}
		}

		if !frameBlocked {
			return emit(ev.raw)
		}

		st.blocked = true
		parts := make([]map[string]any, 0, len(safeTexts)+1)
		for _, txt := range safeTexts {
			if txt != "" {
				parts = append(parts, map[string]any{"text": txt})
			}
		}
		parts = append(parts, map[string]any{
			"text": fmt.Sprintf("[holone blocked a suspicious tool call: %s]", blockReason),
		})
		return emit(dataFrame(map[string]any{
			"candidates": []any{
				map[string]any{
					"content": map[string]any{
						"role":  "model",
						"parts": parts,
					},
					"finishReason": "STOP",
				},
			},
		}))
	}

	onOversized := func(ruleID string, n int) error {
		st.add(oversizedSSEFinding(ruleID, n))
		st.blocked = true
		if e := emit(geminiBlockedFrame(ruleID)); e != nil {
			return e
		}
		return errSSELineOversized
	}

	_ = readSSE(r, nil, onEvent, onOversized)
	st.add(thoughtInsp.Finish()...)
	st.add(textInsp.Finish()...)
}

func geminiBlockedFrame(reason string) []byte {
	return dataFrame(map[string]any{
		"candidates": []any{
			map[string]any{
				"content": map[string]any{
					"role":  "model",
					"parts": []any{map[string]any{"text": fmt.Sprintf("[holone blocked a suspicious tool call: %s]", reason)}},
				},
				"finishReason": "STOP",
			},
		},
	})
}
