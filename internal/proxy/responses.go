package proxy

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/vanndh/holone/internal/inspect"
)

// The OpenAI Responses API (/v1/responses) streams a different event schema
// than Chat Completions. Without dedicated parsing it fell into the generic
// handler, which can only observe — so Block mode silently degraded to
// monitor-only. The events that matter here are:
//
//	response.output_item.added            item.type=="function_call", item.name, item.call_id
//	response.function_call_arguments.delta  streamed argument fragment (delta)
//	response.function_call_arguments.done   final argument string
//	response.output_item.done             complete item (arguments included)
//	response.completed                    final response with the full output[]
//
// Arguments are accumulated and inspected exactly like the other protocols.

// errResponsesBlocked stops the stream after holone emitted a fail-closed
// error event for the Responses API.
var errResponsesBlocked = errors.New("responses stream blocked")

// responsesEvent is the subset of the Responses API SSE schema we inspect.
type responsesEvent struct {
	Type        string        `json:"type"`
	Item        responsesItem `json:"item"`
	ItemID      string        `json:"item_id"`
	OutputIndex int           `json:"output_index"`
	Delta       string        `json:"delta"`
	Arguments   string        `json:"arguments"`
	Response    struct {
		Output []responsesItem `json:"output"`
	} `json:"response"`
}

type responsesItem struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	CallID    string `json:"call_id"`
	Arguments string `json:"arguments"`
}

// responsesCall tracks one streamed function_call item.
type responsesCall struct {
	name      string
	insp      *streamInspector
	raw       [][]byte // withheld frames, replayed on the clean path
	bytes     int
	gotDelta  bool
	oversized bool
}

func newResponsesCall(eng *inspect.Engine, name string) *responsesCall {
	return &responsesCall{name: name, insp: newStreamInspector(eng, "tool_call:"+name)}
}

func parseResponses(ev sseEvent) (responsesEvent, bool) {
	data := strings.TrimSpace(ev.data)
	if data == "" || data == "[DONE]" {
		return responsesEvent{}, false
	}
	var re responsesEvent
	if err := json.Unmarshal([]byte(data), &re); err != nil || re.Type == "" {
		return responsesEvent{}, false
	}
	return re, true
}

// responsesKey identifies the function_call item an event belongs to. Deltas
// carry item_id, item events carry item.id; output_index is the fallback.
func responsesKey(re responsesEvent) string {
	if re.Item.ID != "" {
		return re.Item.ID
	}
	if re.ItemID != "" {
		return re.ItemID
	}
	return "#" + strconv.Itoa(re.OutputIndex)
}

// streamResponses handles an OpenAI Responses API SSE response.
func (p *Proxy) streamResponses(w http.ResponseWriter, flusher http.Flusher, r *bufio.Reader, st *streamState) {
	if p.cfg.Mode == ModeBlock {
		p.streamResponsesBlock(w, flusher, r, st)
		return
	}

	calls := map[string]*responsesCall{}
	text := newStreamInspector(p.cfg.Engine, "text")

	onLine := func(b []byte) error { return writeAndFlush(w, flusher, b) }
	onEvent := func(ev sseEvent) error {
		re, ok := parseResponses(ev)
		if !ok {
			return nil
		}
		switch re.Type {
		case "response.output_item.added":
			if re.Item.Type == "function_call" {
				st.checkToolCall(re.Item.Name)
				c := newResponsesCall(p.cfg.Engine, re.Item.Name)
				c.insp.Write(re.Item.Arguments)
				calls[responsesKey(re)] = c
			}
		case "response.function_call_arguments.delta":
			if c := calls[responsesKey(re)]; c != nil {
				c.gotDelta = true
				c.insp.Write(re.Delta)
			}
		case "response.function_call_arguments.done":
			if c := calls[responsesKey(re)]; c != nil && !c.gotDelta {
				c.insp.Write(re.Arguments)
			}
		case "response.output_item.done":
			if re.Item.Type == "function_call" {
				key := responsesKey(re)
				c := calls[key]
				if c == nil {
					st.checkToolCall(re.Item.Name)
					c = newResponsesCall(p.cfg.Engine, re.Item.Name)
					calls[key] = c
				}
				if !c.gotDelta && re.Item.Arguments != "" {
					c.insp.Write(re.Item.Arguments)
				}
				st.add(c.insp.Finish()...)
				delete(calls, key)
			}
		case "response.completed":
			for _, item := range re.Response.Output {
				if item.Type != "function_call" {
					continue
				}
				key := item.ID
				if c, ok := calls[key]; ok {
					st.add(c.insp.Finish()...)
					delete(calls, key)
					continue
				}
				// A call reported only in the final frame was not streamed.
				st.checkToolCall(item.Name)
				st.add(p.cfg.Engine.Inspect(item.Arguments, "tool_call:"+item.Name)...)
			}
		case "response.output_text.delta":
			text.Write(re.Delta)
		case "error", "response.failed":
			st.add(p.cfg.Engine.Inspect(ev.data, "error-frame")...)
		}
		return nil
	}

	_ = readSSE(r, onLine, onEvent)
	for _, c := range calls {
		st.add(c.insp.Finish()...)
	}
	st.add(text.Finish()...)
}

// streamResponsesBlock fails closed: a function_call item is withheld until its
// arguments are fully inspected, and if it is malicious or undeclared the call
// is never emitted. We then emit a Responses-style `error` SSE event and stop
// forwarding, so the client fails the turn instead of executing the call.
// (The Responses API reports mid-stream failures as `event: error` frames; this
// is the documented fail-closed shape rather than a risky in-place rewrite.)
func (p *Proxy) streamResponsesBlock(w http.ResponseWriter, flusher http.Flusher, r *bufio.Reader, st *streamState) {
	calls := map[string]*responsesCall{}
	text := newStreamInspector(p.cfg.Engine, "text")
	dropped := false

	emit := func(b []byte) error { return writeAndFlush(w, flusher, b) }

	// finalizeCall inspects a withheld function call and either replays its
	// frames (clean, declared) or emits a terminal error event.
	finalizeCall := func(c *responsesCall) error {
		findings := c.insp.Finish()
		st.add(findings...)
		drop := inspect.MaxSeverity(findings) == inspect.SevHigh ||
			inspect.MaxSeverity(st.findings) == inspect.SevHigh ||
			len(st.declaredTools) == 0 || c.oversized
		if !drop {
			for _, raw := range c.raw {
				if e := emit(raw); e != nil {
					return e
				}
			}
			return nil
		}
		dropped = true
		reason := "unsolicited tool call"
		switch {
		case c.oversized:
			f := oversizedToolFinding(c.name)
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
		if e := emit(responsesErrorFrame(reason)); e != nil {
			return e
		}
		return errResponsesBlocked
	}

	// buffered appends a frame (and optional argument fragment) to a call,
	// enforcing the hard tool-call size cap.
	buffered := func(c *responsesCall, raw []byte, delta string) {
		if c.oversized {
			return
		}
		c.bytes += len(raw) + len(delta)
		if c.bytes > maxToolCallBytes {
			c.oversized = true
			c.raw = nil
			c.bytes = 0
			return
		}
		c.raw = append(c.raw, raw)
		c.insp.Write(delta)
	}

	onEvent := func(ev sseEvent) error {
		re, ok := parseResponses(ev)
		if !ok {
			return emit(ev.raw)
		}
		switch re.Type {
		case "response.output_item.added":
			if re.Item.Type == "function_call" {
				c := newResponsesCall(p.cfg.Engine, re.Item.Name)
				st.checkToolCall(re.Item.Name)
				buffered(c, ev.raw, re.Item.Arguments)
				calls[responsesKey(re)] = c
				return nil // withheld until resolved
			}
		case "response.function_call_arguments.delta":
			key := responsesKey(re)
			c := calls[key]
			if c == nil {
				// A delta with no preceding added event: still never forward
				// an uninspected call.
				c = newResponsesCall(p.cfg.Engine, "")
				st.checkToolCall("")
				calls[key] = c
			}
			c.gotDelta = true
			buffered(c, ev.raw, re.Delta)
			return nil
		case "response.function_call_arguments.done":
			key := responsesKey(re)
			c := calls[key]
			if c == nil {
				c = newResponsesCall(p.cfg.Engine, "")
				st.checkToolCall("")
				calls[key] = c
			}
			if !c.gotDelta {
				buffered(c, ev.raw, re.Arguments)
			} else {
				buffered(c, ev.raw, "")
			}
			return nil
		case "response.output_item.done":
			if re.Item.Type == "function_call" {
				key := responsesKey(re)
				c := calls[key]
				if c == nil {
					c = newResponsesCall(p.cfg.Engine, re.Item.Name)
					st.checkToolCall(re.Item.Name)
					calls[key] = c
				}
				if re.Item.Name != "" && c.name != re.Item.Name {
					c.name = re.Item.Name
					st.checkToolCall(c.name)
				}
				if !c.gotDelta && re.Item.Arguments != "" {
					buffered(c, ev.raw, re.Item.Arguments)
				} else {
					buffered(c, ev.raw, "")
				}
				delete(calls, key)
				return finalizeCall(c)
			}
		case "response.completed":
			// Resolve calls reported only in the final frame (servers that do
			// not stream per-item events). A malicious call here still fails
			// the stream closed, though earlier frames may have been forwarded.
			for i, item := range re.Response.Output {
				if item.Type != "function_call" {
					continue
				}
				// Match the streamed call by item id, falling back to the
				// output index when the server omits ids in the final frame.
				var c *responsesCall
				for _, key := range []string{item.ID, "#" + strconv.Itoa(i)} {
					if cc, ok := calls[key]; ok {
						c = cc
						delete(calls, key)
						break
					}
				}
				if c != nil {
					if err := finalizeCall(c); err != nil {
						return err
					}
					continue
				}
				findings := p.cfg.Engine.Inspect(item.Arguments, "tool_call:"+item.Name)
				st.add(findings...)
				nameFindings := st.checkToolCall(item.Name)
				if inspect.MaxSeverity(append(findings, nameFindings...)) == inspect.SevHigh || len(st.declaredTools) == 0 {
					dropped = true
					if e := emit(responsesErrorFrame(firstRuleID(findings, nameFindings))); e != nil {
						return e
					}
					return errResponsesBlocked
				}
			}
		case "response.output_text.delta":
			text.Write(re.Delta)
		case "error", "response.failed":
			st.add(p.cfg.Engine.Inspect(ev.data, "error-frame")...)
		}
		return emit(ev.raw)
	}

	_ = readSSE(r, nil, onEvent)
	// Calls left open at EOF (truncated stream) must still be resolved.
	keys := make([]string, 0, len(calls))
	for k := range calls {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := finalizeCall(calls[k]); err != nil {
			break
		}
	}
	st.add(text.Finish()...)
	if dropped {
		st.blocked = true
	}
}

// responsesErrorFrame builds the fail-closed terminal event: the Responses API
// delivers mid-stream errors as `event: error` frames.
func responsesErrorFrame(reason string) []byte {
	return jsonFrame("error", map[string]any{
		"type":    "error",
		"code":    "holone_blocked",
		"message": fmt.Sprintf("holone blocked a suspicious tool call: %s", reason),
	})
}

// firstRuleID picks a stable reason from the findings available.
func firstRuleID(lists ...[]inspect.Finding) string {
	for _, fs := range lists {
		for _, f := range fs {
			if f.Severity == inspect.SevHigh.String() {
				return f.RuleID
			}
		}
	}
	return "proto-tooluse-unsolicited"
}
