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
//	response.output_item.added            item.type=="function_call" (or mcp/shell/computer/custom call)
//	response.function_call_arguments.delta  streamed argument fragment (delta)
//	response.function_call_arguments.done   final argument string
//	response.output_item.done             complete item (arguments/action/command included)
//	response.completed                    final response with the full output[]
//
// Arguments are accumulated and inspected in both delta and final events so
// a hostile server cannot send benign deltas and swap a payload into *.done.

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
	Input       string        `json:"input"`
	Text        string        `json:"text"`
	Response    struct {
		Output []responsesItem `json:"output"`
	} `json:"response"`
}

type responsesItem struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Name      string          `json:"name"`
	CallID    string          `json:"call_id"`
	Arguments string          `json:"arguments"`
	Input     json.RawMessage `json:"input"`
	Action    json.RawMessage `json:"action"`
	Command   json.RawMessage `json:"command"`
	Code      string          `json:"code"`
}

func isResponsesToolItem(t string) bool {
	switch t {
	case "function_call", "mcp_call", "local_shell_call", "shell_call",
		"computer_call", "custom_tool_call", "code_interpreter_call":
		return true
	default:
		return false
	}
}

func itemCheckName(item responsesItem) string {
	if item.Name != "" {
		return item.Name
	}
	return item.Type
}

func itemPayload(item responsesItem) string {
	if item.Arguments != "" {
		return item.Arguments
	}
	var parts []string
	for _, raw := range []json.RawMessage{item.Input, item.Action, item.Command} {
		s := strings.TrimSpace(string(raw))
		if s != "" && s != "null" && s != "{}" {
			parts = append(parts, s)
		}
	}
	if item.Code != "" {
		parts = append(parts, item.Code)
	}
	return strings.Join(parts, "\n")
}

// responsesCall tracks one streamed tool-call item.
type responsesCall struct {
	name          string
	insp          *streamInspector
	extraFindings []inspect.Finding
	raw           [][]byte // withheld frames, replayed on the clean path
	bytes         int
	gotDelta      bool
	oversized     bool
}

func newResponsesCall(eng *inspect.Engine, name string) *responsesCall {
	return &responsesCall{name: name, insp: newToolStreamInspector(eng, "tool_call:"+name, name)}
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

// responsesKey identifies the tool-call item an event belongs to. Deltas carry
// item_id, item events carry item.id; output_index is the fallback.
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

	inspectDonePayload := func(c *responsesCall, payload string) {
		if payload == "" {
			return
		}
		if !c.gotDelta {
			c.insp.Write(payload)
			return
		}
		st.add(p.cfg.Engine.InspectToolArgs(c.name, payload, "tool_call:"+c.name)...)
	}

	onLine := func(b []byte) error { return writeAndFlush(w, flusher, b) }
	onEvent := func(ev sseEvent) error {
		re, ok := parseResponses(ev)
		if !ok {
			return nil
		}
		switch re.Type {
		case "response.output_item.added":
			if isResponsesToolItem(re.Item.Type) {
				name := itemCheckName(re.Item)
				st.checkToolCall(name)
				c := newResponsesCall(p.cfg.Engine, name)
				if payload := itemPayload(re.Item); payload != "" {
					c.insp.Write(payload)
				}
				calls[responsesKey(re)] = c
			}
		case "response.function_call_arguments.delta", "response.mcp_call_arguments.delta", "response.custom_tool_call_input.delta":
			if c := calls[responsesKey(re)]; c != nil {
				c.gotDelta = true
				c.insp.Write(re.Delta)
			}
		case "response.function_call_arguments.done", "response.mcp_call_arguments.done":
			if c := calls[responsesKey(re)]; c != nil {
				inspectDonePayload(c, re.Arguments)
			}
		case "response.custom_tool_call_input.done":
			if c := calls[responsesKey(re)]; c != nil {
				inspectDonePayload(c, re.Input)
			}
		case "response.output_item.done":
			if isResponsesToolItem(re.Item.Type) {
				key := responsesKey(re)
				name := itemCheckName(re.Item)
				c := calls[key]
				if c == nil {
					st.checkToolCall(name)
					c = newResponsesCall(p.cfg.Engine, name)
					calls[key] = c
				}
				if name != "" && c.name != name {
					c.name = name
					c.insp.SetToolName(name)
					st.checkToolCall(name)
				}
				inspectDonePayload(c, itemPayload(re.Item))
				st.add(c.insp.Finish()...)
				delete(calls, key)
			}
		case "response.completed":
			for _, item := range re.Response.Output {
				if !isResponsesToolItem(item.Type) {
					continue
				}
				name := itemCheckName(item)
				payload := itemPayload(item)
				key := item.ID
				if c, ok := calls[key]; ok {
					inspectDonePayload(c, payload)
					st.add(c.insp.Finish()...)
					delete(calls, key)
					continue
				}
				// A call reported only in the final frame (or already closed
				// earlier) still has its final payload verified.
				st.checkToolCall(name)
				st.add(p.cfg.Engine.InspectToolArgs(name, payload, "tool_call:"+name)...)
			}
		case "response.output_text.delta", "response.reasoning_summary_text.delta":
			text.Write(re.Delta)
		case "response.output_text.done":
			text.Write(re.Text)
		case "error", "response.failed":
			st.add(p.cfg.Engine.Inspect(ev.data, "error-frame")...)
		}
		return nil
	}

	_ = readSSE(r, onLine, onEvent, p.monitorOversized(st))
	for _, c := range calls {
		st.add(c.insp.Finish()...)
	}
	st.add(text.Finish()...)
}

// streamResponsesBlock fails closed: a tool-call item is withheld until its
// arguments are fully inspected, and if it is malicious or undeclared the call
// is never emitted. We then emit a Responses-style `error` SSE event and stop
// forwarding, so the client fails the turn instead of executing the call.
func (p *Proxy) streamResponsesBlock(w http.ResponseWriter, flusher http.Flusher, r *bufio.Reader, st *streamState) {
	calls := map[string]*responsesCall{}
	text := newStreamInspector(p.cfg.Engine, "text")
	dropped := false
	terminated := false

	emit := func(b []byte) error { return writeAndFlush(w, flusher, b) }

	// finalizeCall inspects a withheld call and either replays its frames
	// (clean, declared) or emits a terminal error event.
	finalizeCall := func(c *responsesCall) error {
		findings := append(c.insp.Finish(), c.extraFindings...)
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
		terminated = true
		reason := "unsolicited tool call"
		switch {
		case c.oversized:
			f := oversizedToolFinding(c.name)
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

	// bufferDonePayload always verifies final arguments on *.done even when
	// streaming deltas were already seen (defeats split-view bypass).
	bufferDonePayload := func(c *responsesCall, raw []byte, payload string) {
		if !c.gotDelta {
			buffered(c, raw, payload)
			return
		}
		buffered(c, raw, "")
		if payload != "" {
			c.extraFindings = append(c.extraFindings, p.cfg.Engine.InspectToolArgs(c.name, payload, "tool_call:"+c.name)...)
		}
	}

	onEvent := func(ev sseEvent) error {
		re, ok := parseResponses(ev)
		if !ok {
			return emit(ev.raw)
		}
		switch re.Type {
		case "response.output_item.added":
			if isResponsesToolItem(re.Item.Type) {
				name := itemCheckName(re.Item)
				c := newResponsesCall(p.cfg.Engine, name)
				st.checkToolCall(name)
				buffered(c, ev.raw, itemPayload(re.Item))
				calls[responsesKey(re)] = c
				return nil // withheld until resolved
			}
		case "response.function_call_arguments.delta", "response.mcp_call_arguments.delta", "response.custom_tool_call_input.delta":
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
		case "response.function_call_arguments.done", "response.mcp_call_arguments.done":
			key := responsesKey(re)
			c := calls[key]
			if c == nil {
				c = newResponsesCall(p.cfg.Engine, "")
				st.checkToolCall("")
				calls[key] = c
			}
			bufferDonePayload(c, ev.raw, re.Arguments)
			return nil
		case "response.custom_tool_call_input.done":
			key := responsesKey(re)
			c := calls[key]
			if c == nil {
				c = newResponsesCall(p.cfg.Engine, "")
				st.checkToolCall("")
				calls[key] = c
			}
			bufferDonePayload(c, ev.raw, re.Input)
			return nil
		case "response.output_item.done":
			if isResponsesToolItem(re.Item.Type) {
				key := responsesKey(re)
				name := itemCheckName(re.Item)
				c := calls[key]
				if c == nil {
					c = newResponsesCall(p.cfg.Engine, name)
					st.checkToolCall(name)
					calls[key] = c
				}
				if name != "" && c.name != name {
					c.name = name
					c.insp.SetToolName(name)
					st.checkToolCall(c.name)
				}
				bufferDonePayload(c, ev.raw, itemPayload(re.Item))
				delete(calls, key)
				return finalizeCall(c)
			}
		case "response.completed":
			// Resolve calls reported only in the final frame (or verify final
			// output[] items against any streamed calls).
			for i, item := range re.Response.Output {
				if !isResponsesToolItem(item.Type) {
					continue
				}
				name := itemCheckName(item)
				payload := itemPayload(item)
				var c *responsesCall
				for _, key := range []string{item.ID, "#" + strconv.Itoa(i)} {
					if cc, ok := calls[key]; ok {
						c = cc
						delete(calls, key)
						break
					}
				}
				if c != nil {
					if payload != "" {
						c.extraFindings = append(c.extraFindings, p.cfg.Engine.InspectToolArgs(c.name, payload, "tool_call:"+c.name)...)
					}
					if err := finalizeCall(c); err != nil {
						return err
					}
					continue
				}
				findings := p.cfg.Engine.InspectToolArgs(name, payload, "tool_call:"+name)
				st.add(findings...)
				nameFindings := st.checkToolCall(name)
				if inspect.MaxSeverity(append(findings, nameFindings...)) == inspect.SevHigh || len(st.declaredTools) == 0 {
					dropped = true
					terminated = true
					if e := emit(responsesErrorFrame(firstRuleID(findings, nameFindings))); e != nil {
						return e
					}
					return errResponsesBlocked
				}
			}
		case "response.output_text.delta", "response.reasoning_summary_text.delta":
			text.Write(re.Delta)
		case "response.output_text.done":
			text.Write(re.Text)
		case "error", "response.failed":
			st.add(p.cfg.Engine.Inspect(ev.data, "error-frame")...)
		}
		return emit(ev.raw)
	}

	// An uninspectable line cannot be safely parsed, so fail closed: withhold
	// every pending call and terminate with the Responses error event.
	onOversized := func(ruleID string, n int) error {
		st.add(oversizedSSEFinding(ruleID, n))
		st.blocked = true
		dropped = true
		terminated = true
		calls = map[string]*responsesCall{}
		if e := emit(responsesErrorFrame(ruleID)); e != nil {
			return e
		}
		return errSSELineOversized
	}

	_ = readSSE(r, nil, onEvent, onOversized)
	// Calls left open at EOF (truncated stream) must still be resolved, unless
	// the stream was already terminated fail-closed.
	keys := make([]string, 0, len(calls))
	for k := range calls {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if !terminated {
		for _, k := range keys {
			if err := finalizeCall(calls[k]); err != nil {
				break
			}
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
	for _, fs := range lists {
		if len(fs) > 0 {
			return fs[0].RuleID
		}
	}
	return "proto-tooluse-unsolicited"
}
