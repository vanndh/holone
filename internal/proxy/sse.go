package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"

	"github.com/vanndh/holone/internal/inspect"
)

// maxSSELine bounds how much of a single SSE line is held in memory. A hostile
// upstream can send one line without a newline for hundreds of megabytes;
// accumulating it would be an unbounded-memory DoS. Lines longer than this are
// drained in fixed-size chunks (so Monitor mode can still forward every byte)
// but never buffered for inspection.
const maxSSELine = 1 << 20 // 1 MiB

// maxSSEFrame bounds a whole SSE frame. A hostile upstream can send many lines
// just under maxSSELine without ever sending the blank separator, which would
// grow the frame buffer without bound. The frame is dropped once it would exceed
// this cap (the same fail-closed handling as an over-long line).
const maxSSEFrame = 4 << 20 // 4 MiB

// errSSELineOversized stops reading once a Block-mode stream was terminated
// fail-closed because an uninspectable line was seen.
var errSSELineOversized = errors.New("sse line oversized; stream terminated")

// oversizedSSEFinding flags a line or frame that exceeded its hard cap. Rule id
// and match are stable so repeated overflows collapse into one finding.
func oversizedSSEFinding(ruleID string, total int) inspect.Finding {
	limit, what := maxSSELine, "SSE line"
	if ruleID == inspect.RuleAnomalyOversizedSSEFrame {
		limit, what = maxSSEFrame, "SSE frame"
	}
	return inspect.Finding{
		RuleID:   ruleID,
		Category: "protocol-anomaly",
		Severity: inspect.SevHigh.String(),
		Match:    what + " exceeds " + humanBytes(int64(limit)),
		Source:   "protocol",
		Description: "The upstream sent a " + what + " larger than " + humanBytes(int64(limit)) +
			" (" + humanBytes(int64(total)) + " read). It was not inspected; treat the response as untrusted.",
	}
}

// monitorOversized records an uninspectable line or frame and keeps forwarding:
// Monitor mode never alters or drops traffic.
func (p *Proxy) monitorOversized(st *streamState) func(string, int) error {
	return func(ruleID string, total int) error {
		st.add(oversizedSSEFinding(ruleID, total))
		return nil
	}
}

// sseEvent is one parsed Server-Sent-Events frame.
type sseEvent struct {
	raw   []byte // exact bytes of the frame, including the terminating blank line
	event string // value of the last "event:" field ("" if none, e.g. OpenAI)
	data  string // concatenated "data:" field value(s)
}

// readSSE parses an SSE stream frame by frame.
//
// onLine, if non-nil, is called with the raw bytes of every line fragment the
// instant it is read — this is how Monitor mode forwards to the client with
// zero added latency (the bytes leave before inspection happens). onEvent is
// called once per complete frame and is where inspection (and, in Block mode,
// emission) occurs.
//
// A line longer than maxSSELine cannot be parsed safely: it is never buffered,
// the frame it belongs to is discarded. A frame that grows past maxSSEFrame is
// discarded the same way. onOversized is called at most once per stream (with
// the matching rule id), which is what Block mode uses to terminate the response
// fail-closed. If any callback returns an error, reading stops and the error is
// returned.
func readSSE(r *bufio.Reader, onLine func([]byte) error, onEvent func(sseEvent) error, onOversized func(ruleID string, total int) error) error {
	var raw bytes.Buffer
	var data bytes.Buffer
	var eventType string
	skipFrame := false
	oversizedReported := false

	flush := func() error {
		if raw.Len() == 0 {
			return nil
		}
		ev := sseEvent{
			raw:   append([]byte(nil), raw.Bytes()...),
			event: eventType,
			data:  data.String(),
		}
		raw.Reset()
		data.Reset()
		eventType = ""
		return onEvent(ev)
	}

	for {
		line, oversized, total, err := readSSELine(r, onLine)
		switch {
		case oversized:
			// The line is untrustworthy: drop accumulated frame state and
			// ignore the remaining lines up to its blank-line separator.
			raw.Reset()
			data.Reset()
			eventType = ""
			skipFrame = true
			if !oversizedReported && onOversized != nil {
				oversizedReported = true
				if e := onOversized(inspect.RuleAnomalyOversizedSSELine, total); e != nil {
					return e
				}
			}
		case len(line) > 0:
			trimmed := strings.TrimRight(string(line), "\r\n")
			switch {
			case skipFrame:
				if trimmed == "" {
					skipFrame = false
				}
			case trimmed == "":
				// Frame separator: the blank line is not frame content, so it
				// never counts against maxSSEFrame.
				raw.Write(line)
				if e := flush(); e != nil {
					return e
				}
			case raw.Len()+len(line) > maxSSEFrame:
				// Too many content lines without a separator: the frame is
				// uninspectable and must not be accumulated any further.
				frameLen := raw.Len() + len(line)
				raw.Reset()
				data.Reset()
				eventType = ""
				skipFrame = true
				if !oversizedReported && onOversized != nil {
					oversizedReported = true
					if e := onOversized(inspect.RuleAnomalyOversizedSSEFrame, frameLen); e != nil {
						return e
					}
				}
			default:
				raw.Write(line)
				switch {
				case strings.HasPrefix(trimmed, "data:"):
					d := strings.TrimPrefix(trimmed, "data:")
					d = strings.TrimPrefix(d, " ")
					if data.Len() > 0 {
						data.WriteByte('\n')
					}
					data.WriteString(d)
				case strings.HasPrefix(trimmed, "event:"):
					eventType = strings.TrimSpace(strings.TrimPrefix(trimmed, "event:"))
				}
			}
		}
		if err != nil {
			if ferr := flush(); ferr != nil {
				return ferr
			}
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// readSSELine reads one line, handing every fragment to onChunk as it is read
// so an oversized line is streamed rather than buffered. When the line exceeds
// maxSSELine it is still drained to its newline (or EOF), line is nil, oversized
// is true, and total reports the bytes consumed.
func readSSELine(r *bufio.Reader, onChunk func([]byte) error) (line []byte, oversized bool, total int, err error) {
	for {
		frag, e := r.ReadSlice('\n')
		if len(frag) > 0 {
			total += len(frag)
			if onChunk != nil {
				if ce := onChunk(frag); ce != nil {
					return nil, oversized, total, ce
				}
			}
			if !oversized {
				if len(line)+len(frag) > maxSSELine {
					// Too long to inspect: release the buffer and keep draining.
					oversized = true
					line = nil
				} else {
					line = append(line, frag...)
				}
			}
		}
		if e == nil {
			return line, oversized, total, nil
		}
		if e == bufio.ErrBufferFull {
			continue
		}
		return line, oversized, total, e
	}
}

// writeAndFlush writes p to w and flushes; errors are swallowed (client gone).
func writeAndFlush(w io.Writer, flusher interface{ Flush() }, p []byte) error {
	if _, err := w.Write(p); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}
