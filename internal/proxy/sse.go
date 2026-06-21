package proxy

import (
	"bufio"
	"bytes"
	"io"
	"strings"
)

// sseEvent is one parsed Server-Sent-Events frame.
type sseEvent struct {
	raw   []byte // exact bytes of the frame, including the terminating blank line
	event string // value of the last "event:" field ("" if none, e.g. OpenAI)
	data  string // concatenated "data:" field value(s)
}

// readSSE parses an SSE stream frame by frame.
//
// onLine, if non-nil, is called with the raw bytes of every line the instant it
// is read — this is how Monitor mode forwards to the client with zero added
// latency (the bytes leave before inspection happens). onEvent is called once
// per complete frame and is where inspection (and, in Block mode, emission)
// occurs. If onEvent returns an error, reading stops and the error is returned.
func readSSE(r *bufio.Reader, onLine func([]byte) error, onEvent func(sseEvent) error) error {
	var raw bytes.Buffer
	var data bytes.Buffer
	var eventType string

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
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			if onLine != nil {
				if e := onLine(line); e != nil {
					return e
				}
			}
			raw.Write(line)
			trimmed := strings.TrimRight(string(line), "\r\n")
			switch {
			case trimmed == "":
				if e := flush(); e != nil {
					return e
				}
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

// writeAndFlush writes p to w and flushes; errors are swallowed (client gone).
func writeAndFlush(w io.Writer, flusher interface{ Flush() }, p []byte) error {
	if _, err := w.Write(p); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}

// maxInspectBuf bounds how much streamed text / tool-call payload we accumulate
// for inspection, so a hostile upstream cannot exhaust memory. A payload that
// matters fits well within this; the head is what carries the signal.
const maxInspectBuf = 1 << 20 // 1 MiB

// capWrite appends s to b unless b is already at the inspection cap.
func capWrite(b *strings.Builder, s string) {
	if b.Len() >= maxInspectBuf {
		return
	}
	if b.Len()+len(s) > maxInspectBuf {
		s = s[:maxInspectBuf-b.Len()]
	}
	b.WriteString(s)
}
