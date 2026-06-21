package proxy

import (
	"bufio"
	"net/http"
	"strings"
)

// streamGeneric handles an SSE stream of an unrecognized protocol. We cannot
// safely rewrite a format we do not understand, so we always forward verbatim
// (Monitor-style) and inspect the concatenated data for IOC literals and
// behavioral patterns — detection still works, blocking does not apply.
func (p *Proxy) streamGeneric(w http.ResponseWriter, flusher http.Flusher, r *bufio.Reader, st *streamState) {
	var buf strings.Builder
	onLine := func(b []byte) error { return writeAndFlush(w, flusher, b) }
	onEvent := func(ev sseEvent) error {
		if ev.data != "" && ev.data != "[DONE]" {
			capWrite(&buf, ev.data+"\n")
		}
		return nil
	}
	_ = readSSE(r, onLine, onEvent)
	st.add(p.cfg.Engine.Inspect(buf.String(), "stream")...)
	// No reliable tool-call signal for unknown formats; anomaly check is skipped.
}
