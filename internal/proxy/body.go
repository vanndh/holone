package proxy

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// errBodyTooLarge is returned when a request or response body exceeds its
// configured cap. Bodies are never silently truncated: a truncated body would
// be forwarded and inspected as if it were complete.
var errBodyTooLarge = errors.New("body exceeds the configured limit")

// encodingError reports that an upstream body cannot be decoded transparently.
// In Block mode the caller fails closed; in Monitor mode it forwards the bytes
// untouched with the original Content-Encoding preserved.
type encodingError struct {
	Encoding string
	Reason   string
}

func (e *encodingError) Error() string {
	return "Content-Encoding: " + e.Encoding + ": " + e.Reason
}

// readBodyLimit reads r to EOF, up to limit bytes. Unlike io.LimitReader it
// returns errBodyTooLarge instead of silently returning a truncated body.
func readBodyLimit(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errBodyTooLarge
	}
	return b, nil
}

// humanBytes renders a byte count for operator-facing diagnostics.
func humanBytes(n int64) string {
	const mib = 1 << 20
	if n >= mib && n%mib == 0 {
		return fmt.Sprintf("%d MiB", n/mib)
	}
	return fmt.Sprintf("%d bytes", n)
}

// bodyStream is a response body prepared for inspection.
type bodyStream struct {
	r       io.Reader
	closeFn func() error
	decoded bool   // Content-Encoding was decoded; the header must be stripped
	enc     string // original Content-Encoding ("" for identity)
}

// Close releases the decoder (if any). Closing the decoder does not close the
// underlying response body.
func (b bodyStream) Close() error {
	if b.closeFn != nil {
		return b.closeFn()
	}
	return nil
}

// openResponseBody wraps resp.Body so gzip and deflate are decoded
// transparently (we ask upstream for identity, but servers may ignore that).
// Unsupported or undecodable encodings return an *encodingError. The returned
// bodyStream still lets a caller replay every raw byte, so a Monitor decision
// to forward the encoded body untouched never loses data.
func openResponseBody(resp *http.Response) (bodyStream, error) {
	enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	// Peek through a buffered reader so a failed decoder probe never consumes
	// bytes the caller may still need for byte-for-byte forwarding.
	br := bufio.NewReader(resp.Body)
	plain := bodyStream{r: br, enc: enc}

	if enc == "" || enc == "identity" {
		return plain, nil
	}
	if strings.Contains(enc, ",") {
		return plain, &encodingError{Encoding: enc, Reason: "stacked encodings are not supported"}
	}

	switch enc {
	case "gzip":
		pr := &probeReader{r: br}
		gz, err := gzip.NewReader(pr)
		pr.off = true
		if err != nil {
			return bodyStream{r: io.MultiReader(bytes.NewReader(pr.captured()), br), enc: enc},
				&encodingError{Encoding: enc, Reason: "gzip decode failed: " + err.Error()}
		}
		return bodyStream{r: gz, closeFn: gz.Close, decoded: true, enc: enc}, nil
	case "deflate":
		dec, captured, err := newDeflateReader(br)
		if err != nil {
			return bodyStream{r: io.MultiReader(bytes.NewReader(captured), br), enc: enc},
				&encodingError{Encoding: enc, Reason: "deflate decode failed: " + err.Error()}
		}
		return bodyStream{r: dec, closeFn: dec.Close, decoded: true, enc: enc}, nil
	default:
		return plain, &encodingError{Encoding: enc, Reason: "unsupported"}
	}
}

// newDeflateReader decodes an HTTP "deflate" body. RFC 7230 specifies a
// zlib-wrapped stream, but a number of servers send raw DEFLATE; both are
// accepted, sniffing the zlib header (compression method 8, checksum %31 == 0)
// before committing to a decoder. captured holds any bytes the failed zlib
// constructor consumed so the caller can replay the original body.
func newDeflateReader(br *bufio.Reader) (io.ReadCloser, []byte, error) {
	head, err := br.Peek(2)
	if err != nil {
		return nil, nil, err
	}
	if head[0]&0x0f != 8 || (uint16(head[0])<<8|uint16(head[1]))%31 != 0 {
		return flate.NewReader(br), nil, nil
	}
	pr := &probeReader{r: br}
	zr, err := zlib.NewReader(pr)
	pr.off = true
	if err != nil {
		return nil, pr.captured(), err
	}
	return zr, nil, nil
}

// probeReader records the bytes read through it while armed (off == false), so
// a decoder that fails after consuming part of the body leaves a replay buffer.
type probeReader struct {
	r   io.Reader
	buf bytes.Buffer
	off bool
}

func (p *probeReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if !p.off && n > 0 {
		p.buf.Write(b[:n])
	}
	return n, err
}

func (p *probeReader) captured() []byte {
	return append([]byte(nil), p.buf.Bytes()...)
}
