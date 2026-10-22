package corazawaf

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"

	"github.com/corazawaf/coraza/v3/types"
)

// responseInterceptor runs Coraza's response phases on a downstream response.
//
// It decides per response, once the status and headers are known, whether the
// body is held for inspection or streamed to the client:
//   - A body that Coraza inspects (response body access on and the Content-Type
//     in SecResponseBodyMimeType) is buffered by the transaction, up to
//     SecResponseBodyLimit. SecResponseBodyLimitAction then either rejects the
//     response or inspects the partial body and streams the rest.
//   - Any other body is written straight to the client, and flushes pass
//     through, so streamed responses such as server-sent events keep working.
//   - A hijacked connection (WebSocket and other protocol upgrades) is handed
//     to the caller untouched, and the response phases are skipped because
//     there is no HTTP response left to inspect.
type responseInterceptor struct {
	rw    http.ResponseWriter
	tx    types.Transaction
	proto string

	status      int
	wroteHeader bool // The downstream handler has set its final status.
	headerSent  bool // The status has been written to rw.
	buffering   bool // The body goes to the transaction buffer, not to rw.
	hijacked    bool
}

func newResponseInterceptor(rw http.ResponseWriter, tx types.Transaction, proto string) *responseInterceptor {
	return &responseInterceptor{rw: rw, tx: tx, proto: proto, status: http.StatusOK}
}

func (r *responseInterceptor) Header() http.Header {
	return r.rw.Header()
}

// WriteHeader runs phase 3 and selects between buffering and streaming.
func (r *responseInterceptor) WriteHeader(code int) {
	if r.wroteHeader || r.tx.IsInterrupted() {
		return
	}

	// Informational responses (e.g. 103 Early Hints) are not final; send them on.
	if code >= 100 && code < 200 {
		r.rw.WriteHeader(code)
		return
	}

	r.wroteHeader = true
	r.status = code

	for key, vals := range r.rw.Header() {
		for _, v := range vals {
			r.tx.AddResponseHeader(key, v)
		}
	}
	if it := r.tx.ProcessResponseHeaders(code, r.proto); it != nil {
		r.writeInterruption(it)
		return
	}

	if r.tx.IsResponseBodyAccessible() && r.tx.IsResponseBodyProcessable() {
		r.buffering = true
		return
	}
	r.sendHeader()
}

func (r *responseInterceptor) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	if r.tx.IsInterrupted() {
		// The response has been replaced by the interruption; discard the body.
		return len(b), nil
	}
	if !r.buffering {
		return r.rw.Write(b)
	}

	it, n, err := r.tx.WriteResponseBody(b)
	if it != nil {
		r.writeInterruption(it)
		return len(b), nil
	}
	if err != nil || n == len(b) {
		return n, err
	}

	// The body limit is reached and Coraza has inspected the part it holds
	// (ProcessPartial). Send that part and stream the remainder.
	if err := r.releaseBuffer(); err != nil {
		return n, err
	}
	m, err := r.rw.Write(b[n:])
	return n + m, err
}

// Flush implements http.Flusher. It does nothing while the body is held for inspection.
func (r *responseInterceptor) Flush() {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	if r.buffering || r.tx.IsInterrupted() {
		return
	}
	_ = http.NewResponseController(r.rw).Flush()
}

// Hijack implements http.Hijacker, which the proxy needs to complete a protocol upgrade.
func (r *responseInterceptor) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, brw, err := http.NewResponseController(r.rw).Hijack()
	if err != nil {
		return nil, nil, err
	}
	r.hijacked = true
	return conn, brw, nil
}

// Unwrap returns the underlying ResponseWriter, enabling http.ResponseController
// to discover the underlying writer's other capabilities (deadlines, full duplex).
func (r *responseInterceptor) Unwrap() http.ResponseWriter {
	return r.rw
}

// finish runs phase 4 on a buffered body and sends the response.
// It must be called once the downstream handler has returned.
func (r *responseInterceptor) finish() error {
	if r.hijacked || r.tx.IsInterrupted() {
		return nil
	}
	if !r.wroteHeader {
		// The downstream handler wrote nothing: phase 3 still runs for the implicit 200.
		r.WriteHeader(http.StatusOK)
		if r.tx.IsInterrupted() {
			return nil
		}
	}
	if !r.buffering {
		return nil
	}

	it, err := r.tx.ProcessResponseBody()
	if it != nil {
		r.writeInterruption(it)
		return nil
	}
	// Fail open: a processing error still releases the response.
	return errors.Join(err, r.releaseBuffer())
}

func (r *responseInterceptor) sendHeader() {
	if r.headerSent {
		return
	}
	r.headerSent = true
	r.rw.WriteHeader(r.status)
}

func (r *responseInterceptor) releaseBuffer() error {
	r.buffering = false
	r.sendHeader()

	body, err := r.tx.ResponseBodyReader()
	if err != nil {
		return err
	}
	_, err = io.Copy(r.rw, body)
	return err
}

// writeInterruption replaces the downstream response with the interruption status.
func (r *responseInterceptor) writeInterruption(it *types.Interruption) {
	r.buffering = false
	if r.headerSent {
		// The status is already on the wire; the rest of the body is discarded.
		return
	}
	r.headerSent = true

	// Drop the downstream headers so that none of them reach the client.
	header := r.rw.Header()
	for key := range header {
		header.Del(key)
	}
	writeInterruption(r.rw, it)
}
