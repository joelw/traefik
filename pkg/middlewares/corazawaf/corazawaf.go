package corazawaf

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/middlewares"
)

const (
	typeName           = "CorazaWAF"
	defaultMaxBodySize = 1 << 20 // 1 MiB
)

// corazaWAF is the middleware handler.
type corazaWAF struct {
	next        http.Handler
	waf         coraza.WAF
	maxBodySize int64
	inspectResp bool
	name        string
}

// New builds a new Coraza WAF middleware.
// The WAF instance is initialised once and shared across requests; transactions are per-request.
func New(ctx context.Context, next http.Handler, config dynamic.CorazaWAF, middlewareName string) (http.Handler, error) {
	logger := middlewares.GetLogger(ctx, middlewareName, typeName)
	logger.Debug().Msg("Creating middleware")

	cfg := coraza.NewWAFConfig().
		WithRequestBodyAccess()

	if config.InspectResponseBody {
		cfg = cfg.WithResponseBodyAccess()
	}

	maxBodySize := int64(defaultMaxBodySize)
	if config.MaxBodySize > 0 {
		maxBodySize = config.MaxBodySize
	}
	cfg = cfg.WithRequestBodyLimit(int(maxBodySize)).
		WithRequestBodyInMemoryLimit(int(maxBodySize))

	for _, d := range config.Directives {
		cfg = cfg.WithDirectives(d)
	}
	if config.RulesFile != "" {
		cfg = cfg.WithDirectivesFromFile(config.RulesFile)
	}

	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		return nil, fmt.Errorf("corazawaf: failed to initialise WAF: %w", err)
	}

	return &corazaWAF{
		next:        next,
		waf:         waf,
		maxBodySize: maxBodySize,
		inspectResp: config.InspectResponseBody,
		name:        middlewareName,
	}, nil
}

func (c *corazaWAF) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	tx := c.waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		if err := tx.Close(); err != nil {
			log.Ctx(req.Context()).Warn().Err(err).Str("middleware", c.name).Msg("corazawaf: error closing transaction")
		}
	}()

	// Phase 1 — connection + URI.
	remoteAddr := req.RemoteAddr
	host, port := splitHostPort(remoteAddr)
	tx.ProcessConnection(host, port, req.Host, 0)

	proto := "HTTP/1.1"
	if req.Proto != "" {
		proto = req.Proto
	}
	tx.ProcessURI(req.URL.String(), req.Method, proto)

	// Phase 1 — request headers.
	tx.AddRequestHeader("Host", req.Host)
	for key, vals := range req.Header {
		for _, v := range vals {
			tx.AddRequestHeader(key, v)
		}
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		c.interrupt(rw, it)
		return
	}

	// Phase 2 — request body.
	if req.Body != nil && req.ContentLength != 0 {
		if req.ContentLength < 0 || req.ContentLength <= c.maxBodySize {
			// Buffer up to maxBodySize; ReadRequestBodyFrom handles the Coraza body limit.
			limited := io.LimitReader(req.Body, c.maxBodySize+1)
			buf := &bytes.Buffer{}
			n, _ := buf.ReadFrom(limited)
			// Replace the body so the upstream handler can still read it.
			req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf.Bytes()), req.Body))

			if n <= c.maxBodySize {
				if it, _, err := tx.ReadRequestBodyFrom(bytes.NewReader(buf.Bytes())); err != nil {
					log.Ctx(req.Context()).Warn().Err(err).Str("middleware", c.name).Msg("corazawaf: error writing request body")
				} else if it != nil {
					c.interrupt(rw, it)
					return
				}
			}
			// Body above threshold: skip inspection, pass through.
		}
	}

	if it, err := tx.ProcessRequestBody(); err != nil {
		log.Ctx(req.Context()).Warn().Err(err).Str("middleware", c.name).Msg("corazawaf: error processing request body")
	} else if it != nil {
		c.interrupt(rw, it)
		return
	}

	// Phase 3/4 — response (optional).
	if !c.inspectResp {
		c.next.ServeHTTP(rw, req)
		return
	}

	// Wrap the ResponseWriter to capture status + body before flushing.
	wrappedRW := newResponseCapture(rw)
	c.next.ServeHTTP(wrappedRW, req)

	// Phase 3 — response headers.
	for key, vals := range wrappedRW.Header() {
		for _, v := range vals {
			tx.AddResponseHeader(key, v)
		}
	}
	if it := tx.ProcessResponseHeaders(wrappedRW.status, proto); it != nil {
		http.Error(rw, http.StatusText(it.Status), it.Status)
		return
	}

	// Phase 4 — response body.
	if _, _, err := tx.WriteResponseBody(wrappedRW.body.Bytes()); err != nil {
		log.Ctx(req.Context()).Warn().Err(err).Str("middleware", c.name).Msg("corazawaf: error writing response body")
	}
	if it, err := tx.ProcessResponseBody(); err != nil {
		log.Ctx(req.Context()).Warn().Err(err).Str("middleware", c.name).Msg("corazawaf: error processing response body")
	} else if it != nil {
		// We already captured the response; send an error response instead.
		http.Error(rw, http.StatusText(it.Status), it.Status)
		return
	}

	// Flush the captured response.
	rw.WriteHeader(wrappedRW.status)
	_, _ = rw.Write(wrappedRW.body.Bytes())
}

func (c *corazaWAF) interrupt(rw http.ResponseWriter, it *types.Interruption) {
	status := it.Status
	if status == 0 {
		status = http.StatusForbidden
	}
	http.Error(rw, http.StatusText(status), status)
}

// splitHostPort splits "host:port" into (host, port int). Returns (addr, 0) on error.
func splitHostPort(addr string) (string, int) {
	if i := strings.LastIndex(addr, ":"); i > 0 {
		port := 0
		fmt.Sscanf(addr[i+1:], "%d", &port)
		return addr[:i], port
	}
	return addr, 0
}

// responseCapture buffers a downstream response so Coraza can inspect it.
type responseCapture struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func newResponseCapture(rw http.ResponseWriter) *responseCapture {
	return &responseCapture{ResponseWriter: rw, status: http.StatusOK}
}

func (r *responseCapture) WriteHeader(code int) {
	r.status = code
}

func (r *responseCapture) Write(b []byte) (int, error) {
	return r.body.Write(b)
}
