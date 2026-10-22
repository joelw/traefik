package corazawaf

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
)

// blockSecretRule denies any inspected response body that contains "secret".
const blockSecretRule = `SecRule RESPONSE_BODY "@contains secret" "id:9000001,phase:4,deny,status:403,log"`

func newTestWAF(t *testing.T, next http.Handler, directives ...string) http.Handler {
	t.Helper()

	handler, err := New(context.Background(), next, dynamic.CorazaWAF{
		InspectResponseBody: true,
		Directives: append([]string{
			"SecRuleEngine On",
			"SecResponseBodyAccess On",
			"SecResponseBodyMimeType text/plain text/html application/json",
		}, directives...),
	}, "test")
	require.NoError(t, err)

	return handler
}

func TestCorazaWAF_WebSocketUpgrade(t *testing.T) {
	upgrader := websocket.Upgrader{}
	backend := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(rw, req, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		messageType, message, err := conn.ReadMessage()
		if err != nil {
			return
		}
		_ = conn.WriteMessage(messageType, message)
	}))
	t.Cleanup(backend.Close)

	backendURL, err := url.Parse(backend.URL)
	require.NoError(t, err)

	frontend := httptest.NewServer(newTestWAF(t, httputil.NewSingleHostReverseProxy(backendURL), blockSecretRule))
	t.Cleanup(frontend.Close)

	conn, res, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(frontend.URL, "http"), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	assert.Equal(t, http.StatusSwitchingProtocols, res.StatusCode)

	require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte("hello")))
	_, message, err := conn.ReadMessage()
	require.NoError(t, err)
	assert.Equal(t, "hello", string(message))
}

func TestCorazaWAF_StreamsResponseThatIsNotInspected(t *testing.T) {
	release := make(chan struct{})
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/event-stream")
		_, _ = rw.Write([]byte("data: first\n\n"))
		rw.(http.Flusher).Flush()

		// Hold the response open until the client has the first event.
		<-release
		_, _ = rw.Write([]byte("data: second\n\n"))
	})

	frontend := httptest.NewServer(newTestWAF(t, next, blockSecretRule))
	t.Cleanup(frontend.Close)
	t.Cleanup(func() { close(release) })

	res, err := http.Get(frontend.URL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = res.Body.Close() })

	lines := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(res.Body).ReadString('\n')
		lines <- line
	}()

	select {
	case line := <-lines:
		assert.Equal(t, "data: first\n", line)
	case <-time.After(5 * time.Second):
		t.Fatal("the first event was not flushed before the response completed")
	}
}

func TestCorazaWAF_BlocksInspectedResponseBody(t *testing.T) {
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/html")
		rw.Header().Set("X-Upstream", "leaked")
		_, _ = rw.Write([]byte("<p>the secret value</p>"))
	})

	rec := httptest.NewRecorder()
	newTestWAF(t, next, blockSecretRule).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Empty(t, rec.Header().Get("X-Upstream"))
	assert.NotContains(t, rec.Body.String(), "secret")
}

func TestCorazaWAF_PassesInspectedResponseBody(t *testing.T) {
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusCreated)
		_, _ = rw.Write([]byte(`{"status":`))
		_, _ = rw.Write([]byte(`"ok"}`))
	})

	rec := httptest.NewRecorder()
	newTestWAF(t, next, blockSecretRule).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
}

func TestCorazaWAF_PassesBodyAboveLimitWithProcessPartial(t *testing.T) {
	body := strings.Repeat("a", 64*1024)
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		for chunk := range 16 {
			_, _ = rw.Write([]byte(body[chunk*4096 : (chunk+1)*4096]))
		}
	})

	rec := httptest.NewRecorder()
	handler := newTestWAF(t, next, blockSecretRule,
		"SecResponseBodyLimit 1024",
		"SecResponseBodyLimitAction ProcessPartial",
	)
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, body, rec.Body.String())
}

func TestCorazaWAF_SendsStatusForEmptyResponse(t *testing.T) {
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	})

	frontend := httptest.NewServer(newTestWAF(t, next))
	t.Cleanup(frontend.Close)

	res, err := http.Get(frontend.URL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = res.Body.Close() })

	assert.Equal(t, http.StatusNoContent, res.StatusCode)
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.Empty(t, body)
}

func TestCorazaWAF_RejectsBodyAboveLimit(t *testing.T) {
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = rw.Write([]byte(strings.Repeat("a", 4096)))
	})

	rec := httptest.NewRecorder()
	handler := newTestWAF(t, next,
		"SecResponseBodyLimit 1024",
		"SecResponseBodyLimitAction Reject",
	)
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "aaaa")
}
