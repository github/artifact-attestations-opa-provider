package fetcher

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errBrokenPipe is a stand-in for a request-write failure surfaced through
// httptrace.WroteRequestInfo.Err.
var errBrokenPipe = errors.New("broken pipe")

// fieldMap turns the flat key/value slice returned by Fields into a map so a
// test can look a field up by name.
func fieldMap(t *testing.T, kvs []any) map[string]any {
	t.Helper()
	require.Equal(t, 0, len(kvs)%2, "Fields must return an even number of elements")

	m := make(map[string]any, len(kvs)/2)
	for i := 0; i < len(kvs); i += 2 {
		key, ok := kvs[i].(string)
		require.Truef(t, ok, "field key at index %d must be a string, got %T", i, kvs[i])
		m[key] = kvs[i+1]
	}
	return m
}

// asInt extracts an int field value, failing the test if it is another type.
func asInt(t *testing.T, v any) int {
	t.Helper()
	n, ok := v.(int)
	require.Truef(t, ok, "expected int, got %T", v)
	return n
}

// asInt64 extracts an int64 field value, failing the test if it is another type.
func asInt64(t *testing.T, v any) int64 {
	t.Helper()
	n, ok := v.(int64)
	require.Truef(t, ok, "expected int64, got %T", v)
	return n
}

// TestTraceCollectorReusedConnectionNeverReturnsFirstByte drives the trace
// hooks directly for the black-hole signature: a reused, long-idle connection
// that the request is written into but from which no response byte ever
// arrives.
func TestTraceCollectorReusedConnectionNeverReturnsFirstByte(t *testing.T) {
	c := NewTraceCollector()
	tr := c.Trace()

	tr.GetConn("registry.example:443")
	tr.GotConn(httptrace.GotConnInfo{Reused: true, IdleTime: 8 * time.Second})
	tr.WroteRequest(httptrace.WroteRequestInfo{})
	// Deliberately no GotFirstResponseByte: the connection was black-holed.

	f := fieldMap(t, c.Fields())
	assert.Equal(t, 1, asInt(t, f["conns_reused"]))
	assert.Equal(t, 0, asInt(t, f["conns_new"]))
	assert.Equal(t, true, f["last_conn_reused"])
	assert.Equal(t, int64(8000), asInt64(t, f["last_conn_idle_ms"]))
	assert.Equal(t, true, f["wrote_request"])
	assert.Equal(t, int64(-1), asInt64(t, f["ttfb_ms"]))
	// A reused connection skips DNS/connect/TLS entirely, which must read as
	// "not observed" (-1) rather than a real zero-duration phase.
	assert.Equal(t, int64(-1), asInt64(t, f["dns_ms"]))
	assert.Equal(t, int64(-1), asInt64(t, f["connect_ms"]))
	assert.Equal(t, int64(-1), asInt64(t, f["tls_ms"]))
}

// TestTraceCollectorLastConnIdleMsUnobserved verifies that last_conn_idle_ms
// reports the notRecorded sentinel, not 0, whenever an idle time was never
// observed: a fresh collector that instrumented no request at all, and a
// fresh (non-reused) dial, which never assigns an idle time because that
// assignment only happens on the httptrace.GotConnInfo.Reused branch.
func TestTraceCollectorLastConnIdleMsUnobserved(t *testing.T) {
	t.Run("fresh collector, no requests", func(t *testing.T) {
		c := NewTraceCollector()

		f := fieldMap(t, c.Fields())
		assert.Equal(t, int64(-1), asInt64(t, f["last_conn_idle_ms"]))
	})

	t.Run("fresh dial", func(t *testing.T) {
		c := NewTraceCollector()
		tr := c.Trace()

		tr.GetConn("registry.example:443")
		tr.GotConn(httptrace.GotConnInfo{Reused: false})

		f := fieldMap(t, c.Fields())
		assert.Equal(t, false, f["last_conn_reused"])
		assert.Equal(t, int64(-1), asInt64(t, f["last_conn_idle_ms"]))
	})
}

// TestTraceCollectorLastConnIdleMsGenuineZero verifies that a reused
// connection with a sub-millisecond idle time reports a genuine 0, which must
// stay distinct from the -1 sentinel reported when no idle time was observed
// at all (TestTraceCollectorLastConnIdleMsUnobserved). This is the regression
// case for the fix: routing last_conn_idle_ms through the same ms() sentinel
// helper as the other phase timings must not turn this genuine 0 into -1.
func TestTraceCollectorLastConnIdleMsGenuineZero(t *testing.T) {
	c := NewTraceCollector()
	tr := c.Trace()

	tr.GetConn("registry.example:443")
	tr.GotConn(httptrace.GotConnInfo{Reused: true, IdleTime: 0})

	f := fieldMap(t, c.Fields())
	assert.Equal(t, true, f["last_conn_reused"])
	assert.Equal(t, int64(0), asInt64(t, f["last_conn_idle_ms"]))
}

// TestTraceCollectorClearsPriorConnectionOnNewRequest verifies that a request
// which fails during establishment (GetConn but no GotConn) does not inherit
// the previous request's reuse state, so the failure line cannot claim a
// connection was reused when the failing dial was fresh.
func TestTraceCollectorClearsPriorConnectionOnNewRequest(t *testing.T) {
	c := NewTraceCollector()
	tr := c.Trace()

	// First request: a reused connection that completes.
	tr.GetConn("registry.example:443")
	tr.GotConn(httptrace.GotConnInfo{Reused: true, IdleTime: 5 * time.Second})
	tr.GotFirstResponseByte()

	// Second request: acquires a connection slot but fails before GotConn
	// (for example, a fresh dial that never connects).
	tr.GetConn("registry.example:443")

	f := fieldMap(t, c.Fields())
	assert.Equal(t, false, f["last_conn_reused"],
		"stale reuse state from the prior request must be cleared at GetConn")
	assert.Equal(t, int64(-1), asInt64(t, f["last_conn_idle_ms"]),
		"stale idle time from the prior request must be cleared at GetConn, not reported as a genuine 0")
	assert.Equal(t, int64(-1), asInt64(t, f["ttfb_ms"]),
		"a request that never received a byte must not inherit the prior ttfb")
	// The fetch-level reuse count still reflects the first, completed request.
	assert.Equal(t, 1, asInt(t, f["conns_reused"]))
}

// TestTraceCollectorIgnoresFailedRequestWrite verifies that a WroteRequest hook
// carrying an error does not set wrote_request, so a write failure is not
// misreported as the black-hole signature (request written, no response).
func TestTraceCollectorIgnoresFailedRequestWrite(t *testing.T) {
	c := NewTraceCollector()
	tr := c.Trace()

	tr.GetConn("registry.example:443")
	tr.GotConn(httptrace.GotConnInfo{Reused: false})
	tr.WroteRequest(httptrace.WroteRequestInfo{Err: errBrokenPipe})

	f := fieldMap(t, c.Fields())
	assert.Equal(t, false, f["wrote_request"],
		"a failed request write must not be recorded as written")
}

// TestTraceCollectorFreshDialRecordsPhaseDurations drives the establishment
// hooks for a fresh connection and asserts the DNS, connect, and TLS phase
// durations are recorded.
func TestTraceCollectorFreshDialRecordsPhaseDurations(t *testing.T) {
	c := NewTraceCollector()
	tr := c.Trace()

	// A small sleep between each phase's start and done makes the recorded
	// duration reliably greater than a millisecond without slowing the test.
	tr.GetConn("registry.example:443")
	tr.DNSStart(httptrace.DNSStartInfo{})
	time.Sleep(2 * time.Millisecond)
	tr.DNSDone(httptrace.DNSDoneInfo{})
	tr.ConnectStart("tcp", "10.0.0.1:443")
	time.Sleep(2 * time.Millisecond)
	tr.ConnectDone("tcp", "10.0.0.1:443", nil)
	tr.TLSHandshakeStart()
	time.Sleep(2 * time.Millisecond)
	tr.TLSHandshakeDone(tls.ConnectionState{}, nil)
	tr.GotConn(httptrace.GotConnInfo{Reused: false})

	f := fieldMap(t, c.Fields())
	assert.Equal(t, 1, asInt(t, f["conns_new"]))
	assert.Equal(t, 0, asInt(t, f["conns_reused"]))
	assert.Equal(t, false, f["last_conn_reused"])
	assert.Positive(t, asInt64(t, f["dns_ms"]))
	assert.Positive(t, asInt64(t, f["connect_ms"]))
	assert.Positive(t, asInt64(t, f["tls_ms"]))
}

// TestTraceCollectorInstrumentsRealRequest confirms the ClientTrace propagates
// through a real net/http transport when attached to the request context: a
// successful HTTPS fetch on a fresh connection records the connection counts
// and a time-to-first-byte.
func TestTraceCollectorInstrumentsRealRequest(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// A brief delay before the first byte guarantees a measurable ttfb.
		time.Sleep(5 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewTraceCollector()
	ctx := httptrace.WithClientTrace(t.Context(), c.Trace())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	// The request targets the local httptest server under test, not
	// attacker-controlled input.
	// #nosec G704
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	f := fieldMap(t, c.Fields())
	assert.Equal(t, 1, asInt(t, f["conns_new"]))
	assert.Equal(t, 0, asInt(t, f["conns_reused"]))
	assert.Equal(t, false, f["last_conn_reused"])
	assert.Equal(t, int64(-1), asInt64(t, f["last_conn_idle_ms"]))
	// connect_ms and tls_ms are sub-millisecond on loopback, so only their
	// presence and non-negativity are asserted here; the synthetic fresh-dial
	// test above exercises their timing exactly.
	assert.GreaterOrEqual(t, asInt64(t, f["connect_ms"]), int64(0))
	assert.GreaterOrEqual(t, asInt64(t, f["tls_ms"]), int64(0))
	assert.Positive(t, asInt64(t, f["ttfb_ms"]))
}

// TestTraceCollectorReportsBlackHoleOnRealRequest simulates a black-holed
// connection with a handler that accepts the request but never writes a
// response. The request ages out and the collector reports the request was
// written but no first byte was received.
func TestTraceCollectorReportsBlackHoleOnRealRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// Accept the request but never respond; unblock when the client's
		// context is cancelled so the handler does not leak.
		<-r.Context().Done()
	}))
	defer srv.Close()

	c := NewTraceCollector()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	ctx = httptrace.WithClientTrace(ctx, c.Trace())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	// The request targets the local httptest server under test, not
	// attacker-controlled input.
	// #nosec G704
	resp, err := srv.Client().Do(req)
	require.Error(t, err)
	if resp != nil {
		_ = resp.Body.Close()
	}

	f := fieldMap(t, c.Fields())
	assert.Equal(t, true, f["wrote_request"])
	assert.Equal(t, int64(-1), asInt64(t, f["ttfb_ms"]))
	assert.Equal(t, int64(-1), asInt64(t, f["last_conn_idle_ms"]))
}
