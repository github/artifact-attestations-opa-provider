package fetcher

import (
	"crypto/tls"
	"net/http/httptrace"
	"sync"
	"time"
)

// TraceEnabled gates connection instrumentation. Set from a flag at startup
// (default true). Overhead is a few timestamp captures per request.
var TraceEnabled = true

// notRecorded is the sentinel returned for a phase timing that was never
// observed (for example, time-to-first-byte when no response byte ever
// arrived). It is negative so it is unambiguous alongside real millisecond
// durations, which are always non-negative.
const notRecorded int64 = -1

// durationUnset marks a phase timing that has not been observed. It is negative
// so Fields can distinguish an unobserved phase (for example, the
// DNS/connect/TLS phases that are skipped when a pooled connection is reused)
// from a phase that completed in under a millisecond, which rounds to zero.
const durationUnset = time.Duration(-1)

// TraceCollector accumulates HTTP connection-phase timings for one bundle
// fetch. A fetch issues several requests (and retries); the collector keeps
// per-fetch counts plus the phase timings of the most recently used
// connection, which is the one in flight when a stall trips the per-attempt
// deadline. All fields are guarded by mu because GotFirstResponseByte can fire
// from the transport's read goroutine.
type TraceCollector struct {
	mu sync.Mutex

	reusedConns int
	newConns    int

	// Most-recent-connection fields, reset per request at GetConn.
	lastReused bool
	lastIdle   time.Duration
	dns        time.Duration
	connect    time.Duration
	tls        time.Duration
	ttfb       time.Duration // GotConn to first response byte; -1 if never.
	wroteReq   bool

	// Transient phase-start timestamps.
	dnsStart  time.Time
	connStart time.Time
	tlsStart  time.Time
	gotConnAt time.Time
}

// NewTraceCollector returns a TraceCollector ready to instrument one fetch. The
// phase timings start at the unset sentinel so a phase that never runs (for
// example, time-to-first-byte on a black-holed connection, or DNS/connect/TLS
// on a reused one) is distinguishable from one that completed in under a
// millisecond.
func NewTraceCollector() *TraceCollector {
	return &TraceCollector{
		dns:     durationUnset,
		connect: durationUnset,
		tls:     durationUnset,
		ttfb:    durationUnset,
	}
}

// Trace returns a ClientTrace whose hooks record connection-phase timings into
// the collector. Attach it to a request context with httptrace.WithClientTrace.
func (c *TraceCollector) Trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GetConn: func(string) {
			c.mu.Lock()
			// Reset every per-request field so a stall in this request is never
			// described with a prior request's connection state. Unobserved
			// phases use durationUnset (not zero) so "skipped" stays distinct
			// from "completed in <1ms"; lastReused and gotConnAt are cleared so
			// a fresh dial that fails before GotConn is not reported as a reuse
			// of the previous connection.
			c.ttfb = durationUnset
			c.dns = durationUnset
			c.connect = durationUnset
			c.tls = durationUnset
			c.wroteReq = false
			c.lastReused = false
			c.lastIdle = 0
			c.gotConnAt = time.Time{}
			c.mu.Unlock()
		},
		GotConn: func(info httptrace.GotConnInfo) {
			c.mu.Lock()
			c.gotConnAt = time.Now()
			c.lastReused = info.Reused
			if info.Reused {
				c.reusedConns++
				c.lastIdle = info.IdleTime
			} else {
				c.newConns++
			}
			c.mu.Unlock()
		},
		DNSStart: func(httptrace.DNSStartInfo) {
			c.mu.Lock()
			c.dnsStart = time.Now()
			c.mu.Unlock()
		},
		DNSDone: func(httptrace.DNSDoneInfo) {
			c.mu.Lock()
			c.dns = time.Since(c.dnsStart)
			c.mu.Unlock()
		},
		// ConnectStart and ConnectDone assume a single TCP connect attempt is in
		// flight at a time. Under the platform's default dual-stack Fast
		// Fallback a host may briefly race IPv4 and IPv6 connects; if that
		// happens connect_ms reflects the most recent attempt rather than the
		// exact winning dial. The connection-reuse and time-to-first-byte
		// signals this instrumentation exists for are unaffected.
		ConnectStart: func(_, _ string) {
			c.mu.Lock()
			c.connStart = time.Now()
			c.mu.Unlock()
		},
		ConnectDone: func(_, _ string, _ error) {
			c.mu.Lock()
			c.connect = time.Since(c.connStart)
			c.mu.Unlock()
		},
		TLSHandshakeStart: func() {
			c.mu.Lock()
			c.tlsStart = time.Now()
			c.mu.Unlock()
		},
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			c.mu.Lock()
			c.tls = time.Since(c.tlsStart)
			c.mu.Unlock()
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			// WroteRequest also fires when the write itself failed, carrying the
			// error in info.Err. Recording only the success case keeps
			// wrote_request=true with ttfb_ms=-1 meaning "request written, no
			// response" (the black-hole signature) rather than a masked write
			// failure.
			if info.Err != nil {
				return
			}
			c.mu.Lock()
			c.wroteReq = true
			c.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			c.mu.Lock()
			if !c.gotConnAt.IsZero() {
				c.ttfb = time.Since(c.gotConnAt)
			}
			c.mu.Unlock()
		},
	}
}

// Fields returns structured log key/values describing where the fetch spent
// its connection time. A ttfb_ms of -1 means no response byte was ever
// received on the last connection: the request was written into a connection
// that returned nothing before the deadline.
func (c *TraceCollector) Fields() []any {
	c.mu.Lock()
	defer c.mu.Unlock()

	ms := func(d time.Duration) int64 {
		if d < 0 {
			return notRecorded
		}
		return d.Milliseconds()
	}

	return []any{
		"conns_reused", c.reusedConns,
		"conns_new", c.newConns,
		"last_conn_reused", c.lastReused,
		"last_conn_idle_ms", c.lastIdle.Milliseconds(),
		"dns_ms", ms(c.dns),
		"connect_ms", ms(c.connect),
		"tls_ms", ms(c.tls),
		"wrote_request", c.wroteReq,
		"ttfb_ms", ms(c.ttfb),
	}
}
