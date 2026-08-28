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
// time-to-first-byte starts at -1 so a fetch that never receives a response
// byte is distinguishable from one that received it instantly.
func NewTraceCollector() *TraceCollector {
	return &TraceCollector{ttfb: -1}
}

// Trace returns a ClientTrace whose hooks record connection-phase timings into
// the collector. Attach it to a request context with httptrace.WithClientTrace.
func (c *TraceCollector) Trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GetConn: func(string) {
			c.mu.Lock()
			c.ttfb = -1
			c.wroteReq = false
			c.dns = 0
			c.connect = 0
			c.tls = 0
			c.lastIdle = 0
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
		WroteRequest: func(httptrace.WroteRequestInfo) {
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
