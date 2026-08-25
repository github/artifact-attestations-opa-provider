package main

import (
	"testing"
	"time"

	"github.com/github/artifact-attestations-opa-provider/pkg/fetcher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// restoreFetcherConfig snapshots every fetcher tunable configureBundleFetcher
// mutates and restores it (plus the shared transport) after the test, so cases
// that set overrides do not leak into later tests.
func restoreFetcherConfig(t *testing.T) {
	t.Helper()

	maxAttempts := fetcher.MaxAttempts
	timeout := fetcher.Timeout
	delay := fetcher.Delay
	dial := fetcher.DialTimeoutOverride
	tlsHandshake := fetcher.TLSHandshakeTimeoutOverride
	responseHeader := fetcher.ResponseHeaderTimeoutOverride
	request := fetcher.RequestTimeoutOverride
	t.Cleanup(func() {
		fetcher.MaxAttempts = maxAttempts
		fetcher.Timeout = timeout
		fetcher.Delay = delay
		fetcher.DialTimeoutOverride = dial
		fetcher.TLSHandshakeTimeoutOverride = tlsHandshake
		fetcher.ResponseHeaderTimeoutOverride = responseHeader
		fetcher.RequestTimeoutOverride = request
		fetcher.ConfigureTransport()
	})
}

func TestConfigureBundleFetcher(t *testing.T) {
	restoreFetcherConfig(t)

	// Zero overrides: connection-phase timeouts derive from bundle-timeout and
	// the overall request wall is derived too.
	err := configureBundleFetcher(5, 750*time.Millisecond, 25*time.Millisecond, registryTimeouts{})

	require.NoError(t, err)
	assert.Equal(t, 5, fetcher.MaxAttempts)
	assert.Equal(t, 750*time.Millisecond, fetcher.Timeout)
	assert.Equal(t, 25*time.Millisecond, fetcher.Delay)
	assert.Zero(t, fetcher.DialTimeoutOverride)
	assert.Zero(t, fetcher.TLSHandshakeTimeoutOverride)
	assert.Zero(t, fetcher.ResponseHeaderTimeoutOverride)
	assert.Zero(t, fetcher.RequestTimeoutOverride)
}

func TestConfigureBundleFetcherHonorsTransportOverrides(t *testing.T) {
	restoreFetcherConfig(t)

	err := configureBundleFetcher(3, 5*time.Second, 0, registryTimeouts{
		dial:           1 * time.Second,
		tlsHandshake:   2 * time.Second,
		responseHeader: 3 * time.Second,
		request:        8 * time.Second,
	})

	require.NoError(t, err)
	assert.Equal(t, 1*time.Second, fetcher.DialTimeoutOverride)
	assert.Equal(t, 2*time.Second, fetcher.TLSHandshakeTimeoutOverride)
	assert.Equal(t, 3*time.Second, fetcher.ResponseHeaderTimeoutOverride)
	assert.Equal(t, 8*time.Second, fetcher.RequestTimeoutOverride)
}

func TestConfigureBundleFetcherAllowsOverrideAboveBudget(t *testing.T) {
	restoreFetcherConfig(t)

	// An override larger than bundle-timeout is accepted: like the derived
	// 250ms floor, an operator may keep a usable connection-setup timeout even
	// when it exceeds the per-attempt budget. Only negative values are rejected.
	err := configureBundleFetcher(3, 1*time.Second, 0, registryTimeouts{dial: 5 * time.Second})

	require.NoError(t, err)
	assert.Equal(t, 5*time.Second, fetcher.DialTimeoutOverride)
}

func TestConfigureBundleFetcherRejectsInvalidValues(t *testing.T) {
	restoreFetcherConfig(t)

	tests := []struct {
		name        string
		maxAttempts int
		timeout     time.Duration
		delay       time.Duration
		timeouts    registryTimeouts
		errorText   string
	}{
		{
			name:        "zero attempts",
			maxAttempts: 0,
			timeout:     time.Second,
			errorText:   "bundle-max-attempts must be greater than zero",
		},
		{
			name:        "zero timeout",
			maxAttempts: 1,
			timeout:     0,
			errorText:   "bundle-timeout must be greater than zero",
		},
		{
			name:        "negative timeout",
			maxAttempts: 1,
			timeout:     -time.Second,
			errorText:   "bundle-timeout must be greater than zero",
		},
		{
			name:        "negative delay",
			maxAttempts: 1,
			timeout:     time.Second,
			delay:       -time.Millisecond,
			errorText:   "bundle-delay must not be negative",
		},
		{
			name:        "negative dial timeout",
			maxAttempts: 1,
			timeout:     time.Second,
			timeouts:    registryTimeouts{dial: -time.Millisecond},
			errorText:   "registry-dial-timeout must not be negative",
		},
		{
			name:        "negative request timeout",
			maxAttempts: 1,
			timeout:     time.Second,
			timeouts:    registryTimeouts{request: -time.Millisecond},
			errorText:   "registry-request-timeout must not be negative",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fetcher.MaxAttempts = 9
			fetcher.Timeout = 9 * time.Second
			fetcher.Delay = 9 * time.Millisecond

			err := configureBundleFetcher(test.maxAttempts, test.timeout, test.delay, test.timeouts)

			require.EqualError(t, err, test.errorText)
			assert.Equal(t, 9, fetcher.MaxAttempts)
			assert.Equal(t, 9*time.Second, fetcher.Timeout)
			assert.Equal(t, 9*time.Millisecond, fetcher.Delay)
		})
	}
}
