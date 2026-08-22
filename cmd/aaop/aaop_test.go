package main

import (
	"testing"
	"time"

	"github.com/github/artifact-attestations-opa-provider/pkg/fetcher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigureBundleFetcher(t *testing.T) {
	originalMaxAttempts := fetcher.MaxAttempts
	originalTimeout := fetcher.Timeout
	originalDelay := fetcher.Delay
	originalDial := fetcher.DialTimeoutOverride
	originalTLS := fetcher.TLSHandshakeTimeoutOverride
	originalResponseHeader := fetcher.ResponseHeaderTimeoutOverride
	t.Cleanup(func() {
		fetcher.MaxAttempts = originalMaxAttempts
		fetcher.Timeout = originalTimeout
		fetcher.Delay = originalDelay
		fetcher.DialTimeoutOverride = originalDial
		fetcher.TLSHandshakeTimeoutOverride = originalTLS
		fetcher.ResponseHeaderTimeoutOverride = originalResponseHeader
		fetcher.ConfigureTransport()
	})

	// Zero overrides: phase timeouts are derived from bundle-timeout.
	err := configureBundleFetcher(5, 750*time.Millisecond, 25*time.Millisecond, 0, 0, 0)

	require.NoError(t, err)
	assert.Equal(t, 5, fetcher.MaxAttempts)
	assert.Equal(t, 750*time.Millisecond, fetcher.Timeout)
	assert.Equal(t, 25*time.Millisecond, fetcher.Delay)
	assert.Zero(t, fetcher.DialTimeoutOverride)
	assert.Zero(t, fetcher.TLSHandshakeTimeoutOverride)
	assert.Zero(t, fetcher.ResponseHeaderTimeoutOverride)
}

func TestConfigureBundleFetcherHonorsTransportOverrides(t *testing.T) {
	originalTimeout := fetcher.Timeout
	originalDial := fetcher.DialTimeoutOverride
	originalTLS := fetcher.TLSHandshakeTimeoutOverride
	originalResponseHeader := fetcher.ResponseHeaderTimeoutOverride
	t.Cleanup(func() {
		fetcher.Timeout = originalTimeout
		fetcher.DialTimeoutOverride = originalDial
		fetcher.TLSHandshakeTimeoutOverride = originalTLS
		fetcher.ResponseHeaderTimeoutOverride = originalResponseHeader
		fetcher.ConfigureTransport()
	})

	err := configureBundleFetcher(3, 5*time.Second, 0,
		1*time.Second, 2*time.Second, 3*time.Second)

	require.NoError(t, err)
	assert.Equal(t, 1*time.Second, fetcher.DialTimeoutOverride)
	assert.Equal(t, 2*time.Second, fetcher.TLSHandshakeTimeoutOverride)
	assert.Equal(t, 3*time.Second, fetcher.ResponseHeaderTimeoutOverride)
}

func TestConfigureBundleFetcherAllowsOverrideAboveBudget(t *testing.T) {
	originalTimeout := fetcher.Timeout
	originalDial := fetcher.DialTimeoutOverride
	originalTLS := fetcher.TLSHandshakeTimeoutOverride
	originalResponseHeader := fetcher.ResponseHeaderTimeoutOverride
	t.Cleanup(func() {
		fetcher.Timeout = originalTimeout
		fetcher.DialTimeoutOverride = originalDial
		fetcher.TLSHandshakeTimeoutOverride = originalTLS
		fetcher.ResponseHeaderTimeoutOverride = originalResponseHeader
		fetcher.ConfigureTransport()
	})

	// An override larger than bundle-timeout is accepted: like the derived
	// 250ms floor, an operator may keep a usable connection-setup timeout even
	// when it exceeds the per-attempt budget. Only negative values are rejected.
	err := configureBundleFetcher(3, 1*time.Second, 0,
		5*time.Second, 0, 0)

	require.NoError(t, err)
	assert.Equal(t, 5*time.Second, fetcher.DialTimeoutOverride)
}

func TestConfigureBundleFetcherRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name                  string
		maxAttempts           int
		timeout               time.Duration
		delay                 time.Duration
		dialTimeout           time.Duration
		tlsHandshakeTimeout   time.Duration
		responseHeaderTimeout time.Duration
		errorText             string
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
			dialTimeout: -time.Millisecond,
			errorText:   "registry-dial-timeout must not be negative",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fetcher.MaxAttempts = 9
			fetcher.Timeout = 9 * time.Second
			fetcher.Delay = 9 * time.Millisecond

			err := configureBundleFetcher(test.maxAttempts, test.timeout, test.delay,
				test.dialTimeout, test.tlsHandshakeTimeout, test.responseHeaderTimeout)

			require.EqualError(t, err, test.errorText)
			assert.Equal(t, 9, fetcher.MaxAttempts)
			assert.Equal(t, 9*time.Second, fetcher.Timeout)
			assert.Equal(t, 9*time.Millisecond, fetcher.Delay)
		})
	}
}
