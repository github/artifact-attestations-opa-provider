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
	t.Cleanup(func() {
		fetcher.MaxAttempts = originalMaxAttempts
		fetcher.Timeout = originalTimeout
		fetcher.Delay = originalDelay
	})

	err := configureBundleFetcher(5, 750*time.Millisecond, 25*time.Millisecond)

	require.NoError(t, err)
	assert.Equal(t, 5, fetcher.MaxAttempts)
	assert.Equal(t, 750*time.Millisecond, fetcher.Timeout)
	assert.Equal(t, 25*time.Millisecond, fetcher.Delay)
}

func TestConfigureBundleFetcherRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name        string
		maxAttempts int
		timeout     time.Duration
		delay       time.Duration
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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fetcher.MaxAttempts = 9
			fetcher.Timeout = 9 * time.Second
			fetcher.Delay = 9 * time.Millisecond

			err := configureBundleFetcher(test.maxAttempts, test.timeout, test.delay)

			require.EqualError(t, err, test.errorText)
			assert.Equal(t, 9, fetcher.MaxAttempts)
			assert.Equal(t, 9*time.Second, fetcher.Timeout)
			assert.Equal(t, 9*time.Millisecond, fetcher.Delay)
		})
	}
}
