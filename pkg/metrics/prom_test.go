package metrics //nolint:revive

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

// TestSetConfigInfo verifies the config-info gauge records exactly one always-1
// series carrying the effective fetch configuration.
func TestSetConfigInfo(t *testing.T) {
	SetConfigInfo(2500*time.Millisecond, 3, 250*time.Millisecond, false)

	// Exactly one config-info series is emitted.
	assert.Equal(t, 1, testutil.CollectAndCount(ConfigInfo, "aaop_config_info"))

	// It is the always-1 gauge with the expected label values (durations render
	// via time.Duration.String, so 2.5s and 250ms).
	g := ConfigInfo.WithLabelValues("2.5s", "3", "250ms", "false")
	assert.InDelta(t, 1.0, testutil.ToFloat64(g), 0.0001)
}
