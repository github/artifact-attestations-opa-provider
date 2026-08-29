package metrics //nolint:revive

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// fetchBuckets resolves the per-image fetch-latency body and the failure tail:
// the success percentiles, the connection-phase boundaries, the fixed failure
// walls, and the long cancellations that the default buckets (which top out at
// 10s) collapse into +Inf.
var fetchBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 1.5, 2, 2.5, 3, 4, 6, 8, 10, 15, 30, 60}

// requestBuckets resolves the whole-request ceilings and the tail beyond them.
var requestBuckets = []float64{0.1, 0.25, 0.5, 1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 20, 30, 60}

var (
	//nolint: revive
	AttestationsRetrieved = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aaop_attestations_retrieved_total",
		Help: "The total number of attestations retrieved",
	})

	//nolint: revive
	AttestationsRetrieveFail = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aaop_attestations_retrieved_fail",
		Help: "The total number of attestation fetch failures, by reason, fetch step, and registry HTTP status (0 when no numeric status was recorded)",
	}, []string{"reason", "step", "status"})

	//nolint: revive
	AttestationsMissing = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aaop_attestations_missing_total",
		Help: "The total number of verifications where no attestations exist",
	})

	//nolint: revive
	AttestationsVerOk = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aaop_attestations_verified_ok",
		Help: "The total number of attestations verified",
	})

	//nolint: revive
	AttestationsVerFail = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aaop_attestations_verified_fail",
		Help: "The total number of attestations that failed verification",
	})

	//nolint: revive
	AttestationsPullTimer = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "aaop_attestations_retrieved_timer",
		Help:    "The duration (seconds) for fetching attestations for a single image from the OCI registry, labelled by outcome and (on failure) reason, fetch step, and attempts",
		Buckets: fetchBuckets,
	}, []string{"outcome", "reason", "step", "attempts"})

	//nolint: revive
	AttestationsVerTimer = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "aaop_attestations_verification_timer",
		Help: "The duration (seconds) for verifying attestations",
	})

	//nolint: revive
	AttestationsReqTimer = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "aaop_attestations_request_timer",
		Help:    "The duration (seconds) for the entire request processing, labelled by image count and outcome (whether every image verified cleanly)",
		Buckets: requestBuckets,
	}, []string{"images", "outcome"})

	//nolint: revive
	KeychainBuildTimer = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "aaop_keychain_build_timer",
		Help:    "The duration (seconds) to build the registry keychain",
		Buckets: append(prometheus.DefBuckets, 15, 30),
	})

	//nolint: revive
	KeychainRefreshFail = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aaop_keychain_refresh_fail",
		Help: "The total number of background keychain refreshes that failed or were degraded (did not fully rebuild the keychain), leaving the previous keychain in place",
	})

	//nolint: revive
	ConfigInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "aaop_config_info",
		Help: "The effective fetch configuration; value is always 1",
	}, []string{"bundle_timeout", "bundle_max_attempts", "bundle_delay", "retry_throttled"})
)

// SetConfigInfo records the effective fetch configuration as a single always-1
// gauge series so config can be compared across instances at a glance. It is
// defined here so prom.go stays the single definition site for every metric.
func SetConfigInfo(bundleTimeout time.Duration, maxAttempts int, delay time.Duration, retryThrottled bool) {
	ConfigInfo.WithLabelValues(
		bundleTimeout.String(),
		strconv.Itoa(maxAttempts),
		delay.String(),
		strconv.FormatBool(retryThrottled),
	).Set(1)
}
