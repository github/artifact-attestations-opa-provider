package metrics //nolint:revive

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	//nolint: revive
	AttestationsRetrieved = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aaop_attestations_retrieved_total",
		Help: "The total number of attestations retrieved",
	})

	//nolint: revive
	AttestationsRetrieveFail = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aaop_attestations_retrieved_fail",
		Help: "The total number of attestations retrieve failure",
	}, []string{"reason"})

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
	AttestationsPullTimer = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "aaop_attestations_retrieved_timer",
		Help: "The duration (seconds) for fetching attestations from the OCI registry",
	})

	//nolint: revive
	AttestationsVerTimer = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "aaop_attestations_verification_timer",
		Help: "The duration (seconds) for verifying attestations",
	})

	//nolint: revive
	AttestationsReqTimer = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "aaop_attestations_request_timer",
		Help: "The duration (seconds) for the entire request processing",
	})

	//nolint: revive
	AttestationsReqImages = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "aaop_attestations_request_images",
		Help:    "The number of images (keys) included in a single provider request",
		Buckets: []float64{1, 2, 3, 5, 10, 20, 50},
	})

	//nolint: revive
	BundleCacheHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aaop_bundle_cache_hits_total",
		Help: "The total number of bundle fetches served from the in-memory cache",
	})

	//nolint: revive
	BundleCacheMisses = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aaop_bundle_cache_misses_total",
		Help: "The total number of bundle fetches not served from the in-memory cache",
	})

	//nolint: revive
	BundleFetchDeduped = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aaop_bundle_fetch_deduped_total",
		Help: "The total number of bundle fetches de-duplicated by singleflight (shared with an in-flight fetch)",
	})

	//nolint: revive
	BundleCacheEntries = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "aaop_bundle_cache_entries",
		Help: "The current number of entries in the in-memory bundle cache",
	})
)
