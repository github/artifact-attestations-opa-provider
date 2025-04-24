package metrics

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
	AttestationsRetrieveFail = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aaop_attestations_retrieved_fail",
		Help: "The total number of attestations retrieve failure",
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
		Name: "aaop_attestations_verifcation_timer",
		Help: "The duration (seconds) for verifying attestations",
	})

	//nolint: revive
	AttestationsReqTimer = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "aaop_attestations_request_timer",
		Help: "The duration (seconds) for the entire request processing",
	})
)
