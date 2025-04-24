package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	AttestationsRetrieved = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aaop_attestations_retrieved_total",
		Help: "The total number of attestations retrieved",
	})

	AttestationsRetrieveFail = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aaop_attestations_retrieved_fail",
		Help: "The total number of attestations retrieve failure",
	})

	AttestationsVerOk = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aaop_attestations_verified_ok",
		Help: "The total number of attestations verified",
	})

	AttestationsVerFail = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aaop_attestations_verified_fail",
		Help: "The total number of attestations that failed verification",
	})

	AttestationsPullTimer = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "aaop_attestations_retrieved_timer",
		Help: "The duration (seconds) for fetching attestations from the OCI registry",
	})

	AttestationsVerTimer = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "aaop_attestations_verifcation_timer",
		Help: "The duration (seconds) for verifying attestations",
	})

	AttestationsReqTimer = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "aaop_attestations_request_timer",
		Help: "The duration (seconds) for the entire request processing",
	})
)
