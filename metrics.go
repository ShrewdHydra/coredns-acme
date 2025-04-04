package acme

import (
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Variables declared for monitoring.
var (
	// RequestCount exports a prometheus metric that is incremented every time a DNS request is processed by the acme plugin.
	RequestCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "acme",
		Name:      "request_count_total",
		Help:      "Counter of DNS requests served by the acme plugin.",
	}, []string{"server"})

	// APIRequestCount exports a prometheus metric that is incremented every time an API request is processed.
	APIRequestCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "acme",
		Name:      "api_request_count_total",
		Help:      "Counter of API requests to the acme plugin.",
	}, []string{"server", "endpoint"})
)
