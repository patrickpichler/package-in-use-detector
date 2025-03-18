package tracer

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	Missing = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "package_in_use_missing",
		Help: "Counter for amount of missing items",
	}, []string{"type"})
	Collisions = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "package_in_use_collisions",
		Help: "Gauge for amount of collisions in files",
	}, []string{"type"})
	MapSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "package_in_use_map_size",
		Help: "Gauge for map size",
	}, []string{"type"})
)
