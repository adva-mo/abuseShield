package metrics

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

// Counters are package-level atomics — no allocation on the hot path.
var (
	AllowedTotal atomic.Int64
	BlockedTotal atomic.Int64

	// Broken down by reason.
	BlockedByIP      atomic.Int64
	BlockedByAPIKey  atomic.Int64
	BlockedByCooldown atomic.Int64
)

// Handler returns an http.HandlerFunc that serves Prometheus-compatible
// plain-text metrics. activeKeysFn is a callback to avoid a circular import
// between the metrics and limiter packages.
func Handler(activeKeysFn func() int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		allowed := AllowedTotal.Load()
		blocked := BlockedTotal.Load()
		byIP := BlockedByIP.Load()
		byKey := BlockedByAPIKey.Load()
		byCooldown := BlockedByCooldown.Load()
		activeKeys := activeKeysFn()

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprintf(w, "# HELP abuseshield_allowed_requests_total Total allowed requests\n")
		fmt.Fprintf(w, "# TYPE abuseshield_allowed_requests_total counter\n")
		fmt.Fprintf(w, "abuseshield_allowed_requests_total %d\n\n", allowed)

		fmt.Fprintf(w, "# HELP abuseshield_blocked_requests_total Total blocked requests\n")
		fmt.Fprintf(w, "# TYPE abuseshield_blocked_requests_total counter\n")
		fmt.Fprintf(w, "abuseshield_blocked_requests_total %d\n\n", blocked)

		fmt.Fprintf(w, "# HELP abuseshield_blocked_by_reason_total Blocked requests by reason\n")
		fmt.Fprintf(w, "# TYPE abuseshield_blocked_by_reason_total counter\n")
		fmt.Fprintf(w, "abuseshield_blocked_by_reason_total{reason=\"ip\"} %d\n", byIP)
		fmt.Fprintf(w, "abuseshield_blocked_by_reason_total{reason=\"api_key\"} %d\n", byKey)
		fmt.Fprintf(w, "abuseshield_blocked_by_reason_total{reason=\"cooldown\"} %d\n\n", byCooldown)

		fmt.Fprintf(w, "# HELP abuseshield_active_keys_count Current number of tracked keys\n")
		fmt.Fprintf(w, "# TYPE abuseshield_active_keys_count gauge\n")
		fmt.Fprintf(w, "abuseshield_active_keys_count %d\n", activeKeys)
	}
}
