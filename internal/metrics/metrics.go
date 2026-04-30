package metrics

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

// Counters are package-level atomics — no allocation on the hot path.
var (
	AllowedTotal      atomic.Int64
	BlockedTotal      atomic.Int64
	BlockedByIP       atomic.Int64
	BlockedByAPIKey   atomic.Int64
	BlockedByCooldown atomic.Int64

	// Abuse detection counters.
	EventsLogged   atomic.Int64 // SecurityEvents successfully enqueued
	EventsDropped  atomic.Int64 // SecurityEvents dropped (buffer full) — alias of engine.EventsDropped
	BlockedByBurst atomic.Int64 // L1 burst_detected blocks
	SuspiciousSeq  atomic.Int64 // L2 sequence_violation hits
)

// Sources carries the dynamic gauge callbacks needed by Handler.
// Using a struct avoids changing the Handler signature when new gauges are added.
type Sources struct {
	ActiveLimiterKeys func() int64 // from limiter.Limiter.ActiveKeysCount
	ActiveEntities    func() int64 // from engine.Store.ActiveCount
}

// Handler returns an http.HandlerFunc that serves Prometheus-compatible
// plain-text metrics. The Sources callbacks avoid circular imports between
// the metrics package and the limiter/engine packages.
func Handler(s Sources) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		allowed := AllowedTotal.Load()
		blocked := BlockedTotal.Load()
		byIP := BlockedByIP.Load()
		byKey := BlockedByAPIKey.Load()
		byCooldown := BlockedByCooldown.Load()
		evLogged := EventsLogged.Load()
		evDropped := EventsDropped.Load()
		byBurst := BlockedByBurst.Load()
		suspSeq := SuspiciousSeq.Load()

		var activeKeys, activeEntities int64
		if s.ActiveLimiterKeys != nil {
			activeKeys = s.ActiveLimiterKeys()
		}
		if s.ActiveEntities != nil {
			activeEntities = s.ActiveEntities()
		}

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprintf(w, "# HELP abuseshield_allowed_requests_total Total allowed requests\n")
		fmt.Fprintf(w, "# TYPE abuseshield_allowed_requests_total counter\n")
		fmt.Fprintf(w, "abuseshield_allowed_requests_total %d\n\n", allowed)

		fmt.Fprintf(w, "# HELP abuseshield_blocked_requests_total Total blocked requests\n")
		fmt.Fprintf(w, "# TYPE abuseshield_blocked_requests_total counter\n")
		fmt.Fprintf(w, "abuseshield_blocked_requests_total %d\n\n", blocked)

		fmt.Fprintf(w, "# HELP abuseshield_blocked_by_reason_total Blocked requests broken down by reason\n")
		fmt.Fprintf(w, "# TYPE abuseshield_blocked_by_reason_total counter\n")
		fmt.Fprintf(w, "abuseshield_blocked_by_reason_total{reason=\"ip\"} %d\n", byIP)
		fmt.Fprintf(w, "abuseshield_blocked_by_reason_total{reason=\"api_key\"} %d\n", byKey)
		fmt.Fprintf(w, "abuseshield_blocked_by_reason_total{reason=\"cooldown\"} %d\n", byCooldown)
		fmt.Fprintf(w, "abuseshield_blocked_by_reason_total{reason=\"burst_detected\"} %d\n", byBurst)
		fmt.Fprintf(w, "\n")

		fmt.Fprintf(w, "# HELP abuseshield_suspicious_total Suspicious requests by detection layer\n")
		fmt.Fprintf(w, "# TYPE abuseshield_suspicious_total counter\n")
		fmt.Fprintf(w, "abuseshield_suspicious_total{reason=\"sequence_violation\"} %d\n\n", suspSeq)

		fmt.Fprintf(w, "# HELP abuseshield_security_events_total SecurityEvents emitted by the detection engine\n")
		fmt.Fprintf(w, "# TYPE abuseshield_security_events_total counter\n")
		fmt.Fprintf(w, "abuseshield_security_events_total{status=\"logged\"} %d\n", evLogged)
		fmt.Fprintf(w, "abuseshield_security_events_total{status=\"dropped\"} %d\n\n", evDropped)

		fmt.Fprintf(w, "# HELP abuseshield_active_keys_count Current number of tracked limiter keys\n")
		fmt.Fprintf(w, "# TYPE abuseshield_active_keys_count gauge\n")
		fmt.Fprintf(w, "abuseshield_active_keys_count %d\n\n", activeKeys)

		fmt.Fprintf(w, "# HELP abuseshield_active_entities_count Current number of tracked entity fingerprints\n")
		fmt.Fprintf(w, "# TYPE abuseshield_active_entities_count gauge\n")
		fmt.Fprintf(w, "abuseshield_active_entities_count %d\n", activeEntities)
	}
}
