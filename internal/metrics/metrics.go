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

	// Abuse detection counters — fire on detection regardless of shadow mode.
	// "Detected" means the signal fired; use BlockedTotal to count actual rejections.
	EventsLogged        atomic.Int64 // SecurityEvents written to the log
	EventsDropped       atomic.Int64 // SecurityEvents dropped because the async buffer was full
	DetectedByBurst     atomic.Int64 // L1 burst_detected signal fired
	DetectedByRateLimit atomic.Int64 // L1 rate_limited signal fired (slow persistent bots)
	DetectedSeq         atomic.Int64 // L2 sequence_violation signal fired
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
		detByBurst := DetectedByBurst.Load()
		detByRateLimit := DetectedByRateLimit.Load()
		detSeq := DetectedSeq.Load()

		var activeKeys, activeEntities int64
		if s.ActiveLimiterKeys != nil {
			activeKeys = s.ActiveLimiterKeys()
		}
		if s.ActiveEntities != nil {
			activeEntities = s.ActiveEntities()
		}

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		fmt.Fprintf(w, "# HELP abuseshield_allowed_requests_total Requests proxied to upstream.\n")
		fmt.Fprintf(w, "# TYPE abuseshield_allowed_requests_total counter\n")
		fmt.Fprintf(w, "abuseshield_allowed_requests_total %d\n\n", allowed)

		fmt.Fprintf(w, "# HELP abuseshield_blocked_requests_total Requests rejected (always zero in shadow mode).\n")
		fmt.Fprintf(w, "# TYPE abuseshield_blocked_requests_total counter\n")
		fmt.Fprintf(w, "abuseshield_blocked_requests_total %d\n\n", blocked)

		fmt.Fprintf(w, "# HELP abuseshield_blocked_by_reason_total Enforced blocks by reason (always zero in shadow mode).\n")
		fmt.Fprintf(w, "# TYPE abuseshield_blocked_by_reason_total counter\n")
		fmt.Fprintf(w, "abuseshield_blocked_by_reason_total{reason=\"ip\"} %d\n", byIP)
		fmt.Fprintf(w, "abuseshield_blocked_by_reason_total{reason=\"api_key\"} %d\n", byKey)
		fmt.Fprintf(w, "abuseshield_blocked_by_reason_total{reason=\"cooldown\"} %d\n\n", byCooldown)

		fmt.Fprintf(w, "# HELP abuseshield_detected_by_reason_total Detection signals fired (increments in shadow mode too).\n")
		fmt.Fprintf(w, "# TYPE abuseshield_detected_by_reason_total counter\n")
		fmt.Fprintf(w, "abuseshield_detected_by_reason_total{reason=\"burst_detected\"} %d\n", detByBurst)
		fmt.Fprintf(w, "abuseshield_detected_by_reason_total{reason=\"rate_limited\"} %d\n", detByRateLimit)
		fmt.Fprintf(w, "abuseshield_detected_by_reason_total{reason=\"sequence_violation\"} %d\n\n", detSeq)

		fmt.Fprintf(w, "# HELP abuseshield_security_events_total SecurityEvents emitted by the async logger.\n")
		fmt.Fprintf(w, "# TYPE abuseshield_security_events_total counter\n")
		fmt.Fprintf(w, "abuseshield_security_events_total{status=\"logged\"} %d\n", evLogged)
		fmt.Fprintf(w, "abuseshield_security_events_total{status=\"dropped\"} %d\n\n", evDropped)

		fmt.Fprintf(w, "# HELP abuseshield_active_keys_count Limiter keys currently tracked (gauge).\n")
		fmt.Fprintf(w, "# TYPE abuseshield_active_keys_count gauge\n")
		fmt.Fprintf(w, "abuseshield_active_keys_count %d\n\n", activeKeys)

		fmt.Fprintf(w, "# HELP abuseshield_active_entities_count Entity fingerprints currently tracked (gauge).\n")
		fmt.Fprintf(w, "# TYPE abuseshield_active_entities_count gauge\n")
		fmt.Fprintf(w, "abuseshield_active_entities_count %d\n", activeEntities)
	}
}
