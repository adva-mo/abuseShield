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
	EventsLogged   atomic.Int64 // SecurityEvents written to the log
	EventsDropped  atomic.Int64 // SecurityEvents dropped because the async buffer was full
	DetectedByBurst atomic.Int64 // L1 burst_detected signal fired
	DetectedSeq     atomic.Int64 // L2 sequence_violation signal fired
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
		detSeq := DetectedSeq.Load()

		var activeKeys, activeEntities int64
		if s.ActiveLimiterKeys != nil {
			activeKeys = s.ActiveLimiterKeys()
		}
		if s.ActiveEntities != nil {
			activeEntities = s.ActiveEntities()
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "abuseshield_allowed_requests_total %d\n", allowed)
		fmt.Fprintf(w, "abuseshield_blocked_requests_total %d\n", blocked)
		fmt.Fprintf(w, "abuseshield_blocked_by_reason_total{reason=\"ip\"} %d\n", byIP)
		fmt.Fprintf(w, "abuseshield_blocked_by_reason_total{reason=\"api_key\"} %d\n", byKey)
		fmt.Fprintf(w, "abuseshield_blocked_by_reason_total{reason=\"cooldown\"} %d\n", byCooldown)
		fmt.Fprintf(w, "abuseshield_detected_by_reason_total{reason=\"burst_detected\"} %d\n", detByBurst)
		fmt.Fprintf(w, "abuseshield_detected_by_reason_total{reason=\"sequence_violation\"} %d\n", detSeq)
		fmt.Fprintf(w, "abuseshield_security_events_total{status=\"logged\"} %d\n", evLogged)
		fmt.Fprintf(w, "abuseshield_security_events_total{status=\"dropped\"} %d\n", evDropped)
		fmt.Fprintf(w, "abuseshield_active_keys_count %d\n", activeKeys)
		fmt.Fprintf(w, "abuseshield_active_entities_count %d\n", activeEntities)
	}
}
