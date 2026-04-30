package engine

// L1Result is the output of the L1 rate-limit and burst-detection check.
type L1Result struct {
	Allowed    bool
	Decision   string  // "ALLOW" | "BLOCK"
	Reason     string  // "" | "rate_limited" | "burst_detected"
	Confidence float64 // 0.0 when allowed; 0.90 rate_limited; 0.95 burst_detected
}

// CheckL1 performs the L1 check for the given entity.
//   - rate:         tokens refilled per second
//   - burst:        maximum token capacity (also the initial token count)
//   - burstWindowNs: detection window in nanoseconds (e.g. 2s = 2_000_000_000)
//   - now:          current time as UnixNano
//
// Hot path: acquires shard lock, reads/mutates entityState, releases lock.
// Zero heap allocations: all values are primitives on the stack.
func CheckL1(s *Store, entityKey string, rate, burst float64, burstWindowNs, now int64) L1Result {
	sh, st := s.getOrCreate(entityKey, now, burst)

	// Fast path for brand-new entities: getOrCreate already returned ALLOW
	// by seeding tokens=burst. The initial call is handled below; on re-entry
	// the entity exists and we fall through to normal token-bucket logic.

	// Refill tokens based on elapsed time since last check.
	elapsed := float64(now-st.lastRefill) / 1e9
	st.tokens += elapsed * rate
	if st.tokens > burst {
		st.tokens = burst
	}
	st.lastRefill = now

	// Reset the burst window if we've moved past the window boundary.
	if now-st.windowStart >= burstWindowNs {
		st.windowStart = now
		st.windowCount = 0
	}

	// Burst detection: if this request would push the window count above
	// burst within the burst window, the entity is exhausting the burst
	// capacity in a single window — a strong bot signal.
	// Checked before token exhaustion so this more specific reason always
	// takes priority over the generic rate_limited reason.
	if float64(st.windowCount+1) > burst {
		st.lastSeen = now
		sh.mu.Unlock()
		return L1Result{
			Allowed:    false,
			Decision:   "BLOCK",
			Reason:     "burst_detected",
			Confidence: 0.95,
		}
	}

	// Token exhaustion: not enough tokens for this request.
	if st.tokens < 1.0 {
		st.lastSeen = now
		sh.mu.Unlock()
		return L1Result{
			Allowed:    false,
			Decision:   "BLOCK",
			Reason:     "rate_limited",
			Confidence: 0.90,
		}
	}

	// Allow: consume one token and count this request in the burst window.
	st.tokens--
	st.windowCount++
	st.lastSeen = now
	sh.mu.Unlock()
	return L1Result{
		Allowed:    true,
		Decision:   "ALLOW",
		Reason:     "",
		Confidence: 1.0,
	}
}
