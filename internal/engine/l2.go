package engine

// L2Result is the output of the L2 sequence check.
type L2Result struct {
	Suspicious bool
	Reason     string  // "" | "sequence_violation"
	Confidence float64 // 0.0 when clean; 0.7 when suspicious
}

// CheckL2 updates the entity's page-visit sequence and returns an L2Result.
//
// It enforces the invariant: a legitimate user visits gate before target.
// Hitting target without a prior gate visit is a strong signal of a scripted
// onboarding flow (bot or automation).
//
//   - gate:   the expected first step in the funnel (e.g. "/home")
//   - target: the protected endpoint (e.g. "/register")
//   - now:    current time as UnixNano (recorded as gateTime on first gate visit)
//
// Acquires shard lock, mutates seenGate/seenTarget/gateTime, releases lock.
func CheckL2(s *Store, entityKey, path, gate, target string, now int64) L2Result {
	sh, st := s.getOrCreate(entityKey, now, 0)

	var result L2Result

	switch path {
	case gate:
		if !st.seenGate {
			st.seenGate = true
		}
	case target:
		st.seenTarget = true
		if !st.seenGate {
			result = L2Result{
				Suspicious: true,
				Reason:     "sequence_violation",
				Confidence: 0.7,
			}
		}
	}

	st.lastSeen = now
	sh.mu.Unlock()
	return result
}
