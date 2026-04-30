package engine

// L2Result is the output of the L2 sequence check.
type L2Result struct {
	Suspicious bool
	Reason     string  // "" | "sequence_violation"
	Confidence float64 // 0.0 when clean; 0.7 when suspicious
}

// CheckL2 updates the entity's page-visit sequence and returns an L2Result.
//
// The check enforces the invariant: a legitimate user visits /home before
// /register. Hitting /register without a prior /home visit is a strong signal
// of a scripted onboarding flow (bot or automation).
//
//   - path: normalized request path (trailing slash already stripped by caller)
//   - now:  current time as UnixNano (recorded as homeTime on first /home visit)
//
// Acquires shard lock, mutates seenHome/seenRegister/homeTime, releases lock.
func CheckL2(s *Store, entityKey, path string, now int64) L2Result {
	sh, st := s.getOrCreate(entityKey, now, 0) // burst=0: getOrCreate won't be used for L1 here

	var result L2Result

	switch path {
	case "/home":
		if !st.seenHome {
			st.seenHome = true
			st.homeTime = now
		}
	case "/register":
		st.seenRegister = true
		if !st.seenHome {
			// /register reached without a prior /home visit — sequence violation.
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
