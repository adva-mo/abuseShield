package limiter

import (
	"sync"
	"sync/atomic"
)

const (
	numShards     = 256
	// minHotSamples is the minimum number of allowed requests within a 1-second
	// window before hot-key cooldown can activate. Prevents short legitimate
	// bursts from triggering cooldown.
	minHotSamples = 50
)

// bucket is the per-key token-bucket state.
type bucket struct {
	tokens      float64 // current token count
	lastRefill  int64   // UnixNano of last refill
	windowStart int64   // UnixNano — start of current 1-second hot-key window
	windowCount int64   // allowed requests in current window (blocked requests excluded)
	blocked     bool    // true when in hot-key cooldown
	blockUntil  int64   // UnixNano when cooldown expires
}

// shard holds a mutex-protected map of buckets padded to 64 bytes to
// prevent false sharing across CPU cache lines.
type shard struct {
	mu   sync.Mutex
	keys map[string]*bucket
	size atomic.Int64
	// Padding: sync.Mutex is 8 bytes, map is 8 bytes, atomic.Int64 is 8 bytes = 24 bytes.
	// We pad to 64 bytes to fill a full cache line.
	_ [64 - 24]byte
}

// fnv1a32 computes a 32-bit FNV-1a hash of s with zero allocations.
// Iterates string bytes directly — no []byte conversion needed.
func fnv1a32(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

// shardIndex returns the shard index for key k using bitwise AND (no division).
func shardIndex(k string) uint8 {
	return uint8(fnv1a32(k) & 0xFF)
}

// allow checks and updates the token bucket for key in the given shard array.
// rate is tokens/sec, burst is max tokens, hotMul is the hot-key multiplier,
// cooldownNs is cooldown duration in nanoseconds, now is current UnixNano.
// Returns (allowed bool, retryAfterMs int64, reason string).
// reason is "" when allowed, "cooldown" when in hot-key cooldown, "token" when
// the token bucket is exhausted. Callers map "token" to a keyspace-specific label.
func allow(shards *[numShards]shard, key string, rate, burst, hotMul float64, cooldownNs, now int64) (bool, int64, string) {
	idx := shardIndex(key)
	sh := &shards[idx]

	sh.mu.Lock()

	b, exists := sh.keys[key]
	if !exists {
		b = &bucket{
			tokens:      burst, // new clients start with full burst
			lastRefill:  now,
			windowStart: now,
		}
		if sh.keys == nil {
			sh.keys = make(map[string]*bucket)
		}
		sh.keys[key] = b
		sh.mu.Unlock()
		sh.size.Add(1)
		return true, 0, ""
	}

	// Fast path: check cooldown block first.
	if b.blocked {
		if now < b.blockUntil {
			retryMs := (b.blockUntil - now) / 1e6
			sh.mu.Unlock()
			return false, retryMs, "cooldown"
		}
		// Cooldown expired — unblock and reset.
		b.blocked = false
		b.windowStart = now
		b.windowCount = 0
	}

	// Refill tokens based on elapsed time since last refill.
	elapsed := float64(now-b.lastRefill) / 1e9
	b.tokens += elapsed * rate
	if b.tokens > burst {
		b.tokens = burst
	}
	b.lastRefill = now

	// Token bucket: fail fast before touching hot-key counters.
	// Blocked-by-exhaustion requests must not count toward hot-key detection.
	if b.tokens < 1.0 {
		deficit := 1.0 - b.tokens
		retryNs := int64(deficit / rate * 1e9)
		retryMs := retryNs / 1e6
		if retryMs < 1 {
			retryMs = 1
		}
		sh.mu.Unlock()
		return false, retryMs, "token"
	}

	// Update hot-key window (fixed 1-second window).
	if now-b.windowStart >= 1_000_000_000 {
		b.windowStart = now
		b.windowCount = 0
	}

	// Hot-key detection: check whether admitting this request would push
	// the allowed-request count over the threshold. windowCount is only
	// incremented for requests that are actually allowed, so both conditions
	// must hold to avoid false positives on short bursts.
	nextAllowed := b.windowCount + 1
	if float64(nextAllowed) > hotMul*rate && nextAllowed >= minHotSamples {
		b.blocked = true
		b.blockUntil = now + cooldownNs
		retryMs := (b.blockUntil - now) / 1e6
		if retryMs < 0 {
			retryMs = 0
		}
		sh.mu.Unlock()
		return false, retryMs, "cooldown"
	}

	// Allow: count this request and consume the token.
	b.windowCount++
	b.tokens--
	sh.mu.Unlock()
	return true, 0, ""
}

// evictExpired removes stale buckets from a single shard.
// A bucket is stale if it was last used more than staleness nanoseconds ago
// and is not currently blocked.
func evictShard(sh *shard, now, stalenessNs int64) {
	sh.mu.Lock()
	var removed int64
	for k, b := range sh.keys {
		if !b.blocked && now-b.lastRefill > stalenessNs {
			delete(sh.keys, k)
			removed++
		}
	}
	sh.mu.Unlock()
	if removed > 0 {
		sh.size.Add(-removed)
	}
}
