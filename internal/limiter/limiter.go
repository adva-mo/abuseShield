package limiter

import (
	"time"
)

// Decision is the result of a rate-limit check.
type Decision struct {
	Allowed      bool
	RetryAfterMs int64
	// Reason is set only when Allowed==false.
	// Values: "ip", "api_key", "cooldown"
	Reason string
}

// Limiter holds two independent shard arrays: one for IPs, one for API keys.
// Keeping them separate prevents cross-keyspace lock contention.
type Limiter struct {
	ipShards  [numShards]shard
	keyShards [numShards]shard

	ipRate    float64
	ipBurst   float64
	keyRate   float64
	keyBurst  float64
	hotMul   float64
	cooldown time.Duration
}

// New creates a Limiter with the given parameters.
func New(ipRate, ipBurst, keyRate, keyBurst, hotMul float64, cooldown time.Duration) *Limiter {
	return &Limiter{
		ipRate:   ipRate,
		ipBurst:  ipBurst,
		keyRate:  keyRate,
		keyBurst: keyBurst,
		hotMul:   hotMul,
		cooldown: cooldown,
	}
}

// CheckIP checks whether the given IP address is allowed.
func (l *Limiter) CheckIP(ip string, now int64) Decision {
	ok, retryMs, reason := allow(&l.ipShards, ip, l.ipRate, l.ipBurst, l.hotMul, int64(l.cooldown), now)
	if ok {
		return Decision{Allowed: true}
	}
	if reason == "token" {
		reason = "ip"
	}
	return Decision{Allowed: false, RetryAfterMs: retryMs, Reason: reason}
}

// CheckKey checks whether the given API key is allowed.
func (l *Limiter) CheckKey(key string, now int64) Decision {
	ok, retryMs, reason := allow(&l.keyShards, key, l.keyRate, l.keyBurst, l.hotMul, int64(l.cooldown), now)
	if ok {
		return Decision{Allowed: true}
	}
	if reason == "token" {
		reason = "api_key"
	}
	return Decision{Allowed: false, RetryAfterMs: retryMs, Reason: reason}
}

// ActiveKeysCount returns the total number of tracked keys across all shards.
// Reads 512 atomics (~2.5 µs) — acceptable for a metrics endpoint.
func (l *Limiter) ActiveKeysCount() int64 {
	var total int64
	for i := 0; i < numShards; i++ {
		total += l.ipShards[i].size.Load()
		total += l.keyShards[i].size.Load()
	}
	return total
}

// StartEviction launches a background goroutine that evicts stale buckets
// every interval. Buckets unused for more than 5 minutes are removed.
func (l *Limiter) StartEviction(interval time.Duration) {
	const stalenessNs = 5 * 60 * int64(time.Second/time.Nanosecond) // 5 minutes in ns

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now().UnixNano()
			for i := 0; i < numShards; i++ {
				evictShard(&l.ipShards[i], now, stalenessNs)
				evictShard(&l.keyShards[i], now, stalenessNs)
			}
		}
	}()
}
