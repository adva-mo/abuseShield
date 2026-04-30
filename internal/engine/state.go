package engine

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

const (
	numShards   = 256
	stalenessDur = 5 * time.Minute
)

// entityState holds all per-entity tracking data for L1 and L2 checks.
// Kept flat so a single map lookup gives everything with one pointer dereference.
type entityState struct {
	// L1: token bucket
	tokens      float64
	lastRefill  int64 // UnixNano
	windowCount int64 // requests in current burst window
	windowStart int64 // UnixNano — start of current burst window

	// L2: sequence tracking
	seenHome     bool
	seenRegister bool
	homeTime     int64 // UnixNano of first /home visit

	// eviction
	lastSeen int64 // UnixNano — updated on every access
}

// entityShard is a single shard of the entity state map, padded to 64 bytes
// (one CPU cache line) to prevent false sharing.
// Layout: sync.Mutex(8) + map(8) + atomic.Int64(8) = 24 bytes → pad [40]byte.
type entityShard struct {
	mu     sync.Mutex
	states map[string]*entityState
	size   atomic.Int64
	_      [64 - 24]byte
}

// Store is the top-level sharded entity state store.
type Store struct {
	shards [numShards]entityShard
}

// NewStore allocates a Store with all 256 shard maps pre-initialized.
func NewStore() *Store {
	s := &Store{}
	for i := range s.shards {
		s.shards[i].states = make(map[string]*entityState)
	}
	return s
}

// shardIndex returns the shard index for a key using FNV-1a64 + bitwise AND.
func shardIndex(key string) uint8 {
	return uint8(fnv1a64(key) & 0xFF)
}

// getOrCreate returns the shard and entity state for the given key, creating
// the entity if it does not exist (initialized with tokens=burst).
//
// The shard mutex is HELD on return. The caller is responsible for calling
// sh.mu.Unlock() after reading or mutating the entityState.
//
// burst is only used when initializing a new entity. For L2-only calls where
// the entity is expected to already exist, pass 0 — it has no effect on
// existing entities.
func (s *Store) getOrCreate(key string, now int64, burst float64) (*entityShard, *entityState) {
	idx := shardIndex(key)
	sh := &s.shards[idx]
	sh.mu.Lock()

	st, exists := sh.states[key]
	if !exists {
		st = &entityState{
			tokens:      burst,
			lastRefill:  now,
			windowStart: now,
			lastSeen:    now,
		}
		sh.states[key] = st
		sh.size.Add(1) // atomic.Int64.Add is safe to call under the shard lock
	}
	return sh, st
}

// evictShard removes entities not seen for more than stalenessNs nanoseconds.
func evictShard(sh *entityShard, now, stalenessNs int64) {
	sh.mu.Lock()
	var removed int64
	for k, st := range sh.states {
		if now-st.lastSeen > stalenessNs {
			delete(sh.states, k)
			removed++
		}
	}
	sh.mu.Unlock()
	if removed > 0 {
		sh.size.Add(-removed)
	}
}

// StartEviction launches a background goroutine that evicts stale entities
// from all 256 shards every interval. Stops when ctx is cancelled.
func (s *Store) StartEviction(ctx context.Context, interval time.Duration) {
	stalenessNs := stalenessDur.Nanoseconds()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case t := <-ticker.C:
				now := t.UnixNano()
				for i := range s.shards {
					evictShard(&s.shards[i], now, stalenessNs)
				}
			}
		}
	}()
}

// ActiveCount returns the total number of currently tracked entities
// by summing the size counter across all shards.
func (s *Store) ActiveCount() int64 {
	var total int64
	for i := range s.shards {
		total += s.shards[i].size.Load()
	}
	return total
}
