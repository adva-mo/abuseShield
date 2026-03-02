package limiter

import (
	"fmt"
	"os"
	"testing"
	"time"
)

const (
	testIPRate   = 1000.0
	testIPBurst  = 2000.0
	testKeyRate  = 1000.0
	testKeyBurst = 2000.0
	testHotMul   = 3.0
	testCooldown = int64(60 * time.Second)
)

func newTestLimiter() *Limiter {
	return New(testIPRate, testIPBurst, testKeyRate, testKeyBurst, testHotMul, testCooldown)
}

// TestMain prints a column-name header before the benchmark runner output.
func TestMain(m *testing.M) {
	fmt.Fprintln(os.Stdout, "")
	fmt.Fprintln(os.Stdout, "  Benchmark                        │ procs │    ns/op │      req/sec │  B/op │ allocs/op")
	fmt.Fprintln(os.Stdout, "  ───────────────────────────────────────────────────────────────────────────────────────")
	os.Exit(m.Run())
}

// BenchmarkAllowSingleKey measures worst-case shard contention:
// all goroutines hammer the same IP, serializing on one shard's mutex.
func BenchmarkAllowSingleKey(b *testing.B) {
	l := newTestLimiter()
	now := time.Now().UnixNano()
	b.ResetTimer()
	start := time.Now()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			l.CheckIP("192.0.2.1", now)
		}
	})
	b.ReportMetric(float64(b.N)/time.Since(start).Seconds(), "req/sec")
}

// BenchmarkAllowDistributedKeys measures realistic production throughput:
// 10k unique IPs distributed across all 256 shards.
func BenchmarkAllowDistributedKeys(b *testing.B) {
	const numKeys = 10_000
	keys := make([]string, numKeys)
	for i := range keys {
		keys[i] = fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
	}

	l := newTestLimiter()
	now := time.Now().UnixNano()
	b.ResetTimer()
	start := time.Now()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			l.CheckIP(keys[i%numKeys], now)
			i++
		}
	})
	b.ReportMetric(float64(b.N)/time.Since(start).Seconds(), "req/sec")
}

// BenchmarkAllowWithAPIKey measures the dual-check path (IP + API key).
// Each iteration performs two allow() calls, so req/sec counts decision pairs.
func BenchmarkAllowWithAPIKey(b *testing.B) {
	const numIPs = 1000
	const numKeys = 500
	ips := make([]string, numIPs)
	apiKeys := make([]string, numKeys)
	for i := range ips {
		ips[i] = fmt.Sprintf("10.0.%d.%d", (i>>8)&0xFF, i&0xFF)
	}
	for i := range apiKeys {
		apiKeys[i] = fmt.Sprintf("key-%d", i)
	}

	l := newTestLimiter()
	now := time.Now().UnixNano()
	b.ResetTimer()
	start := time.Now()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			l.CheckIP(ips[i%numIPs], now)
			l.CheckKey(apiKeys[i%numKeys], now)
			i++
		}
	})
	b.ReportMetric(float64(b.N)/time.Since(start).Seconds(), "req/sec")
}

// BenchmarkFNV1a32 isolates hash cost; verifies 0 allocs/op.
func BenchmarkFNV1a32(b *testing.B) {
	const key = "192.168.100.200"
	b.ReportAllocs()
	b.ResetTimer()
	start := time.Now()
	var sink uint32
	for i := 0; i < b.N; i++ {
		sink = fnv1a32(key)
	}
	b.ReportMetric(float64(b.N)/time.Since(start).Seconds(), "hash/sec")
	_ = sink
}

// BenchmarkHotKeyBlock measures fast-path exit speed for a key in cooldown.
func BenchmarkHotKeyBlock(b *testing.B) {
	l := newTestLimiter()
	const ip = "203.0.113.1"

	// Force the key into cooldown by directly manipulating shard state.
	idx := shardIndex(ip)
	sh := &l.ipShards[idx]
	sh.mu.Lock()
	if sh.keys == nil {
		sh.keys = make(map[string]*bucket)
	}
	now := time.Now().UnixNano()
	sh.keys[ip] = &bucket{
		tokens:     0,
		lastRefill: now,
		blocked:    true,
		blockUntil: now + testCooldown,
	}
	sh.mu.Unlock()
	sh.size.Add(1)

	b.ResetTimer()
	start := time.Now()
	b.RunParallel(func(pb *testing.PB) {
		n := time.Now().UnixNano()
		for pb.Next() {
			l.CheckIP(ip, n)
		}
	})
	b.ReportMetric(float64(b.N)/time.Since(start).Seconds(), "req/sec")
}
