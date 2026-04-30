AbuseShield — Test Reference
============================

----------------------------------------------------------------------
RUN ALL TESTS
----------------------------------------------------------------------
go test ./...

Run all tests with verbose output:
go test ./... -v

Run all tests with race detector:
go test -race ./...


----------------------------------------------------------------------
E2E TESTS  (test/e2e/e2e_test.go)
----------------------------------------------------------------------

Run all e2e tests:
  go test ./test/e2e/ -v

Run a single e2e test:
  go test ./test/e2e/ -v -run <TestName>

--- Happy path ---
TestHappyPath
  Verifies a normal request is proxied to the upstream.
  go test ./test/e2e/ -v -run TestHappyPath

TestUpstreamBodyPassthrough
  Verifies the upstream response body reaches the client.
  go test ./test/e2e/ -v -run TestUpstreamBodyPassthrough

TestUpstreamStatusPassthrough
  Verifies non-200 upstream status codes are forwarded.
  go test ./test/e2e/ -v -run TestUpstreamStatusPassthrough

TestAPIKeyOptional
  Verifies requests without X-API-Key bypass key checking.
  go test ./test/e2e/ -v -run TestAPIKeyOptional

TestUpstreamUnavailable
  Verifies a 502 Bad Gateway when the upstream is down.
  go test ./test/e2e/ -v -run TestUpstreamUnavailable

--- Metrics ---
TestMetricsBypass
  Verifies /metrics is never subject to rate limiting.
  go test ./test/e2e/ -v -run TestMetricsBypass

TestMetricsFormat
  Verifies Prometheus text format and presence of all metric names.
  go test ./test/e2e/ -v -run TestMetricsFormat

TestActiveKeysCountInMetrics
  Verifies active_keys_count gauge reflects tracked keys after traffic.
  go test ./test/e2e/ -v -run TestActiveKeysCountInMetrics

TestMetricsCountersIncrement
  Verifies AllowedTotal and BlockedTotal accurately reflect traffic.
  go test ./test/e2e/ -v -run TestMetricsCountersIncrement

--- IP rate limiting ---
TestIPRateLimitExhausted
  Verifies IP token exhaustion produces a 429.
  go test ./test/e2e/ -v -run TestIPRateLimitExhausted

TestIPRateLimitReasonCounter
  Verifies BlockedByIP counter increments on IP exhaustion.
  go test ./test/e2e/ -v -run TestIPRateLimitReasonCounter

TestXFFIPIsolation
  Verifies different X-Forwarded-For IPs have independent token buckets.
  go test ./test/e2e/ -v -run TestXFFIPIsolation

TestXFFMultipleProxies
  Verifies the rightmost IP in a multi-hop XFF chain is used.
  go test ./test/e2e/ -v -run TestXFFMultipleProxies

TestXFFSpoofedLeftmostIgnored
  Verifies rotating spoofed leftmost IPs cannot bypass the rate limiter.
  go test ./test/e2e/ -v -run TestXFFSpoofedLeftmostIgnored

--- API key rate limiting ---
TestAPIKeyRateLimitExhausted
  Verifies API key token exhaustion produces a 429.
  go test ./test/e2e/ -v -run TestAPIKeyRateLimitExhausted

TestAPIKeyReasonCounter
  Verifies BlockedByAPIKey counter increments on key exhaustion.
  go test ./test/e2e/ -v -run TestAPIKeyReasonCounter

TestDifferentAPIKeysSeparateBuckets
  Verifies distinct API keys each get their own independent token bucket.
  go test ./test/e2e/ -v -run TestDifferentAPIKeysSeparateBuckets

TestIPKeyIndependence
  Verifies IP limiter and key limiter are independent.
  go test ./test/e2e/ -v -run TestIPKeyIndependence

--- Hot-key cooldown ---
TestHotKeyIPCooldown
  Verifies an IP sending >= 50 req/s is put into cooldown (429).
  go test ./test/e2e/ -v -run TestHotKeyIPCooldown

TestHotKeyIPCooldownCounter
  Verifies BlockedByCooldown is incremented for IP cooldown.
  go test ./test/e2e/ -v -run TestHotKeyIPCooldownCounter

TestHotKeyAPIKeyCooldown
  Verifies hot-key cooldown is enforced for API keys.
  go test ./test/e2e/ -v -run TestHotKeyAPIKeyCooldown

--- 429 response shape ---
TestRateLimitResponseHeaders
  Verifies 429 carries correct Content-Type and Retry-After header.
  go test ./test/e2e/ -v -run TestRateLimitResponseHeaders

TestRetryAfterMsPositive
  Verifies retry_after_ms in the JSON body is > 0.
  go test ./test/e2e/ -v -run TestRetryAfterMsPositive


----------------------------------------------------------------------
BENCHMARKS  (internal/limiter/bench_test.go)
----------------------------------------------------------------------

Run all benchmarks:
  go test -bench=. -benchmem ./internal/limiter/

BenchmarkAllowSingleKey
  Worst-case shard contention: all goroutines hammer the same IP.
  go test -bench=BenchmarkAllowSingleKey -benchmem ./internal/limiter/

BenchmarkAllowDistributedKeys
  Realistic production throughput: 10k unique IPs across 256 shards.
  go test -bench=BenchmarkAllowDistributedKeys -benchtime=10s -benchmem ./internal/limiter/

BenchmarkAllowWithAPIKey
  Dual-check path (IP + API key): measures decision pairs per second.
  go test -bench=BenchmarkAllowWithAPIKey -benchmem ./internal/limiter/

BenchmarkFNV1a32
  Isolates hash cost; verifies 0 allocs/op.
  go test -bench=BenchmarkFNV1a32 -benchmem ./internal/limiter/

BenchmarkHotKeyBlock
  Fast-path exit speed for a key already in cooldown.
  go test -bench=BenchmarkHotKeyBlock -benchmem ./internal/limiter/


----------------------------------------------------------------------
MANUAL TRAFFIC SIMULATION (server must be running)
----------------------------------------------------------------------

Start server:
  go run ./cmd/abuseshield/ -config config.json

Start upstream mock (separate terminal):
  python3 -m http.server 8081

Single IP — exhaust token bucket:
  for i in $(seq 1 200); do curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/; done | sort | uniq -c

Randomized IPs via XFF — all should be allowed (independent buckets):
  for i in $(seq 1 200); do curl -s -o /dev/null -w "%{http_code}\n" -H "X-Forwarded-For: 1.2.3.4, 10.0.0.$((RANDOM % 255 + 1))" http://localhost:8080/; done | sort | uniq -c

Trigger cooldown (same IP, fast loop, crosses minHotSamples=50):
  for i in $(seq 1 60); do curl -s -o /dev/null -H "X-Forwarded-For: 1.2.3.4, 10.0.0.2" http://localhost:8080/; done && curl -s http://localhost:8080/metrics | grep blocked

Check metrics:
  curl -s http://localhost:8080/metrics
