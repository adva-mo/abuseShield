// Package e2e contains end-to-end tests for AbuseShield.
//
// Each test wires the full handler stack (limiter → proxy → upstream mock) via
// httptest servers, so requests travel through every production code path.
// Tests are sequential (no t.Parallel) to keep shared metrics counters sane.
package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/adva-mo/abuseShield/internal/limiter"
	"github.com/adva-mo/abuseShield/internal/metrics"
	"github.com/adva-mo/abuseShield/internal/proxy"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// shieldConfig carries rate-limit parameters for a test stack.
type shieldConfig struct {
	ipRate      float64
	ipBurst     float64
	keyRate     float64
	keyBurst    float64
	hotMul      float64
	cooldownSec float64
}

// relaxedCfg has limits so high that normal tests never trigger them.
var relaxedCfg = shieldConfig{
	ipRate:      1000,
	ipBurst:     2000,
	keyRate:     1000,
	keyBurst:    2000,
	hotMul:      3,
	cooldownSec: 30,
}

// newStack creates an upstream mock server and a fully-wired AbuseShield
// server in front of it. Returns the shield's base URL and a cleanup func.
//
// The handler mirrors main.go: /metrics bypasses rate limiting, everything
// else goes through CheckIP → CheckKey → reverse proxy.
func newStack(t *testing.T, cfg shieldConfig, upstreamHandler http.Handler) (shieldURL string, cleanup func()) {
	t.Helper()

	upstream := httptest.NewServer(upstreamHandler)
	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	cooldown := time.Duration(cfg.cooldownSec * float64(time.Second))
	l := limiter.New(cfg.ipRate, cfg.ipBurst, cfg.keyRate, cfg.keyBurst, cfg.hotMul, cooldown)

	transport := proxy.NewTransport(16, 5*time.Second, 10*time.Second)
	rp := proxy.New(u, transport)

	mux := http.NewServeMux()

	// /metrics is never rate-limited.
	mux.Handle("/metrics", metrics.Handler(metrics.Sources{
		ActiveLimiterKeys: l.ActiveKeysCount,
	}))

	// All other paths go through the limiter then the proxy.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		now := time.Now().UnixNano()
		clientIP := proxy.ExtractClientIP(r)

		ipDec := l.CheckIP(clientIP, now)
		if !ipDec.Allowed {
			metrics.BlockedTotal.Add(1)
			switch ipDec.Reason {
			case "cooldown":
				metrics.BlockedByCooldown.Add(1)
			case "ip":
				metrics.BlockedByIP.Add(1)
			}
			proxy.WriteRateLimitResponse(w, ipDec.RetryAfterMs)
			return
		}

		if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
			keyDec := l.CheckKey(apiKey, now)
			if !keyDec.Allowed {
				metrics.BlockedTotal.Add(1)
				switch keyDec.Reason {
				case "cooldown":
					metrics.BlockedByCooldown.Add(1)
				case "api_key":
					metrics.BlockedByAPIKey.Add(1)
				}
				proxy.WriteRateLimitResponse(w, keyDec.RetryAfterMs)
				return
			}
		}

		metrics.AllowedTotal.Add(1)
		rp.ServeHTTP(w, r)
	})

	shield := httptest.NewServer(mux)
	return shield.URL, func() {
		shield.Close()
		upstream.Close()
	}
}

// echoHandler returns a simple upstream that replies with statusCode and body.
func echoHandler(statusCode int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(statusCode)
		fmt.Fprint(w, body)
	})
}

// doRequest sends a GET to shieldURL+path. xff and apiKey are optional.
func doRequest(t *testing.T, shieldURL, path, xff, apiKey string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, shieldURL+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

// drainClose discards and closes the response body.
func drainClose(resp *http.Response) {
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
}

// bodyString reads and closes the response body, returning its content.
func bodyString(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return strings.TrimSpace(string(b))
}

// resetMetrics zeroes all package-level metric counters.
func resetMetrics() {
	metrics.AllowedTotal.Store(0)
	metrics.BlockedTotal.Store(0)
	metrics.BlockedByIP.Store(0)
	metrics.BlockedByAPIKey.Store(0)
	metrics.BlockedByCooldown.Store(0)
}

// rateLimitBody is the JSON shape returned on 429 responses.
type rateLimitBody struct {
	Error        string `json:"error"`
	RetryAfterMs int64  `json:"retry_after_ms"`
}

// parse429Body decodes the JSON body of a 429 response.
func parse429Body(t *testing.T, resp *http.Response) rateLimitBody {
	t.Helper()
	defer resp.Body.Close()
	var body rateLimitBody
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode 429 body: %v", err)
	}
	return body
}

// ---------------------------------------------------------------------------
// Token-bucket math reference (for all tests below)
//
//   New bucket: tokens = burst, returned immediately WITHOUT consuming a token.
//   Subsequent requests: consume 1 token each (after refilling by elapsed*rate).
//
//   With burst=N, the allowed sequence per IP/key is:
//     request 1 → free (new bucket, tokens=N)
//     requests 2…N+1 → each consumes a token
//     request N+2 → tokens ≈ 0 → BLOCKED (reason "ip" or "api_key")
//   So total allowed before exhaustion = N + 1.
//
//   Hot-key cooldown triggers when ALL of:
//     nextAllowed (= windowCount + 1) > hotMul * rate
//     nextAllowed >= minHotSamples (= 50, hardcoded in shard.go)
//   With rate=10 and hotMul=3 → hotMul*rate=30 < 50, so minHotSamples binds.
//   Cooldown fires on the 51st total request (50th non-free):
//     request 1  → free, windowCount stays 0
//     requests 2…50 → windowCount 1→49
//     request 51 → nextAllowed=50 > 30 ✓ AND >= 50 ✓ → COOLDOWN
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Happy-path tests
// ---------------------------------------------------------------------------

// TestHappyPath verifies that a normal request is proxied to the upstream.
func TestHappyPath(t *testing.T) {
	shieldURL, cleanup := newStack(t, relaxedCfg, echoHandler(http.StatusOK, "hello"))
	defer cleanup()

	resp := doRequest(t, shieldURL, "/", "10.0.0.1", "")
	defer drainClose(resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
}

// TestUpstreamBodyPassthrough verifies the upstream response body reaches the client.
func TestUpstreamBodyPassthrough(t *testing.T) {
	const want = "pong"
	shieldURL, cleanup := newStack(t, relaxedCfg, echoHandler(http.StatusOK, want))
	defer cleanup()

	resp := doRequest(t, shieldURL, "/ping", "10.0.1.1", "")
	got := bodyString(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	if got != want {
		t.Fatalf("body: want %q, got %q", want, got)
	}
}

// TestUpstreamStatusPassthrough verifies non-200 upstream statuses are forwarded.
func TestUpstreamStatusPassthrough(t *testing.T) {
	shieldURL, cleanup := newStack(t, relaxedCfg, echoHandler(http.StatusNotFound, "not found"))
	defer cleanup()

	resp := doRequest(t, shieldURL, "/missing", "10.0.2.1", "")
	defer drainClose(resp)

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 from upstream, got %d", resp.StatusCode)
	}
}

// TestAPIKeyOptional verifies that requests without X-API-Key bypass key checking.
func TestAPIKeyOptional(t *testing.T) {
	shieldURL, cleanup := newStack(t, relaxedCfg, echoHandler(http.StatusOK, "ok"))
	defer cleanup()

	// No X-API-Key header → key check is skipped entirely.
	resp := doRequest(t, shieldURL, "/", "10.0.3.1", "")
	defer drainClose(resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200 (no key header → no key check), got %d", resp.StatusCode)
	}
}

// TestUpstreamUnavailable verifies a 502 Bad Gateway when the upstream is down.
func TestUpstreamUnavailable(t *testing.T) {
	// Start and immediately close a server to capture a dead address.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	u, _ := url.Parse(deadURL)
	rp := proxy.New(u, proxy.NewTransport(1, 500*time.Millisecond, 500*time.Millisecond))

	shield := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rp.ServeHTTP(w, r)
	}))
	defer shield.Close()

	resp := doRequest(t, shield.URL, "/", "10.0.4.1", "")
	defer drainClose(resp)

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("want 502, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// /metrics endpoint tests
// ---------------------------------------------------------------------------

// TestMetricsBypass verifies /metrics is never subject to rate limiting.
func TestMetricsBypass(t *testing.T) {
	// Extremely tight IP limit — /metrics must still return 200 every time.
	cfg := shieldConfig{ipRate: 1, ipBurst: 1, keyRate: 1, keyBurst: 1, hotMul: 3, cooldownSec: 30}
	shieldURL, cleanup := newStack(t, cfg, echoHandler(http.StatusOK, "ok"))
	defer cleanup()

	for i := 0; i < 10; i++ {
		resp := doRequest(t, shieldURL, "/metrics", "10.1.0.1", "")
		if resp.StatusCode != http.StatusOK {
			drainClose(resp)
			t.Fatalf("request %d: want 200 on /metrics, got %d", i+1, resp.StatusCode)
		}
		drainClose(resp)
	}
}

// TestMetricsFormat verifies Prometheus text format and the presence of all
// expected metric names.
func TestMetricsFormat(t *testing.T) {
	shieldURL, cleanup := newStack(t, relaxedCfg, echoHandler(http.StatusOK, "ok"))
	defer cleanup()

	resp := doRequest(t, shieldURL, "/metrics", "10.1.1.1", "")
	body := bodyString(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type: want text/plain prefix, got %q", ct)
	}

	wantMetrics := []string{
		"abuseshield_allowed_requests_total",
		"abuseshield_blocked_requests_total",
		"abuseshield_blocked_by_reason_total",
		"abuseshield_active_keys_count",
	}
	for _, m := range wantMetrics {
		if !strings.Contains(body, m) {
			t.Errorf("metrics body missing %q", m)
		}
	}
}

// TestActiveKeysCountInMetrics verifies that abuseshield_active_keys_count
// reflects tracked keys after traffic.
func TestActiveKeysCountInMetrics(t *testing.T) {
	shieldURL, cleanup := newStack(t, relaxedCfg, echoHandler(http.StatusOK, "ok"))
	defer cleanup()

	// Seed five unique IPs so the limiter tracks at least 5 buckets.
	for i := 1; i <= 5; i++ {
		doRequest(t, shieldURL, "/", fmt.Sprintf("10.1.2.%d", i), "").Body.Close()
	}

	resp := doRequest(t, shieldURL, "/metrics", "", "")
	body := bodyString(t, resp)

	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "abuseshield_active_keys_count ") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			t.Fatalf("unexpected gauge line format: %q", line)
		}
		count, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			t.Fatalf("parse active_keys_count: %v", err)
		}
		if count < 1 {
			t.Errorf("active_keys_count: want >= 1, got %d", count)
		}
		return
	}
	t.Fatal("active_keys_count gauge line not found in metrics output")
}

// ---------------------------------------------------------------------------
// IP rate-limit tests
// ---------------------------------------------------------------------------

// TestIPRateLimitExhausted verifies that IP token exhaustion produces a 429.
//
//	burst=3 → 4 allowed (1 free + 3 tokens), 5th request is blocked.
func TestIPRateLimitExhausted(t *testing.T) {
	cfg := shieldConfig{
		ipRate: 1, ipBurst: 3,
		keyRate: 1000, keyBurst: 2000,
		hotMul: 100, cooldownSec: 30, // high hotMul prevents cooldown
	}
	shieldURL, cleanup := newStack(t, cfg, echoHandler(http.StatusOK, "ok"))
	defer cleanup()

	const xff = "10.2.0.1"

	for i := 1; i <= 4; i++ {
		resp := doRequest(t, shieldURL, "/", xff, "")
		drainClose(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: want 200, got %d", i, resp.StatusCode)
		}
	}

	resp := doRequest(t, shieldURL, "/", xff, "")
	if resp.StatusCode != http.StatusTooManyRequests {
		drainClose(resp)
		t.Fatalf("request 5: want 429 on token exhaustion, got %d", resp.StatusCode)
	}
	body := parse429Body(t, resp)
	if body.Error != "rate_limit_exceeded" {
		t.Errorf("body.error: want %q, got %q", "rate_limit_exceeded", body.Error)
	}
}

// TestIPRateLimitReasonCounter verifies BlockedByIP counter increments.
func TestIPRateLimitReasonCounter(t *testing.T) {
	resetMetrics()
	cfg := shieldConfig{
		ipRate: 1, ipBurst: 1,
		keyRate: 1000, keyBurst: 2000,
		hotMul: 100, cooldownSec: 30,
	}
	shieldURL, cleanup := newStack(t, cfg, echoHandler(http.StatusOK, "ok"))
	defer cleanup()

	const xff = "10.2.1.1"
	// burst=1 → 2 allowed, 3rd blocked.
	doRequest(t, shieldURL, "/", xff, "").Body.Close()
	doRequest(t, shieldURL, "/", xff, "").Body.Close()
	resp := doRequest(t, shieldURL, "/", xff, "")
	drainClose(resp)

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", resp.StatusCode)
	}
	if metrics.BlockedByIP.Load() < 1 {
		t.Fatal("BlockedByIP counter not incremented")
	}
}

// TestXFFIPIsolation verifies that different X-Forwarded-For IPs have
// independent token buckets.
func TestXFFIPIsolation(t *testing.T) {
	cfg := shieldConfig{
		ipRate: 1, ipBurst: 2,
		keyRate: 1000, keyBurst: 2000,
		hotMul: 100, cooldownSec: 30,
	}
	shieldURL, cleanup := newStack(t, cfg, echoHandler(http.StatusOK, "ok"))
	defer cleanup()

	const ip1, ip2 = "10.2.2.1", "10.2.2.2"

	// burst=2 → 3 allowed per IP, then blocked.
	for i := 1; i <= 3; i++ {
		resp := doRequest(t, shieldURL, "/", ip1, "")
		drainClose(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("ip1 request %d: want 200, got %d", i, resp.StatusCode)
		}
	}

	// ip1 should now be exhausted.
	resp := doRequest(t, shieldURL, "/", ip1, "")
	drainClose(resp)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("ip1: want 429 (exhausted), got %d", resp.StatusCode)
	}

	// ip2 bucket is independent — first request must be allowed.
	resp = doRequest(t, shieldURL, "/", ip2, "")
	defer drainClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ip2: want 200 (independent bucket), got %d", resp.StatusCode)
	}
}

// TestXFFMultipleProxies verifies that the rightmost IP in a multi-hop
// X-Forwarded-For chain is used as the client identity.
// The leftmost entries are client-controlled and must not be trusted.
// The rightmost entry is appended by the trusted load balancer.
func TestXFFMultipleProxies(t *testing.T) {
	cfg := shieldConfig{
		ipRate: 1, ipBurst: 2,
		keyRate: 1000, keyBurst: 2000,
		hotMul: 100, cooldownSec: 30,
	}
	shieldURL, cleanup := newStack(t, cfg, echoHandler(http.StatusOK, "ok"))
	defer cleanup()

	// XFF chain: spoofed client IPs, rightmost appended by the load balancer.
	const xff = "9.9.9.9, 8.8.8.8, 10.2.3.3"

	// Exhaust the rightmost IP's bucket (3 allowed).
	for i := 1; i <= 3; i++ {
		resp := doRequest(t, shieldURL, "/", xff, "")
		drainClose(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: want 200, got %d", i, resp.StatusCode)
		}
	}

	// 4th request from the same chain should be blocked (rightmost IP exhausted).
	resp := doRequest(t, shieldURL, "/", xff, "")
	defer drainClose(resp)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("want 429 (rightmost IP exhausted), got %d", resp.StatusCode)
	}
}

// TestXFFSpoofedLeftmostIgnored verifies that a client cannot bypass rate
// limiting by rotating spoofed IPs in the leftmost XFF position.
// Only the rightmost entry (appended by the load balancer) is trusted.
func TestXFFSpoofedLeftmostIgnored(t *testing.T) {
	cfg := shieldConfig{
		ipRate: 1, ipBurst: 2,
		keyRate: 1000, keyBurst: 2000,
		hotMul: 100, cooldownSec: 30,
	}
	shieldURL, cleanup := newStack(t, cfg, echoHandler(http.StatusOK, "ok"))
	defer cleanup()

	// Rightmost IP is fixed (same LB-observed client). Leftmost rotates — must be ignored.
	const realIP = "10.2.4.1"

	// Exhaust the real IP's bucket (burst=2 → 3 allowed).
	for i := 1; i <= 3; i++ {
		xff := fmt.Sprintf("spoofed-%d.0.0.1, %s", i, realIP)
		resp := doRequest(t, shieldURL, "/", xff, "")
		drainClose(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: want 200, got %d", i, resp.StatusCode)
		}
	}

	// 4th request: new spoofed leftmost IP, same real IP — must still be blocked.
	xff := fmt.Sprintf("spoofed-999.0.0.1, %s", realIP)
	resp := doRequest(t, shieldURL, "/", xff, "")
	defer drainClose(resp)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("want 429 (spoofed leftmost ignored, real IP exhausted), got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// API key rate-limit tests
// ---------------------------------------------------------------------------

// TestAPIKeyRateLimitExhausted verifies that API key token exhaustion produces a 429.
func TestAPIKeyRateLimitExhausted(t *testing.T) {
	cfg := shieldConfig{
		ipRate: 1000, ipBurst: 2000,
		keyRate: 1, keyBurst: 3, // burst=3 → 4 allowed, 5th blocked
		hotMul: 100, cooldownSec: 30,
	}
	shieldURL, cleanup := newStack(t, cfg, echoHandler(http.StatusOK, "ok"))
	defer cleanup()

	const xff, apiKey = "10.3.0.1", "test-key-A"

	for i := 1; i <= 4; i++ {
		resp := doRequest(t, shieldURL, "/", xff, apiKey)
		drainClose(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: want 200, got %d", i, resp.StatusCode)
		}
	}

	resp := doRequest(t, shieldURL, "/", xff, apiKey)
	if resp.StatusCode != http.StatusTooManyRequests {
		drainClose(resp)
		t.Fatalf("request 5: want 429 on key exhaustion, got %d", resp.StatusCode)
	}
	drainClose(resp)
}

// TestAPIKeyReasonCounter verifies BlockedByAPIKey counter increments.
func TestAPIKeyReasonCounter(t *testing.T) {
	resetMetrics()
	cfg := shieldConfig{
		ipRate: 1000, ipBurst: 2000,
		keyRate: 1, keyBurst: 1,
		hotMul: 100, cooldownSec: 30,
	}
	shieldURL, cleanup := newStack(t, cfg, echoHandler(http.StatusOK, "ok"))
	defer cleanup()

	const xff, apiKey = "10.3.1.1", "test-key-B"
	// burst=1 → 2 allowed, 3rd blocked.
	doRequest(t, shieldURL, "/", xff, apiKey).Body.Close()
	doRequest(t, shieldURL, "/", xff, apiKey).Body.Close()
	resp := doRequest(t, shieldURL, "/", xff, apiKey)
	drainClose(resp)

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", resp.StatusCode)
	}
	if metrics.BlockedByAPIKey.Load() < 1 {
		t.Fatal("BlockedByAPIKey counter not incremented")
	}
}

// TestDifferentAPIKeysSeparateBuckets verifies that distinct API keys
// each get their own independent token bucket.
func TestDifferentAPIKeysSeparateBuckets(t *testing.T) {
	cfg := shieldConfig{
		ipRate: 1000, ipBurst: 2000,
		keyRate: 1, keyBurst: 2,
		hotMul: 100, cooldownSec: 30,
	}
	shieldURL, cleanup := newStack(t, cfg, echoHandler(http.StatusOK, "ok"))
	defer cleanup()

	const xff = "10.3.2.1"

	// Exhaust key-A (burst=2 → 3 allowed).
	for i := 1; i <= 3; i++ {
		resp := doRequest(t, shieldURL, "/", xff, "key-A")
		drainClose(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("key-A request %d: want 200, got %d", i, resp.StatusCode)
		}
	}
	resp := doRequest(t, shieldURL, "/", xff, "key-A")
	drainClose(resp)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("key-A: want 429 (exhausted), got %d", resp.StatusCode)
	}

	// key-B has its own fresh bucket — first request must be allowed.
	resp = doRequest(t, shieldURL, "/", xff, "key-B")
	defer drainClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("key-B: want 200 (independent bucket), got %d", resp.StatusCode)
	}
}

// TestIPKeyIndependence verifies that the IP limiter and key limiter are
// independent: an exhausted key blocks even when the IP has capacity.
func TestIPKeyIndependence(t *testing.T) {
	cfg := shieldConfig{
		ipRate: 1000, ipBurst: 2000, // IP limit never reached in this test
		keyRate: 1, keyBurst: 2,     // key exhausted after 3 requests
		hotMul: 100, cooldownSec: 30,
	}
	shieldURL, cleanup := newStack(t, cfg, echoHandler(http.StatusOK, "ok"))
	defer cleanup()

	const xff, apiKey = "10.3.3.1", "shared-key"

	for i := 1; i <= 3; i++ {
		resp := doRequest(t, shieldURL, "/", xff, apiKey)
		drainClose(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: want 200, got %d", i, resp.StatusCode)
		}
	}

	// IP bucket still has plenty of capacity; key bucket is exhausted.
	resp := doRequest(t, shieldURL, "/", xff, apiKey)
	defer drainClose(resp)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("want 429 (key exhausted, IP fine), got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Hot-key cooldown tests
// ---------------------------------------------------------------------------

// TestHotKeyIPCooldown verifies that an IP sending >= 50 requests in 1 second
// is put into cooldown and receives 429 with reason "cooldown".
//
// Cooldown trigger (from shard.go):
//
//	nextAllowed > hotMul*rate  (30 with rate=10, hotMul=3)
//	nextAllowed >= minHotSamples  (50, hardcoded)
//
// Because 30 < 50, minHotSamples is the binding constraint.
// Requests 1–50 are allowed; the 51st fires cooldown.
func TestHotKeyIPCooldown(t *testing.T) {
	cfg := shieldConfig{
		ipRate: 10, ipBurst: 60, // enough burst for 50 requests before token exhaustion
		keyRate: 1000, keyBurst: 2000,
		hotMul: 3, cooldownSec: 30,
	}
	shieldURL, cleanup := newStack(t, cfg, echoHandler(http.StatusOK, "ok"))
	defer cleanup()

	const xff = "10.4.0.1"

	for i := 1; i <= 50; i++ {
		resp := doRequest(t, shieldURL, "/", xff, "")
		drainClose(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: want 200 before cooldown, got %d", i, resp.StatusCode)
		}
	}

	// 51st request must trigger cooldown.
	resp := doRequest(t, shieldURL, "/", xff, "")
	if resp.StatusCode != http.StatusTooManyRequests {
		drainClose(resp)
		t.Fatalf("request 51: want 429 (cooldown), got %d", resp.StatusCode)
	}
	body := parse429Body(t, resp)
	if body.Error != "rate_limit_exceeded" {
		t.Errorf("body.error: want %q, got %q", "rate_limit_exceeded", body.Error)
	}
	if body.RetryAfterMs <= 0 {
		t.Errorf("retry_after_ms: want > 0, got %d", body.RetryAfterMs)
	}
}

// TestHotKeyIPCooldownCounter verifies BlockedByCooldown is incremented for IP.
func TestHotKeyIPCooldownCounter(t *testing.T) {
	resetMetrics()
	cfg := shieldConfig{
		ipRate: 10, ipBurst: 60,
		keyRate: 1000, keyBurst: 2000,
		hotMul: 3, cooldownSec: 30,
	}
	shieldURL, cleanup := newStack(t, cfg, echoHandler(http.StatusOK, "ok"))
	defer cleanup()

	const xff = "10.4.1.1"
	for i := 0; i < 50; i++ {
		doRequest(t, shieldURL, "/", xff, "").Body.Close()
	}
	resp := doRequest(t, shieldURL, "/", xff, "") // must hit cooldown
	drainClose(resp)

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", resp.StatusCode)
	}
	if metrics.BlockedByCooldown.Load() < 1 {
		t.Fatal("BlockedByCooldown counter not incremented")
	}
}

// TestHotKeyAPIKeyCooldown verifies hot-key cooldown is enforced for API keys.
func TestHotKeyAPIKeyCooldown(t *testing.T) {
	cfg := shieldConfig{
		ipRate: 1000, ipBurst: 2000,
		keyRate: 10, keyBurst: 60,
		hotMul: 3, cooldownSec: 30,
	}
	shieldURL, cleanup := newStack(t, cfg, echoHandler(http.StatusOK, "ok"))
	defer cleanup()

	const xff, apiKey = "10.4.2.1", "hot-key"

	for i := 1; i <= 50; i++ {
		resp := doRequest(t, shieldURL, "/", xff, apiKey)
		drainClose(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: want 200 before cooldown, got %d", i, resp.StatusCode)
		}
	}

	resp := doRequest(t, shieldURL, "/", xff, apiKey)
	defer drainClose(resp)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("request 51: want 429 (key cooldown), got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// 429 response shape tests
// ---------------------------------------------------------------------------

// TestRateLimitResponseHeaders verifies that a 429 carries the correct
// Content-Type and a valid integer Retry-After header.
func TestRateLimitResponseHeaders(t *testing.T) {
	cfg := shieldConfig{
		ipRate: 1, ipBurst: 1,
		keyRate: 1000, keyBurst: 2000,
		hotMul: 100, cooldownSec: 30,
	}
	shieldURL, cleanup := newStack(t, cfg, echoHandler(http.StatusOK, "ok"))
	defer cleanup()

	const xff = "10.5.0.1"
	// burst=1 → 2 allowed, 3rd blocked.
	doRequest(t, shieldURL, "/", xff, "").Body.Close()
	doRequest(t, shieldURL, "/", xff, "").Body.Close()
	resp := doRequest(t, shieldURL, "/", xff, "")
	defer drainClose(resp)

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type: want application/json, got %q", ct)
	}
	ra := resp.Header.Get("Retry-After")
	if ra == "" {
		t.Fatal("Retry-After header is missing")
	}
	secs, err := strconv.ParseInt(ra, 10, 64)
	if err != nil {
		t.Fatalf("Retry-After is not an integer: %q", ra)
	}
	if secs < 1 {
		t.Errorf("Retry-After: want >= 1s, got %d", secs)
	}
}

// TestRetryAfterMsPositive verifies that retry_after_ms in the JSON body is > 0.
func TestRetryAfterMsPositive(t *testing.T) {
	cfg := shieldConfig{
		ipRate: 1, ipBurst: 1,
		keyRate: 1000, keyBurst: 2000,
		hotMul: 100, cooldownSec: 30,
	}
	shieldURL, cleanup := newStack(t, cfg, echoHandler(http.StatusOK, "ok"))
	defer cleanup()

	const xff = "10.5.1.1"
	doRequest(t, shieldURL, "/", xff, "").Body.Close()
	doRequest(t, shieldURL, "/", xff, "").Body.Close()
	resp := doRequest(t, shieldURL, "/", xff, "")

	body := parse429Body(t, resp)
	if body.RetryAfterMs < 1 {
		t.Errorf("retry_after_ms: want >= 1, got %d", body.RetryAfterMs)
	}
}

// ---------------------------------------------------------------------------
// Metrics counter integration tests
// ---------------------------------------------------------------------------

// TestMetricsCountersIncrement verifies that AllowedTotal and BlockedTotal
// accurately reflect traffic through the shield.
func TestMetricsCountersIncrement(t *testing.T) {
	resetMetrics()
	cfg := shieldConfig{
		ipRate: 1, ipBurst: 2,
		keyRate: 1000, keyBurst: 2000,
		hotMul: 100, cooldownSec: 30,
	}
	shieldURL, cleanup := newStack(t, cfg, echoHandler(http.StatusOK, "ok"))
	defer cleanup()

	const xff = "10.6.0.1"

	// burst=2 → 3 allowed, then blocked.
	for i := 0; i < 3; i++ {
		doRequest(t, shieldURL, "/", xff, "").Body.Close()
	}
	doRequest(t, shieldURL, "/", xff, "").Body.Close() // 4th → blocked

	if got := metrics.AllowedTotal.Load(); got < 3 {
		t.Errorf("AllowedTotal: want >= 3, got %d", got)
	}
	if got := metrics.BlockedTotal.Load(); got < 1 {
		t.Errorf("BlockedTotal: want >= 1, got %d", got)
	}
}
