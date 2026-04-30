# AbuseShield

A high-performance API Security Proxy written in Go. Sits between a Load Balancer and a Backend to detect and block **onboarding abuse** — fake signups, bot-driven registration flows, and scripted account creation.

Zero external dependencies. Sub-millisecond decision latency.

---

## How It Works

Every request passes through a multi-layer detection pipeline before being forwarded to the upstream:

```
Request
  │
  ├─ Kill-switch?          → bypass all detection, forward
  │
  ├─ L0: IP rate limiter   → 429 if IP exceeds token bucket
  ├─ L0: API key limiter   → 429 if key exceeds token bucket
  │
  ├─ L1: Entity rate+burst → BLOCK  (burst_detected / rate_limited)
  ├─ L2: Sequence check    → SUSPICIOUS (sequence_violation / velocity_violation /
  │                                       repeated_registration / funnel_expired)
  │
  ├─ SecurityEvent logged  → JSON line to stdout (async, non-blocking)
  │
  └─ Forward to upstream   (always in shadow mode; blocked in enforcement mode)
```

### Detection Layers

| Layer | Signal | Description | Confidence |
|---|---|---|---|
| L1 | `burst_detected` | Entity exceeds burst capacity within the window | 0.95 |
| L1 | `rate_limited` | Entity token bucket exhausted (sustained drip) | 0.90 |
| L2 | `sequence_violation` | `/register` hit without a prior `/home` visit | 0.70 |
| L2 | `velocity_violation` | `/home` → `/register` faster than human-possible | 0.85 |
| L2 | `repeated_registration` | Entity hit `/register` more than the allowed count | 0.75 |
| L2 | `funnel_expired` | Prior `/home` visit expired before `/register` arrived | 0.65 |

### Shadow Mode (default: on)

In shadow mode every request is **forwarded to the upstream regardless of decision**. SecurityEvents are still logged. This lets you observe the detection engine in production before enabling enforcement.

Set `"shadow_mode": false` in config to enable blocking.

---

## Quick Start

### Prerequisites

- Go 1.22+
- Python 3.6+ (for test scripts only)

### Build

```bash
git clone https://github.com/your-org/AbuseShield.git
cd AbuseShield
go build -o abuseshield ./cmd/abuseshield/
```

### Configure

```bash
cp config.example.json config.json
# Edit config.json:
#   - Set upstream_url to your backend
#   - Set kill_switch_secret to a strong random value
#   - Leave shadow_mode: true until you're confident in the signal quality
```

### Run

```bash
# Terminal 1 — mock upstream (or point to your real backend)
python3 -m http.server 9090

# Terminal 2 — AbuseShield
./abuseshield -config config.json 2>&1 | tee /tmp/shield.log

# Terminal 3 — simulate traffic
python3 scripts/test_abuse.py

# Inspect SecurityEvent logs
python3 scripts/print_events.py /tmp/shield.log
```

---

## Configuration Reference

Copy `config.example.json` to `config.json`. All fields have safe defaults.

| Field | Default | Description |
|---|---|---|
| `listen_addr` | `:8080` | Address AbuseShield listens on |
| `upstream_url` | — | **Required.** Backend to proxy to |
| `shadow_mode` | `true` | Log detections without blocking |
| `block_on_suspicious` | `false` | Also block SUSPICIOUS decisions (not just BLOCK) |
| `kill_switch` | `false` | Start with kill-switch active |
| `kill_switch_secret` | — | Secret for `POST /admin/kill-switch` |
| `entity_rate_per_sec` | `2.5` | L1 token refill rate per entity |
| `entity_burst` | `5` | L1 max burst tokens per entity |
| `entity_burst_window_sec` | `2.0` | Window for burst detection (seconds) |
| `ip_rate_per_sec` | `10` | L0 token refill rate per IP |
| `ip_burst` | `20` | L0 max burst per IP |
| `event_buffer_size` | `1000` | Async SecurityEvent log buffer depth |

---

## SecurityEvent Log Format

Every request emits one JSON line to stdout:

```json
{
  "timestamp": "2026-03-30T16:11:51.477Z",
  "entity_id": "a3f2b1c4d5e6f708",
  "ip": "198.51.100.0/24",
  "user_agent": "python-bot/1.0",
  "path": "/register",
  "method": "POST",
  "decision": "BLOCK",
  "reason": "burst_detected",
  "confidence": 0.95,
  "signals": [
    { "layer": "L1", "reason": "burst_detected",    "confidence": 0.95 },
    { "layer": "L2", "reason": "sequence_violation", "confidence": 0.70 }
  ],
  "shadow_mode": false,
  "blocked": true
}
```

`signals` contains **all** detection rules that fired. `decision` and `reason` reflect the highest-priority signal. `blocked: true` means the request was rejected with HTTP 403 and **not forwarded** to the upstream.

---

## Admin Endpoints

### Kill-Switch

Immediately disables all detection. Requests pass through without any L1/L2 checks. No SecurityEvents are logged while active.

```bash
# Enable
curl -X POST "http://localhost:8080/admin/kill-switch?enable=true" \
     -H "X-Kill-Switch-Secret: your-secret"

# Disable
curl -X POST "http://localhost:8080/admin/kill-switch?enable=false" \
     -H "X-Kill-Switch-Secret: your-secret"
```

### Metrics

Prometheus-compatible plaintext metrics. Bypasses all rate limiting and detection.

```bash
curl http://localhost:8080/metrics
```

---

## Architecture

```
cmd/abuseshield/main.go       Entry point, HTTP server, graceful shutdown
internal/
  config/config.go            JSON config loader with defaults
  engine/
    entity.go                 EntityID: FNV-1a64(ip/24 + UA + TLS placeholder)
    state.go                  256-shard entity state map (cache-line padded)
    l1.go                     Token bucket + burst-window detection
    l2.go                     Sequence / velocity / repeat detection
    events.go                 SecurityEvent struct + async JSON logger
  middleware/
    interceptor.go            HTTP handler: kill-switch → L1 → L2 → log → proxy
  limiter/                    L0 IP + API key token bucket (sharded, 256 shards)
  metrics/metrics.go          Prometheus counters (atomic, zero-alloc hot path)
  proxy/proxy.go              httputil.ReverseProxy wrapper + IP extraction
scripts/
  test_abuse.py               Simulate fake signup vs real user flows
  print_events.py             Pretty-print SecurityEvent JSON lines
```

**Entity fingerprinting:** `FNV-1a64(ip/24 prefix | User-Agent | tls_fp_placeholder)` — zero heap allocations, 256-shard map with cache-line padding to prevent false sharing.

---

## Development

```bash
# Build
go build ./...

# Vet
go vet ./...

# Tests (with race detector)
go test -race ./...

# Benchmarks (limiter hot path)
go test -bench=BenchmarkAllowDistributedKeys -benchtime=10s ./internal/limiter/
```

---

## Deployment Notes

- AbuseShield is designed to sit **behind a trusted Load Balancer** that sets `X-Forwarded-For`. The proxy reads the leftmost XFF entry as the client IP.
- The binary has **no external dependencies** — deploy as a single static binary.
- SecurityEvents are written to **stdout as JSON lines**. Pipe to your log aggregator (`| fluentd`, `| vector`, etc.).
- `config.json` may contain `kill_switch_secret` — **never commit it**. Use `config.example.json` as the template.

---

## License

MIT
