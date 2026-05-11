# AbuseShield

A high-performance API Security Proxy written in Go. Sits between a Load Balancer and a Backend to detect and block **onboarding abuse** — fake signups, bot-driven registration flows, and scripted account creation.

Zero external dependencies. Sub-millisecond decision latency.

---

## How It Works

Every request is fingerprinted into an **EntityID** (IP/24 + User-Agent) and passed through two detection layers before being forwarded:

- **L1** — token-bucket rate limiter + burst-window detection per entity
- **L2** — signup funnel sequence check (`/home` → `/register`)

Detections are emitted as JSON **SecurityEvents** to stdout. In **shadow mode** (default) every request is still forwarded — you observe the signal before enabling enforcement.

---

## Quick Start

### Prerequisites

- Go 1.22+

### Build

```bash
git clone https://github.com/adva-mo/abuseShield.git
cd AbuseShield
go build -o abuseshield ./cmd/abuseshield/
```

### Configure

```bash
cp config.example.json config.json
```

Then edit `config.json`:

- Set `upstream_url` to your backend
- Set `kill_switch_secret` to a strong random value
- Leave `shadow_mode: true` until you're confident in the signal quality

### Run

```bash
./abuseshield -config config.json
```

#### Try it locally

To simulate traffic against a mock backend:

**Terminal 1** — mock upstream (accepts all HTTP methods, always returns 200)

```bash
python3 scripts/mock_upstream.py
```

**Terminal 2** — AbuseShield

```bash
./abuseshield -config config.json 2>&1 | tee /tmp/shield.log
```

**Terminal 3** — simulate bot and real-user flows

```bash
python3 scripts/test_abuse.py
```

The script runs four flows against AbuseShield and prints a live metrics summary at the end:

- **Flow A** — single bot entity fires 100 concurrent `POST /register` (20 workers). Expect `SUSPICIOUS` (sequence_violation) on the first few, then `BLOCK` (burst_detected) once the token bucket empties.
- **Flow B** — 8 distinct bot IPs × 15 requests each, all concurrent. Each entity trips burst detection independently, verifying per-entity sharding.
- **Flow C** — real user: `GET /home` → 1.5 s pause → `POST /register`. Both requests should be `ALLOW`.
- **Flow D** *(optional)* — kill-switch toggle. Pass `--kill-switch` to enable this flow.

Inspect SecurityEvent logs:

```bash
python3 scripts/print_events.py /tmp/shield.log
```

### Test

Run the full test suite (includes race detector):

```bash
go test -race ./...
```

Run only the end-to-end suite:

```bash
go test -race ./test/e2e/
```

The e2e suite spins up a real AbuseShield + upstream stack via `httptest` and covers: request proxying, IP rate limiting, XFF extraction and spoofing, API key limiting, hot-key cooldown, 429 response shape, and metrics counter accuracy — no mocks, no stubs.

---

## Configuration Reference

Copy `config.example.json` to `config.json`. All fields have safe defaults.

| Field | Default | Description |
|---|---|---|
| `listen_addr` | `8080` | Address AbuseShield listens on |
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
| `funnel_gate` | `"/home"` | L2: path the user must visit first |
| `funnel_target` | `"/register"` | L2: protected path — triggers `sequence_violation` if gate was not seen |

---

## Admin Endpoints

### Kill-Switch

Immediately disables all detection. Requests pass through without any checks. No SecurityEvents are logged while active.

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

## Deployment Notes

- AbuseShield is designed to sit **behind a trusted Load Balancer** that sets `X-Forwarded-For`. The proxy reads the rightmost XFF entry as the client IP.
- The binary has **no external dependencies** — deploy as a single static binary.
- SecurityEvents are written to **stdout as JSON lines**. Pipe to your log aggregator (`| fluentd`, `| vector`, etc.).
- `config.json` may contain `kill_switch_secret` — **never commit it**. Use `config.example.json` as the template.

---

## License

MIT
