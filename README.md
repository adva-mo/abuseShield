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
cd abuseShield
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

Inspect live metrics:

```bash
python3 scripts/print_metrics.py
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

Copy `config.example.json` to `config.json`. All fields have safe defaults — the only required field is `upstream_url`.

### General

| Field | Default | Description |
|---|---|---|
| `listen_addr` | `:8080` | Address and port AbuseShield listens on (e.g. `":8080"` or `"0.0.0.0:8080"`) |
| `upstream_url` | — | **Required.** Full URL of the backend to proxy to (e.g. `"http://api:3000"`) |

### Detection Behavior

| Field | Default | Description |
|---|---|---|
| `shadow_mode` | `true` | When `true`, detections are logged as SecurityEvents but nothing is blocked — all requests are forwarded. Disable once you are confident in signal quality. |
| `block_on_suspicious` | `false` | When `true`, requests flagged SUSPICIOUS (e.g. sequence_violation) are also blocked, not just logged. Has no effect in shadow mode. |
| `kill_switch` | `false` | Start with the kill switch active — skips all detection and proxies everything. Normally toggled at runtime via the admin endpoint. |
| `kill_switch_secret` | — | Shared secret that authenticates `POST /admin/kill-switch` requests. Set a strong random value; never commit it. |
| `event_buffer_size` | `1000` | Depth of the async SecurityEvent log buffer. Increase if you see `events_dropped` in metrics under high traffic. |

### L1 — Per-Entity Rate & Burst Detection

Each entity is a fingerprint of IP/24 + User-Agent. L1 fires when an entity exceeds its token bucket or hammers the server in a short window.

| Field | Default | Description |
|---|---|---|
| `entity_rate_per_sec` | `2.5` | Sustained request rate allowed per entity (tokens refilled per second). |
| `entity_burst` | `5` | Maximum burst an entity can send before L1 fires. Lower values are stricter. |
| `entity_burst_window_sec` | `2.0` | Time window (seconds) used to measure burst. Requests beyond `entity_burst` within this window trigger `burst_detected`. |

### L2 — Signup Funnel Sequence

L2 checks that clients follow the expected navigation order. Hitting the target without first visiting the gate is a strong bot signal.

Once an entity visits the gate, it is considered "seen" for up to 5 minutes of inactivity — after that the entity is evicted and the check resets. Entities that do visit the gate but then flood the target are caught by L1, not L2; the two layers are complementary.

| Field | Default | Description |
|---|---|---|
| `funnel_gate` | `"/home"` | Path the client must visit before the target (e.g. a landing page). |
| `funnel_target` | `"/register"` | Protected path. A direct hit without a prior gate visit triggers `sequence_violation`. Must differ from `funnel_gate`. |

### L0 — IP and API Key Rate Limits

Hard per-IP and per-key limits enforced before requests reach the detection engine. Skipped in shadow mode.

| Field | Default | Description |
|---|---|---|
| `ip_rate_per_sec` | `10` | Sustained request rate allowed per IP (tokens refilled per second). |
| `ip_burst` | `20` | Maximum burst per IP before a 429 is returned. |
| `key_rate_per_sec` | `100` | Sustained request rate allowed per API key (`X-API-Key` header). |
| `key_burst` | `200` | Maximum burst per API key before a 429 is returned. |
| `hot_key_multiplier` | `3.0` | An IP or key that sustains more than `multiplier × rate_per_sec` requests per second is put into cooldown and locked out for `cooldown_seconds`. |
| `cooldown_seconds` | `60` | How long a hot IP or key is locked out (all requests return 429) after triggering the hot-key threshold. |

### Allowlist — Trusted Sources

Requests matching any allowlist entry bypass L0, L1, and L2 entirely and go straight to the upstream.

| Field | Default | Description |
|---|---|---|
| `allowlist.ips` | `[]` | Exact IPs or CIDR ranges that are always trusted (e.g. `"10.0.0.0/8"`, `"192.168.1.50"`). |
| `allowlist.paths` | `[]` | Path prefixes that are always trusted (e.g. `"/health"` also covers `"/health/check"`). |
| `allowlist.api_keys` | `[]` | API keys (`X-API-Key` header) that are always trusted. |

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

Prometheus-compatible plaintext metrics endpoint. Bypasses all rate limiting and detection. Point your Prometheus scraper here:

```yaml
# prometheus.yml
- job_name: abuseshield
  static_configs:
    - targets: ["localhost:8080"]
  metrics_path: /metrics
```

For human-readable output during local testing, use the included script instead:

```bash
python3 scripts/print_metrics.py
```

---

## Deployment Notes

- Use `allowlist.ips` for trusted internal services or monitoring agents that should never be rate-limited or inspected. Supports exact IPs and CIDR ranges.
- Use `allowlist.paths` for health-check or internal endpoints (e.g. `/health`, `/internal/`). Prefix-matched, so `/health` covers `/health/check` too.
- Use `allowlist.api_keys` for internal service-to-service calls that carry a known key. Allowlisted requests skip L0, L1, and L2 entirely and go straight to the upstream.
- AbuseShield is designed to sit **behind a trusted Load Balancer** that sets `X-Forwarded-For`. The proxy reads the rightmost XFF entry as the client IP.
- The binary has **no external dependencies** — deploy as a single static binary.
- SecurityEvents are written to **stdout as JSON lines**. Pipe to your log aggregator (`| fluentd`, `| vector`, etc.).
- `config.json` may contain `kill_switch_secret` — **never commit it**. Use `config.example.json` as the template.

---

## License

MIT
