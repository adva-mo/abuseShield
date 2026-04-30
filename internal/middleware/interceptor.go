package middleware

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/adva-mo/abuseShield/internal/engine"
	"github.com/adva-mo/abuseShield/internal/proxy"
)

// InterceptorConfig carries the engine parameters needed by the Interceptor.
// Populated from config.Config by main.go.
type InterceptorConfig struct {
	RatePerSec         float64
	Burst              float64
	BurstWindowNs      int64
	ShadowMode         bool
	BlockOnSuspicious  bool // if true, SUSPICIOUS decisions also block (non-shadow mode only)
}

// Interceptor wraps an inner http.Handler (the reverse proxy + existing rate
// limiter) with the onboarding-abuse detection pipeline.
//
// Request flow:
//  1. Kill-switch check (atomic load; branch-predicted not-taken in normal ops)
//  2. ExtractClientIP
//  3. Compute EntityID from IP/24 + User-Agent
//  4. L1: token-bucket rate limit + burst-window detection
//  5. L2: /home → /register sequence check
//  6. Merge decisions (L1 outranks L2)
//  7. Emit SecurityEvent asynchronously (non-blocking)
//  8. If NOT shadow mode AND decision == "BLOCK": return 403, done
//  9. Forward to inner handler
type Interceptor struct {
	inner      http.Handler
	store      *engine.Store
	logger     *engine.Logger
	cfg        InterceptorConfig
	killSwitch *atomic.Bool

	// suppressUntil gates kill-switch log spam: only log once per 5 seconds.
	suppressUntil atomic.Int64
}

// New creates an Interceptor.
func New(
	inner http.Handler,
	store *engine.Store,
	logger *engine.Logger,
	cfg InterceptorConfig,
	killSwitch *atomic.Bool,
) *Interceptor {
	return &Interceptor{
		inner:      inner,
		store:      store,
		logger:     logger,
		cfg:        cfg,
		killSwitch: killSwitch,
	}
}

// ServeHTTP implements http.Handler. This is the hot path.
func (i *Interceptor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Kill-switch: bypass all detection, pass everything through.
	if i.killSwitch.Load() {
		now := time.Now().UnixNano()
		if now > i.suppressUntil.Load() {
			log.Println("[AbuseShield] kill switch ACTIVE — detection bypassed")
			i.suppressUntil.Store(now + 5_000_000_000) // suppress for 5 seconds
		}
		i.inner.ServeHTTP(w, r)
		return
	}

	now := time.Now().UnixNano()

	// 2. Extract real client IP (reuses existing proxy package logic).
	clientIP := proxy.ExtractClientIP(r)

	// 3. Compute EntityID from IP/24 + User-Agent.
	ua := r.Header.Get("User-Agent")
	entityID := engine.Compute(clientIP, ua)
	entityKey := entityID.String()

	// 4. L1: rate-limit + burst detection.
	l1 := engine.CheckL1(i.store, entityKey, i.cfg.RatePerSec, i.cfg.Burst, i.cfg.BurstWindowNs, now)

	// 5. L2: sequence check on normalized path.
	path := strings.TrimRight(r.URL.Path, "/")
	if path == "" {
		path = "/"
	}
	l2 := engine.CheckL2(i.store, entityKey, path, now)

	// 6. Collect all fired signals and derive the primary decision.
	decision, reason, confidence, signals := mergeDecisions(l1, l2)

	// 7. Build the SecurityEvent. Blocked is set after we know enforcement outcome.
	ip24 := ip24CIDR(clientIP)
	shouldBlock := decision == "BLOCK" || (decision == "SUSPICIOUS" && i.cfg.BlockOnSuspicious)
	blocked := !i.cfg.ShadowMode && shouldBlock

	i.logger.Emit(engine.SecurityEvent{
		Timestamp:  time.Unix(0, now).UTC().Format(time.RFC3339Nano),
		EntityID:   entityKey,
		IP:         ip24,
		UserAgent:  ua,
		Path:       r.URL.Path,
		Method:     r.Method,
		Decision:   decision,
		Reason:     reason,
		Confidence: confidence,
		Signals:    signals,
		ShadowMode: i.cfg.ShadowMode,
		Blocked:    blocked,
	})

	if blocked {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":  "request blocked",
			"reason": reason,
		})
		return
	}

	// 9. Forward to inner handler (existing IP/key rate limiter → reverse proxy).
	i.inner.ServeHTTP(w, r)
}

// mergeDecisions combines L1 and L2 results into a primary decision plus the
// full list of fired signals. L1 BLOCK outranks L2 SUSPICIOUS; both outrank
// a clean ALLOW. Signals includes every non-clean result so the caller sees
// all contributing factors even when a higher-priority signal dominates.
func mergeDecisions(l1 engine.L1Result, l2 engine.L2Result) (decision, reason string, confidence float64, signals []engine.Signal) {
	// Collect every fired signal, ordered by priority (L1 first).
	if !l1.Allowed {
		signals = append(signals, engine.Signal{
			Layer:      "L1",
			Reason:     l1.Reason,
			Confidence: l1.Confidence,
		})
	}
	if l2.Suspicious {
		signals = append(signals, engine.Signal{
			Layer:      "L2",
			Reason:     l2.Reason,
			Confidence: l2.Confidence,
		})
	}

	// Primary decision = highest-priority signal.
	if !l1.Allowed {
		return "BLOCK", l1.Reason, l1.Confidence, signals
	}
	if l2.Suspicious {
		return "SUSPICIOUS", l2.Reason, l2.Confidence, signals
	}
	return "ALLOW", "", 1.0, nil
}

// ip24CIDR converts "192.168.1.100" to "192.168.1.0/24" for log readability.
// For IPv6 or strings without a final dot, returns ip+"/?" as a fallback.
func ip24CIDR(ip string) string {
	for i := len(ip) - 1; i >= 0; i-- {
		if ip[i] == '.' {
			return ip[:i] + ".0/24"
		}
	}
	return ip + "/??"
}
