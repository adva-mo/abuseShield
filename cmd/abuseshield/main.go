package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/adva-mo/abuseShield/internal/config"
	"github.com/adva-mo/abuseShield/internal/engine"
	"github.com/adva-mo/abuseShield/internal/limiter"
	"github.com/adva-mo/abuseShield/internal/metrics"
	"github.com/adva-mo/abuseShield/internal/middleware"
	"github.com/adva-mo/abuseShield/internal/proxy"
)

func main() {
	configPath := flag.String("config", "config.json", "path to config file")
	flag.Parse()

	cfg, derived, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	upstream, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		log.Fatalf("invalid upstream_url: %v", err)
	}

	// --- Existing IP/API-key rate limiter (L0 protection, unchanged) ---
	l := limiter.New(
		cfg.IPRatePerSec,
		cfg.IPBurst,
		cfg.KeyRatePerSec,
		cfg.KeyBurst,
		cfg.HotKeyMultiplier,
		derived.Cooldown,
	)
	l.StartEviction(derived.EvictionInterval)

	// --- Reverse proxy ---
	transport := proxy.NewTransport(
		cfg.MaxIdleConnsPerHost,
		derived.DialTimeout,
		derived.TLSTimeout,
	)
	rp := proxy.New(upstream, transport)

	// --- Abuse detection engine ---
	store := engine.NewStore()

	// Use a context tied to process lifetime for the eviction goroutine.
	evictCtx, evictCancel := context.WithCancel(context.Background())
	defer evictCancel()
	store.StartEviction(evictCtx, derived.EvictionInterval)

	// SecurityEvent logger writes JSON lines to stdout.
	evLogger := engine.NewLogger(cfg.EventBufferSize, os.Stdout)

	// Kill-switch: initialized from config (normally false).
	var killSwitch atomic.Bool
	killSwitch.Store(cfg.KillSwitch)

	// --- Build inner handler: existing L0 rate limiter → reverse proxy ---
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now().UnixNano()
		clientIP := proxy.ExtractClientIP(r)

		ipDecision := l.CheckIP(clientIP, now)
		if !ipDecision.Allowed {
			metrics.BlockedTotal.Add(1)
			switch ipDecision.Reason {
			case "cooldown":
				metrics.BlockedByCooldown.Add(1)
			case "ip":
				metrics.BlockedByIP.Add(1)
			}
			proxy.WriteRateLimitResponse(w, ipDecision.RetryAfterMs)
			return
		}

		if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
			keyDecision := l.CheckKey(apiKey, now)
			if !keyDecision.Allowed {
				metrics.BlockedTotal.Add(1)
				switch keyDecision.Reason {
				case "cooldown":
					metrics.BlockedByCooldown.Add(1)
				case "api_key":
					metrics.BlockedByAPIKey.Add(1)
				}
				proxy.WriteRateLimitResponse(w, keyDecision.RetryAfterMs)
				return
			}
		}

		metrics.AllowedTotal.Add(1)
		rp.ServeHTTP(w, r)
	})

	// --- Abuse detection interceptor wraps the inner handler ---
	interceptor := middleware.New(
		innerHandler,
		store,
		evLogger,
		middleware.InterceptorConfig{
			RatePerSec:        cfg.EntityRatePerSec,
			Burst:             cfg.EntityBurst,
			BurstWindowNs:     derived.EntityBurstWindow.Nanoseconds(),
			ShadowMode:        *cfg.ShadowMode,
			BlockOnSuspicious: cfg.BlockOnSuspicious,
		},
		&killSwitch,
	)

	// --- HTTP mux ---
	mux := http.NewServeMux()

	// /metrics bypasses all detection and rate limiting.
	mux.Handle("/metrics", metrics.Handler(metrics.Sources{
		ActiveLimiterKeys: l.ActiveKeysCount,
		ActiveEntities:    store.ActiveCount,
	}))

	// Kill-switch control endpoint.
	mux.Handle("/admin/kill-switch", killSwitchHandler(&killSwitch, cfg.KillSwitchSecret))

	// All other paths flow through the abuse detection interceptor.
	mux.Handle("/", interceptor)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: derived.ReadHeaderTimeout,
		WriteTimeout:      derived.WriteTimeout,
		MaxHeaderBytes:    1 << 16, // 64 KB
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		log.Printf("AbuseShield listening on %s → %s (shadow_mode=%v, kill_switch=%v)",
			cfg.ListenAddr, cfg.UpstreamURL, *cfg.ShadowMode, cfg.KillSwitch)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	<-quit
	log.Println("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown error: %v", err)
	}

	// Flush remaining SecurityEvents before exit.
	evictCancel()
	evLogger.Close()
	log.Println("stopped")
}

// killSwitchHandler handles POST /admin/kill-switch?enable=true|false.
// Requires the X-Kill-Switch-Secret header to match the configured secret.
func killSwitchHandler(ks *atomic.Bool, secret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("X-Kill-Switch-Secret") != secret {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		enable := r.URL.Query().Get("enable") == "true"
		ks.Store(enable)
		log.Printf("[AbuseShield] kill switch set to %v by admin request", enable)
		w.WriteHeader(http.StatusOK)
	}
}
