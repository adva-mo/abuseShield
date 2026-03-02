package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/abuseshield/lite/internal/config"
	"github.com/abuseshield/lite/internal/limiter"
	"github.com/abuseshield/lite/internal/metrics"
	"github.com/abuseshield/lite/internal/proxy"
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

	// Build rate limiter.
	l := limiter.New(
		cfg.IPRatePerSec,
		cfg.IPBurst,
		cfg.KeyRatePerSec,
		cfg.KeyBurst,
		cfg.HotKeyMultiplier,
		derived.CooldownNs,
	)
	l.StartEviction(derived.EvictionInterval)

	// Build reverse proxy.
	transport := proxy.NewTransport(
		cfg.MaxIdleConnsPerHost,
		derived.DialTimeout,
		derived.TLSTimeout,
	)
	rp := proxy.New(upstream, transport)

	// Build HTTP mux.
	mux := http.NewServeMux()

	// /metrics bypasses rate limiting.
	mux.Handle("/metrics", metrics.Handler(l.ActiveKeysCount))

	// All other paths go through the rate limiter then the reverse proxy.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		now := time.Now().UnixNano()

		// Extract real client IP.
		clientIP := proxy.ExtractClientIP(r)

		// Check IP rate limit.
		ipDecision := l.CheckIP(clientIP, now)
		if !ipDecision.Allowed {
			metrics.BlockedTotal.Add(1)
			switch ipDecision.Reason {
			case "cooldown":
				metrics.BlockedByCooldown.Add(1)
			default:
				metrics.BlockedByIP.Add(1)
			}
			proxy.WriteRateLimitResponse(w, ipDecision.RetryAfterMs)
			return
		}

		// Check API key rate limit (optional header).
		if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
			keyDecision := l.CheckKey(apiKey, now)
			if !keyDecision.Allowed {
				metrics.BlockedTotal.Add(1)
				switch keyDecision.Reason {
				case "cooldown":
					metrics.BlockedByCooldown.Add(1)
				default:
					metrics.BlockedByAPIKey.Add(1)
				}
				proxy.WriteRateLimitResponse(w, keyDecision.RetryAfterMs)
				return
			}
		}

		// Request is allowed — proxy it.
		metrics.AllowedTotal.Add(1)
		rp.ServeHTTP(w, r)
	})

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: derived.ReadHeaderTimeout,
		WriteTimeout:      derived.WriteTimeout,
		MaxHeaderBytes:    1 << 16, // 64 KB
	}

	// Graceful shutdown on SIGTERM / SIGINT.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		log.Printf("AbuseShield listening on %s → %s", cfg.ListenAddr, cfg.UpstreamURL)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	<-quit
	log.Println("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
	log.Println("stopped")
}
