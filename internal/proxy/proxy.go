package proxy

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// New creates a reverse proxy that forwards requests to upstream.
// transport is the http.Transport to use (tuned by the caller).
func New(upstream *url.URL, transport http.RoundTripper) *httputil.ReverseProxy {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			pr.SetXForwarded()
		},
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("upstream error: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{"error": "upstream_unavailable"})
		},
	}
	return rp
}

// NewTransport builds a tuned http.Transport for proxying.
func NewTransport(maxIdleConnsPerHost int, dialTimeout, tlsTimeout time.Duration) http.RoundTripper {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   tlsTimeout,
		MaxIdleConnsPerHost:   maxIdleConnsPerHost,
		MaxIdleConns:          maxIdleConnsPerHost * 4,
		IdleConnTimeout:       90 * time.Second,
		DisableCompression:    true, // upstream handles its own compression
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: 30 * time.Second,
	}
}

// ExtractClientIP returns the real client IP from the request.
// AbuseShield sits behind a trusted load balancer, so the rightmost entry in
// X-Forwarded-For is the IP the LB observed — it cannot be spoofed by the
// client. The leftmost entries are client-controlled and must not be trusted.
func ExtractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Rightmost entry is appended by the trusted load balancer.
		if idx := strings.LastIndexByte(xff, ','); idx != -1 {
			return strings.TrimSpace(xff[idx+1:])
		}
		return strings.TrimSpace(xff)
	}
	// No XFF header: direct connection, use RemoteAddr.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// WriteRateLimitResponse sends a 429 JSON response.
func WriteRateLimitResponse(w http.ResponseWriter, retryAfterMs int64) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", msToSeconds(retryAfterMs))
	w.WriteHeader(http.StatusTooManyRequests)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":          "rate_limit_exceeded",
		"retry_after_ms": retryAfterMs,
	})
}

func msToSeconds(ms int64) string {
	sec := (ms + 999) / 1000 // ceil
	if sec < 1 {
		sec = 1
	}
	return itoa(sec)
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}

// contextKey is unexported to avoid collisions.
type contextKey struct{}

// WithClientIP attaches the client IP to the request context (for future use).
func WithClientIP(r *http.Request, ip string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), contextKey{}, ip))
}
