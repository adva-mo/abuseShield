package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config holds all runtime configuration loaded from config.json.
type Config struct {
	ListenAddr    string  `json:"listen_addr"`
	UpstreamURL   string  `json:"upstream_url"`
	IPRatePerSec  float64 `json:"ip_rate_per_sec"`
	IPBurst       float64 `json:"ip_burst"`
	KeyRatePerSec float64 `json:"key_rate_per_sec"`
	KeyBurst      float64 `json:"key_burst"`

	// HotKeyMultiplier: if windowCount > HotKeyMultiplier * rate_per_sec in 1s, enter cooldown.
	HotKeyMultiplier float64 `json:"hot_key_multiplier"`
	CooldownSeconds  float64 `json:"cooldown_seconds"`

	EvictionIntervalSeconds         float64 `json:"eviction_interval_seconds"`
	MaxIdleConnsPerHost             int     `json:"max_idle_conns_per_host"`
	DialTimeoutSeconds              float64 `json:"dial_timeout_seconds"`
	TLSHandshakeTimeoutSeconds      float64 `json:"tls_handshake_timeout_seconds"`
	ReadHeaderTimeoutSeconds        float64 `json:"read_header_timeout_seconds"`
	WriteTimeoutSeconds             float64 `json:"write_timeout_seconds"`
}

// Derived durations (populated by Load).
type Derived struct {
	CooldownNs       int64
	EvictionInterval time.Duration
	DialTimeout      time.Duration
	TLSTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout     time.Duration
}

func Load(path string) (*Config, *Derived, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, nil, fmt.Errorf("decode config: %w", err)
	}

	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8080"
	}
	if cfg.UpstreamURL == "" {
		return nil, nil, fmt.Errorf("upstream_url is required")
	}
	if cfg.IPRatePerSec <= 0 {
		cfg.IPRatePerSec = 10
	}
	if cfg.IPBurst <= 0 {
		cfg.IPBurst = 20
	}
	if cfg.KeyRatePerSec <= 0 {
		cfg.KeyRatePerSec = 100
	}
	if cfg.KeyBurst <= 0 {
		cfg.KeyBurst = 200
	}
	if cfg.HotKeyMultiplier <= 0 {
		cfg.HotKeyMultiplier = 3
	}
	if cfg.CooldownSeconds <= 0 {
		cfg.CooldownSeconds = 60
	}
	if cfg.EvictionIntervalSeconds <= 0 {
		cfg.EvictionIntervalSeconds = 60
	}
	if cfg.MaxIdleConnsPerHost <= 0 {
		cfg.MaxIdleConnsPerHost = 256
	}
	if cfg.DialTimeoutSeconds <= 0 {
		cfg.DialTimeoutSeconds = 5
	}
	if cfg.TLSHandshakeTimeoutSeconds <= 0 {
		cfg.TLSHandshakeTimeoutSeconds = 10
	}
	if cfg.ReadHeaderTimeoutSeconds <= 0 {
		cfg.ReadHeaderTimeoutSeconds = 5
	}
	if cfg.WriteTimeoutSeconds <= 0 {
		cfg.WriteTimeoutSeconds = 60
	}

	d := &Derived{
		CooldownNs:        int64(cfg.CooldownSeconds * 1e9),
		EvictionInterval:  time.Duration(cfg.EvictionIntervalSeconds * float64(time.Second)),
		DialTimeout:       time.Duration(cfg.DialTimeoutSeconds * float64(time.Second)),
		TLSTimeout:        time.Duration(cfg.TLSHandshakeTimeoutSeconds * float64(time.Second)),
		ReadHeaderTimeout: time.Duration(cfg.ReadHeaderTimeoutSeconds * float64(time.Second)),
		WriteTimeout:      time.Duration(cfg.WriteTimeoutSeconds * float64(time.Second)),
	}

	return &cfg, d, nil
}
