package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/adva-mo/abuseShield/internal/allowlist"
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

	// Abuse detection engine settings.
	// ShadowMode uses *bool so the JSON zero-value (false) is distinguishable
	// from "not set", allowing the default to be true.
	ShadowMode      *bool  `json:"shadow_mode"`
	KillSwitch       bool  `json:"kill_switch"`
	KillSwitchSecret string `json:"kill_switch_secret"`
	// EntityRatePerSec / EntityBurst / EntityBurstWindowSec control the L1
	// token-bucket rate limiter applied per EntityID (not per raw IP).
	EntityRatePerSec    float64 `json:"entity_rate_per_sec"`
	EntityBurst         float64 `json:"entity_burst"`
	EntityBurstWindowSec float64 `json:"entity_burst_window_sec"`
	// EventBufferSize is the capacity of the async SecurityEvent log channel.
	EventBufferSize int `json:"event_buffer_size"`
	// BlockOnSuspicious: when true and shadow_mode is false, SUSPICIOUS decisions
	// (e.g. sequence_violation) also block the request. Defaults to false so
	// sequence detection can be observed in shadow mode before enforcement.
	BlockOnSuspicious bool `json:"block_on_suspicious"`

	// Allowlist defines trusted IPs/CIDRs, path prefixes, and API keys that
	// bypass all detection layers (L0, L1, L2) and go straight to the upstream.
	Allowlist allowlist.Config `json:"allowlist"`
}

// Derived durations (populated by Load).
type Derived struct {
	Cooldown         time.Duration
	EvictionInterval time.Duration
	DialTimeout      time.Duration
	TLSTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout     time.Duration
	EntityBurstWindow time.Duration
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

	// Abuse detection defaults.
	if cfg.ShadowMode == nil {
		t := true
		cfg.ShadowMode = &t
	}
	if cfg.KillSwitchSecret == "" {
		cfg.KillSwitchSecret = "change-me"
	}
	if cfg.EntityRatePerSec <= 0 {
		cfg.EntityRatePerSec = 2.5
	}
	if cfg.EntityBurst <= 0 {
		cfg.EntityBurst = 5
	}
	if cfg.EntityBurstWindowSec <= 0 {
		cfg.EntityBurstWindowSec = 2.0
	}
	if cfg.EventBufferSize <= 0 {
		cfg.EventBufferSize = 1000
	}

	d := &Derived{
		Cooldown:          time.Duration(cfg.CooldownSeconds * float64(time.Second)),
		EvictionInterval:  time.Duration(cfg.EvictionIntervalSeconds * float64(time.Second)),
		DialTimeout:       time.Duration(cfg.DialTimeoutSeconds * float64(time.Second)),
		TLSTimeout:        time.Duration(cfg.TLSHandshakeTimeoutSeconds * float64(time.Second)),
		ReadHeaderTimeout: time.Duration(cfg.ReadHeaderTimeoutSeconds * float64(time.Second)),
		WriteTimeout:      time.Duration(cfg.WriteTimeoutSeconds * float64(time.Second)),
		EntityBurstWindow: time.Duration(cfg.EntityBurstWindowSec * float64(time.Second)),
	}

	return &cfg, d, nil
}
