package allowlist

import (
	"fmt"
	"net"
	"strings"
)

// Config is the JSON-serialisable allowlist configuration.
type Config struct {
	IPs     []string `json:"ips"`
	Paths   []string `json:"paths"`
	APIKeys []string `json:"api_keys"`
}

// Allowlist matches requests against a set of trusted IPs/CIDRs, path
// prefixes, and API keys. A match on any field is sufficient to bypass all
// detection layers. An empty Allowlist never matches.
type Allowlist struct {
	nets    []*net.IPNet
	ips     []net.IP
	paths   []string
	apiKeys map[string]struct{}
}

// New compiles an Allowlist from cfg. Returns an error if any IP/CIDR string
// is unparseable.
func New(cfg Config) (*Allowlist, error) {
	a := &Allowlist{
		paths:   cfg.Paths,
		apiKeys: make(map[string]struct{}, len(cfg.APIKeys)),
	}
	for _, raw := range cfg.IPs {
		if _, network, err := net.ParseCIDR(raw); err == nil {
			a.nets = append(a.nets, network)
		} else if ip := net.ParseIP(raw); ip != nil {
			a.ips = append(a.ips, ip)
		} else {
			return nil, fmt.Errorf("allowlist: invalid ip or cidr %q", raw)
		}
	}
	for _, k := range cfg.APIKeys {
		a.apiKeys[k] = struct{}{}
	}
	return a, nil
}

// Match returns true if the request should bypass all detection.
// ip must be the extracted client IP (not including port).
func (a *Allowlist) Match(ip, path, apiKey string) bool {
	return a.matchIP(ip) || a.matchPath(path) || a.matchAPIKey(apiKey)
}

func (a *Allowlist) matchIP(ipStr string) bool {
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return false
	}
	for _, network := range a.nets {
		if network.Contains(parsed) {
			return true
		}
	}
	for _, allowed := range a.ips {
		if allowed.Equal(parsed) {
			return true
		}
	}
	return false
}

func (a *Allowlist) matchPath(path string) bool {
	for _, prefix := range a.paths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func (a *Allowlist) matchAPIKey(key string) bool {
	if key == "" {
		return false
	}
	_, ok := a.apiKeys[key]
	return ok
}
