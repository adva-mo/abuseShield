package allowlist

import "testing"

func newOrFatal(t *testing.T, cfg Config) *Allowlist {
	t.Helper()
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestEmptyNeverMatches(t *testing.T) {
	a := newOrFatal(t, Config{})
	if a.Match("1.2.3.4", "/register", "key") {
		t.Fatal("empty allowlist should never match")
	}
}

func TestExactIP(t *testing.T) {
	a := newOrFatal(t, Config{IPs: []string{"10.0.0.1"}})
	if !a.Match("10.0.0.1", "/", "") {
		t.Fatal("exact IP should match")
	}
	if a.Match("10.0.0.2", "/", "") {
		t.Fatal("different IP should not match")
	}
}

func TestCIDR(t *testing.T) {
	a := newOrFatal(t, Config{IPs: []string{"192.168.1.0/24"}})
	if !a.Match("192.168.1.100", "/", "") {
		t.Fatal("IP inside CIDR should match")
	}
	if a.Match("192.168.2.1", "/", "") {
		t.Fatal("IP outside CIDR should not match")
	}
}

func TestPathPrefix(t *testing.T) {
	a := newOrFatal(t, Config{Paths: []string{"/health", "/internal/"}})
	if !a.Match("", "/health", "") {
		t.Fatal("/health should match")
	}
	if !a.Match("", "/health/check", "") {
		t.Fatal("/health/check should match /health prefix")
	}
	if !a.Match("", "/internal/status", "") {
		t.Fatal("/internal/status should match /internal/ prefix")
	}
	if a.Match("", "/register", "") {
		t.Fatal("/register should not match")
	}
}

func TestAPIKey(t *testing.T) {
	a := newOrFatal(t, Config{APIKeys: []string{"internal-key"}})
	if !a.Match("", "/", "internal-key") {
		t.Fatal("matching API key should be allowed")
	}
	if a.Match("", "/", "other-key") {
		t.Fatal("non-matching API key should not be allowed")
	}
	if a.Match("", "/", "") {
		t.Fatal("empty API key should not match")
	}
}

func TestInvalidIPReturnsError(t *testing.T) {
	_, err := New(Config{IPs: []string{"not-an-ip"}})
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestAnyFieldSuffices(t *testing.T) {
	a := newOrFatal(t, Config{
		IPs:     []string{"10.0.0.1"},
		Paths:   []string{"/health"},
		APIKeys: []string{"trusted"},
	})
	// Only path matches.
	if !a.Match("1.2.3.4", "/health", "unknown") {
		t.Fatal("path match alone should suffice")
	}
	// Only key matches.
	if !a.Match("1.2.3.4", "/register", "trusted") {
		t.Fatal("key match alone should suffice")
	}
	// Only IP matches.
	if !a.Match("10.0.0.1", "/register", "unknown") {
		t.Fatal("IP match alone should suffice")
	}
}
