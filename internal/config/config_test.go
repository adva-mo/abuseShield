package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "config*.json")
	if err != nil {
		t.Fatalf("create temp config: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	f.Close()
	return filepath.Clean(f.Name())
}

const validBase = `{"upstream_url":"http://localhost:9090","kill_switch_secret":"s3cr3t-token"}`

func TestLoadFailsOnDefaultSecret(t *testing.T) {
	for _, secret := range []string{"", "change-me"} {
		content := `{"upstream_url":"http://localhost:9090","kill_switch_secret":"` + secret + `"}`
		_, _, err := Load(writeConfig(t, content))
		if err == nil {
			t.Errorf("secret=%q: expected error, got nil", secret)
		}
	}
}

func TestLoadFailsOnMissingSecret(t *testing.T) {
	// Omitting the field entirely leaves the zero value (""), which must also fail.
	_, _, err := Load(writeConfig(t, `{"upstream_url":"http://localhost:9090"}`))
	if err == nil {
		t.Error("omitted kill_switch_secret: expected error, got nil")
	}
}

func TestLoadSucceedsWithValidSecret(t *testing.T) {
	cfg, derived, err := Load(writeConfig(t, validBase))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.KillSwitchSecret != "s3cr3t-token" {
		t.Errorf("secret: got %q, want %q", cfg.KillSwitchSecret, "s3cr3t-token")
	}
	if derived == nil {
		t.Error("derived config is nil")
	}
}

func TestLoadFailsWhenFunnelGateEqualsTarget(t *testing.T) {
	content := `{"upstream_url":"http://localhost:9090","kill_switch_secret":"s3cr3t","funnel_gate":"/register","funnel_target":"/register"}`
	_, _, err := Load(writeConfig(t, content))
	if err == nil {
		t.Error("equal funnel paths: expected error, got nil")
	}
}

func TestLoadDefaultsApplied(t *testing.T) {
	cfg, _, err := Load(writeConfig(t, validBase))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.IPRatePerSec != 10 {
		t.Errorf("IPRatePerSec default: got %v, want 10", cfg.IPRatePerSec)
	}
	if cfg.FunnelGate != "/home" {
		t.Errorf("FunnelGate default: got %q, want /home", cfg.FunnelGate)
	}
	if cfg.FunnelTarget != "/register" {
		t.Errorf("FunnelTarget default: got %q, want /register", cfg.FunnelTarget)
	}
	if cfg.ShadowMode == nil || !*cfg.ShadowMode {
		t.Error("ShadowMode default: want true")
	}
}
