package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestKillSwitchHandlerMethodEnforcement(t *testing.T) {
	var ks atomic.Bool
	h := killSwitchHandler(&ks, "secret")

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/admin/kill-switch?enable=true", nil)
		req.Header.Set("X-Kill-Switch-Secret", "secret")
		w := httptest.NewRecorder()
		h(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("method %s: want 405, got %d", method, w.Code)
		}
	}
}

func TestKillSwitchHandlerMissingSecret(t *testing.T) {
	var ks atomic.Bool
	h := killSwitchHandler(&ks, "secret")

	req := httptest.NewRequest(http.MethodPost, "/admin/kill-switch?enable=true", nil)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("missing secret: want 403, got %d", w.Code)
	}
	if ks.Load() {
		t.Error("missing secret: kill switch must not change state")
	}
}

func TestKillSwitchHandlerWrongSecret(t *testing.T) {
	var ks atomic.Bool
	h := killSwitchHandler(&ks, "correct-secret")

	req := httptest.NewRequest(http.MethodPost, "/admin/kill-switch?enable=true", nil)
	req.Header.Set("X-Kill-Switch-Secret", "wrong-secret")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("wrong secret: want 403, got %d", w.Code)
	}
	if ks.Load() {
		t.Error("wrong secret: kill switch must not change state")
	}
}

func TestKillSwitchHandlerEnable(t *testing.T) {
	var ks atomic.Bool
	h := killSwitchHandler(&ks, "secret")

	req := httptest.NewRequest(http.MethodPost, "/admin/kill-switch?enable=true", nil)
	req.Header.Set("X-Kill-Switch-Secret", "secret")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("enable: want 200, got %d", w.Code)
	}
	if !ks.Load() {
		t.Error("enable: kill switch should be on after enable=true")
	}
}

func TestKillSwitchHandlerDisable(t *testing.T) {
	var ks atomic.Bool
	ks.Store(true) // start enabled
	h := killSwitchHandler(&ks, "secret")

	req := httptest.NewRequest(http.MethodPost, "/admin/kill-switch?enable=false", nil)
	req.Header.Set("X-Kill-Switch-Secret", "secret")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("disable: want 200, got %d", w.Code)
	}
	if ks.Load() {
		t.Error("disable: kill switch should be off after enable=false")
	}
}
