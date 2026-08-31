package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCommercialCheckoutEnabledFailClosed(t *testing.T) {
	t.Setenv(commercialCheckoutEnv, "")
	if commercialCheckoutEnabled() {
		t.Fatal("checkout must be disabled when readiness is unset")
	}

	for _, value := range []string{"0", "false", "no", "off", "unexpected"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv(commercialCheckoutEnv, value)
			if commercialCheckoutEnabled() {
				t.Fatalf("checkout must remain disabled for %q", value)
			}
		})
	}
}

func TestCommercialCheckoutEnabledExplicitOnly(t *testing.T) {
	for _, value := range []string{"1", "true", "TRUE", "yes", "on"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv(commercialCheckoutEnv, value)
			if !commercialCheckoutEnabled() {
				t.Fatalf("checkout should be enabled for explicit value %q", value)
			}
		})
	}
}

func TestPolarCheckoutCommercialPausedBeforeBilling(t *testing.T) {
	t.Setenv(commercialCheckoutEnv, "")
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/polar/checkout", strings.NewReader(`{"plan":"starter"}`))

	var h *Handler
	h.PolarCheckoutCommercial(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected %d, got %d", http.StatusServiceUnavailable, recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `"error":"commercial_checkout_paused"`) {
		t.Fatalf("expected stable paused error, got %s", body)
	}
}

func TestPolarCheckoutCommercialForwardsWhenExplicitlyEnabled(t *testing.T) {
	t.Setenv(commercialCheckoutEnv, "true")
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/polar/checkout", strings.NewReader(`{"plan":"starter"}`))

	h := &Handler{}
	h.PolarCheckoutCommercial(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected underlying billing availability response, got %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), `"error":"billing_unavailable"`) {
		t.Fatalf("expected enabled gate to forward to PolarCheckout, got %s", recorder.Body.String())
	}
}
