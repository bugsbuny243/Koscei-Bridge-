package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func dossierAuthRequest() *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dossier/Mint111", nil)
	claims := neonJWTClaims{Sub: "user-1", Email: "user@example.com"}
	return req.WithContext(context.WithValue(req.Context(), authContextKey, claims))
}

func TestStoredEnterpriseGateAllowsEnterpriseWithoutRPC(t *testing.T) {
	calls := 0
	evaluator := func(context.Context, string) (tokenAccessEvaluation, error) {
		calls++
		return tokenAccessEvaluation{
			GateEnabled: true, Configured: true, WalletVerified: true, Tier: "enterprise",
			WalletAddress: "Wallet111", MintAddress: "KoschMint111",
		}, nil
	}
	reached := false
	h := &Handler{}
	handler := h.requireStoredTokenTierWithEvaluator("enterprise", evaluator, func(w http.ResponseWriter, r *http.Request) {
		reached = true
		value, ok := r.Context().Value(tokenAccessRequestContextKey{}).(tokenAccessRequestContext)
		if !ok || value.Evaluation.Tier != "enterprise" {
			t.Fatalf("request context=%#v ok=%t", value, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	response := httptest.NewRecorder()
	handler(response, dossierAuthRequest())
	if response.Code != http.StatusNoContent || !reached || calls != 1 {
		t.Fatalf("status=%d reached=%t calls=%d body=%s", response.Code, reached, calls, response.Body.String())
	}
}

func TestStoredEnterpriseGateRejectsPro(t *testing.T) {
	evaluator := func(context.Context, string) (tokenAccessEvaluation, error) {
		return tokenAccessEvaluation{GateEnabled: true, Configured: true, WalletVerified: true, Tier: "pro"}, nil
	}
	reached := false
	h := &Handler{}
	handler := h.requireStoredTokenTierWithEvaluator("enterprise", evaluator, func(http.ResponseWriter, *http.Request) { reached = true })
	response := httptest.NewRecorder()
	handler(response, dossierAuthRequest())
	if response.Code != http.StatusForbidden || reached {
		t.Fatalf("status=%d reached=%t", response.Code, reached)
	}
}

func TestStoredEnterpriseGateRequiresSnapshot(t *testing.T) {
	evaluator := func(context.Context, string) (tokenAccessEvaluation, error) {
		return tokenAccessEvaluation{}, errors.New("missing snapshot")
	}
	h := &Handler{}
	handler := h.requireStoredTokenTierWithEvaluator("enterprise", evaluator, func(http.ResponseWriter, *http.Request) { t.Fatal("next reached") })
	response := httptest.NewRecorder()
	handler(response, dossierAuthRequest())
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestStoredEnterpriseGateRejectsInvalidRequiredTier(t *testing.T) {
	evaluator := func(context.Context, string) (tokenAccessEvaluation, error) { return tokenAccessEvaluation{}, nil }
	h := &Handler{}
	handler := h.requireStoredTokenTierWithEvaluator("unknown", evaluator, func(http.ResponseWriter, *http.Request) { t.Fatal("next reached") })
	response := httptest.NewRecorder()
	handler(response, dossierAuthRequest())
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", response.Code)
	}
}

func TestDossierOwnerCredentialDetection(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dossier/Mint111", nil)
	if dossierOwnerCredentialPresent(req) {
		t.Fatal("empty request detected as owner")
	}
	req.Header.Set("x-koschei-secret", "secret")
	if !dossierOwnerCredentialPresent(req) {
		t.Fatal("owner header was not detected")
	}
}
