package handlers

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDefenseValidationAPIRouteFailsClosedWithoutTrustedCollectorRegistry(t *testing.T) {
	t.Setenv(defenseValidationTrustedCollectorsEnv, "")
	request := defenseValidationAPITestRequest(t)
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	httpRequest := httptest.NewRequest(http.MethodPost, "/api/v1/defense/validation", strings.NewReader(string(body)))
	(&Handler{}).DefenseValidationV1(recorder, httpRequest)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "defense_validation_trust_unavailable") {
		t.Fatalf("missing fail-closed trust error: %s", recorder.Body.String())
	}
}

func TestDefenseValidationAPIRouteRejectsCallerSelfAttestedCollectorKey(t *testing.T) {
	request := defenseValidationAPITestRequest(t)
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = 0x65
	}
	trustedPrivateKey := ed25519.NewKeyFromSeed(seed)
	trustedPublicKey := base64.RawURLEncoding.EncodeToString(trustedPrivateKey.Public().(ed25519.PublicKey))
	registry, err := json.Marshal(map[string]string{
		request.Controls[0].CollectorRef: trustedPublicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(defenseValidationTrustedCollectorsEnv, string(registry))

	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	httpRequest := httptest.NewRequest(http.MethodPost, "/api/v1/defense/validation", strings.NewReader(string(body)))
	(&Handler{}).DefenseValidationV1(recorder, httpRequest)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "does not match the server trust registry") {
		t.Fatalf("caller-selected collector key was not rejected: %s", recorder.Body.String())
	}
}

func TestDefenseValidationAPIRouteAcceptsServerTrustedCollectorKey(t *testing.T) {
	request := defenseValidationAPITestRequest(t)
	registry, err := json.Marshal(map[string]string{
		request.Controls[0].CollectorRef: request.Controls[0].CollectorPublicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(defenseValidationTrustedCollectorsEnv, string(registry))

	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	httpRequest := httptest.NewRequest(http.MethodPost, "/api/v1/defense/validation", strings.NewReader(string(body)))
	(&Handler{}).DefenseValidationV1(recorder, httpRequest)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
