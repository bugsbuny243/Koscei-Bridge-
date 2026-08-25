package services

import (
	"strings"
	"testing"
)

func TestPiIssuerControlWithholdsLockWhenPaymentsRemainAuthorizable(t *testing.T) {
	arm := SecurityRadarVerdict{ModuleID: ModuleTokenAuthorityScanner, Signals: map[string]any{
		"evidence_status":          "observed",
		"active_signer_count":      2,
		"active_signer_weight_sum": 4,
		"medium_threshold":         3,
		"high_threshold":           5,
	}}
	observation, ok := piIssuerControlFromAuthorityArm(arm)
	if !ok {
		t.Fatal("expected issuer control observation")
	}
	if !observation.PaymentAuthorizationPossible || observation.FutureClassicIssuanceLocked {
		t.Fatalf("unexpected control observation: %#v", observation)
	}
}

func TestPiIssuerControlWithholdsIrreversibleLockWhenSetOptionsStillPossible(t *testing.T) {
	arm := SecurityRadarVerdict{ModuleID: ModuleTokenAuthorityScanner, Signals: map[string]any{
		"evidence_status":          "observed",
		"active_signer_count":      1,
		"active_signer_weight_sum": 2,
		"medium_threshold":         3,
		"high_threshold":           2,
	}}
	observation, ok := piIssuerControlFromAuthorityArm(arm)
	if !ok {
		t.Fatal("expected issuer control observation")
	}
	if observation.PaymentAuthorizationPossible || !observation.SetOptionsAuthorizationPossible || observation.FutureClassicIssuanceLocked {
		t.Fatalf("set-options escape path must prevent lock claim: %#v", observation)
	}
}

func TestPiIssuerControlCanObserveCurrentClassicIssuanceLock(t *testing.T) {
	arm := SecurityRadarVerdict{ModuleID: ModuleTokenAuthorityScanner, Signals: map[string]any{
		"evidence_status":          "observed",
		"active_signer_count":      1,
		"active_signer_weight_sum": 1,
		"medium_threshold":         2,
		"high_threshold":           2,
	}}
	observation, ok := piIssuerControlFromAuthorityArm(arm)
	if !ok {
		t.Fatal("expected issuer control observation")
	}
	if !observation.FutureClassicIssuanceLocked {
		t.Fatalf("expected current classic issuance lock: %#v", observation)
	}
	if observation.MaximumSupplyClaim {
		t.Fatal("issuer lock must not fabricate exact maximum supply")
	}
}

func TestPiIssuerControlNoActiveSignerIsLockedButStillNoSupplyNumber(t *testing.T) {
	arm := SecurityRadarVerdict{ModuleID: ModuleTokenAuthorityScanner, Signals: map[string]any{
		"evidence_status":          "observed",
		"active_signer_count":      0,
		"active_signer_weight_sum": 0,
		"medium_threshold":         0,
		"high_threshold":           0,
	}}
	observation, ok := piIssuerControlFromAuthorityArm(arm)
	if !ok || !observation.FutureClassicIssuanceLocked {
		t.Fatalf("expected no active signer to be non-authorizable: %#v ok=%t", observation, ok)
	}
	got := applyPiIssuerControlToAuthorityArm(arm, observation)
	if got.Signals["maximum_supply_claim"] != false {
		t.Fatalf("maximum supply claim must stay false: %#v", got.Signals)
	}
	if !strings.Contains(strings.Join(got.Evidence, " "), "does not prove") {
		t.Fatalf("expected maximum-supply limitation: %#v", got.Evidence)
	}
}
