package services

import "testing"

func TestIntegrityPostureDoesNotCallMissingTradeVisibilityHealthy(t *testing.T) {
	posture := DeriveSecurityIntegrityPosture(
		SecurityRadarContinuityReport{Status: "caught_up", Available: true, AllCaughtUp: true},
		PumpPortalInboxHealth{Status: "healthy", Available: true},
		PumpPortalTradeStreamHealth{Status: "no_trade_observed", Available: true, APIKeyConfigured: true},
		ProviderWitnessMemoryReport{Status: "learning", Available: true},
	)
	if posture.Status != "partial_visibility" || posture.FullVisibility {
		t.Fatalf("expected partial visibility, got status=%q full=%t", posture.Status, posture.FullVisibility)
	}
	if !posture.VerdictReady {
		t.Fatal("optional trade visibility must not invalidate independent deterministic verdicts")
	}
}

func TestIntegrityPostureFailsVerdictReadyOnDurableIngressDegradation(t *testing.T) {
	posture := DeriveSecurityIntegrityPosture(
		SecurityRadarContinuityReport{Status: "caught_up", Available: true},
		PumpPortalInboxHealth{Status: "degraded", Available: true, ExhaustedCount: 1},
		PumpPortalTradeStreamHealth{Status: "observed", Available: true},
		ProviderWitnessMemoryReport{Status: "learning", Available: true},
	)
	if posture.Status != "degraded" || posture.VerdictReady {
		t.Fatalf("expected degraded non-ready posture, got status=%q ready=%t", posture.Status, posture.VerdictReady)
	}
}

func TestIntegrityPostureProviderDivergenceIsDegradedButNotAutoBan(t *testing.T) {
	posture := DeriveSecurityIntegrityPosture(
		SecurityRadarContinuityReport{Status: "caught_up", Available: true},
		PumpPortalInboxHealth{Status: "healthy", Available: true},
		PumpPortalTradeStreamHealth{Status: "observed", Available: true},
		ProviderWitnessMemoryReport{Status: "attention_required", Available: true},
	)
	if posture.Status != "degraded" {
		t.Fatalf("expected degraded posture, got %q", posture.Status)
	}
	if !posture.VerdictReady {
		t.Fatal("historical provider divergence alone must not replace current quorum authority")
	}
}

func TestIntegrityPostureUnavailableBroadStreamIsPartialNotHealthy(t *testing.T) {
	posture := DeriveSecurityIntegrityPosture(
		SecurityRadarContinuityReport{Status: "unavailable"},
		PumpPortalInboxHealth{Status: "healthy", Available: true},
		PumpPortalTradeStreamHealth{Status: "observed", Available: true},
		ProviderWitnessMemoryReport{Status: "learning", Available: true},
	)
	if posture.Status != "partial_visibility" || posture.FullVisibility {
		t.Fatalf("expected partial visibility, got status=%q full=%t", posture.Status, posture.FullVisibility)
	}
}
