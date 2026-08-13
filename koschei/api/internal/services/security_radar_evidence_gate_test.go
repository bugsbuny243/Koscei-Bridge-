package services

import "testing"

func TestEvidenceGateRejectsUnsignedOutputWithoutLiveEvidence(t *testing.T) {
	bundle := SecurityRadarBundle{
		PumpSybilRadar: SecurityRadarVerdict{
			ModuleID:  ModulePumpSybilRadar,
			RiskIndex: 28,
			RiskLevel: "low",
			Grade:     "A",
			Signed:    true,
			Signature: "fake-signature",
			Signals:   map[string]any{"real_onchain_evidence": false},
		},
		RaydiumPoolGuardian: SecurityRadarVerdict{
			ModuleID:  ModuleRaydiumPoolGuardian,
			RiskIndex: 28,
			RiskLevel: "low",
			Grade:     "A",
			Signed:    true,
			Signature: "fake-signature-2",
			Signals:   map[string]any{"real_onchain_evidence": false},
		},
	}

	gated := EvidenceBackedSecurityRadarBundle(bundle)
	final := EvidenceBackedFinalSecurityRadarVerdict(gated)

	if SecurityRadarHasLiveEvidence(gated) {
		t.Fatal("expected no live evidence")
	}
	if final.Signed {
		t.Fatal("verdict without live evidence must not be signed")
	}
	if final.RiskIndex != 0 || final.Grade != "-" || final.Signature != "" {
		t.Fatalf("unexpected insufficient-evidence final verdict: %#v", final)
	}
	if final.Recommendation != "insufficient_evidence" {
		t.Fatalf("unexpected recommendation: %s", final.Recommendation)
	}
}

func TestEvidenceGateDoesNotPromoteEvidenceArmToFinalVerdict(t *testing.T) {
	bundle := SecurityRadarBundle{
		PumpSybilRadar: SecurityRadarVerdict{
			ModuleID:       ModulePumpSybilRadar,
			RiskIndex:      46,
			RiskLevel:      "medium",
			Grade:          "B",
			Verdict:        "Verified observation",
			Recommendation: "watch",
			Signed:         true,
			Signature:      "verified-signature",
			Signals:        map[string]any{"real_onchain_evidence": true},
		},
		RaydiumPoolGuardian: SecurityRadarVerdict{
			ModuleID:       ModuleRaydiumPoolGuardian,
			RiskIndex:      20,
			RiskLevel:      "low",
			Grade:          "A",
			Recommendation: "safe_to_monitor",
			Signed:         true,
			Signature:      "verified-signature-2",
			Signals:        map[string]any{"real_onchain_evidence": true},
		},
	}

	gated := EvidenceBackedSecurityRadarBundle(bundle)
	final := EvidenceBackedFinalSecurityRadarVerdict(gated)

	if !SecurityRadarHasLiveEvidence(gated) {
		t.Fatal("expected live evidence")
	}
	if final.Signed {
		t.Fatalf("evidence-only arm must not self-sign a final verdict: %#v", final)
	}
	if final.Grade != "-" || final.RiskIndex != 0 || final.RiskLevel != "unknown" || final.Signature != "" {
		t.Fatalf("evidence-only arm leaked grade/score into final verdict: %#v", final)
	}
	if final.Recommendation != "evaluate_unified_rules" {
		t.Fatalf("expected canonical unified-rules handoff, got %q", final.Recommendation)
	}
}
