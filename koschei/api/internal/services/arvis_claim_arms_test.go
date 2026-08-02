package services

import (
	"testing"
	"time"
)

func TestClaimSurfaceRejectsPlainText(t *testing.T) {
	evidence := parseArvisClaimSurface("this is not a url")
	if evidence.Available {
		t.Fatal("plain text must not become URL evidence")
	}
}

func TestSafeHTTPSClaimSurfaceProducesVerifiedEvidenceOnly(t *testing.T) {
	evidence := parseArvisClaimSurface("https://example.com/claim?id=42")
	if !evidence.Available || !evidence.HTTPS || evidence.IPLiteralHost || evidence.PunycodeHost {
		t.Fatalf("unexpected parsed evidence: %#v", evidence)
	}
	req := SecurityRadarRequest{Target: evidence.Original, Network: "solana-mainnet"}
	arm := buildClaimSurfaceArm(req, evidence, time.Now().UTC().Format(time.RFC3339))
	if !SecurityRadarVerdictHasVerifiedEvidence(arm) {
		t.Fatal("valid parsed URL evidence must be verified")
	}
	if arm.RiskIndex != 0 || arm.Grade != "-" {
		t.Fatalf("claim arm issued score or grade: %#v", arm)
	}
	if onchain, _ := arm.Signals["real_onchain_evidence"].(bool); onchain {
		t.Fatal("URL parser evidence must not be labeled on-chain")
	}
	if offchain, _ := arm.Signals["real_offchain_evidence"].(bool); !offchain {
		t.Fatal("URL parser evidence must be labeled off-chain")
	}
}

func TestSuspiciousClaimSurfacePreservesStructuralFactsWithoutScore(t *testing.T) {
	raw := "http://192.0.2.7:8080/airdrop/claim?seedphrase=alpha&approve_transaction=1&redirect_uri=https%3A%2F%2Fexample.org"
	evidence := parseArvisClaimSurface(raw)
	if !evidence.Available || !evidence.IPLiteralHost || evidence.HTTPS {
		t.Fatalf("unexpected suspicious evidence: %#v", evidence)
	}
	req := SecurityRadarRequest{Target: raw, Network: "solana-mainnet"}
	shield := buildWalletlessClaimArm(req, evidence, time.Now().UTC().Format(time.RFC3339))
	surface := buildClaimSurfaceArm(req, evidence, time.Now().UTC().Format(time.RFC3339))
	for _, arm := range []SecurityRadarVerdict{shield, surface} {
		if !arm.Signed {
			t.Fatalf("parsed suspicious surface must produce signed evidence: %#v", arm)
		}
		if arm.RiskIndex != 0 || arm.Grade != "-" {
			t.Fatalf("claim arm issued score or grade: %#v", arm)
		}
	}
	if terms, _ := shield.Signals["secret_request_terms"].([]string); len(terms) == 0 {
		t.Fatalf("secret-request evidence missing: %#v", shield.Signals)
	}
	if ip, _ := surface.Signals["ip_literal_host"].(bool); !ip {
		t.Fatalf("IP-literal evidence missing: %#v", surface.Signals)
	}
}

func TestVerifiedFinalArmCannotPromoteOffchainEvidenceToGrade(t *testing.T) {
	req := SecurityRadarRequest{Target: "https://example.com/claim", Network: "solana-mainnet"}
	generatedAt := time.Now().UTC().Format(time.RFC3339)
	claim := verifiedEvidenceArm("Claim Surface Risk", ModuleClaimSurfaceRisk, req, 44, map[string]any{
		"verified_evidence":      true,
		"real_offchain_evidence": true,
		"real_onchain_evidence":  false,
	}, []string{"parsed URL"}, generatedAt)
	final := buildVerifiedFinalArm(req, []SecurityRadarVerdict{claim}, generatedAt)
	if final.Signed || final.RiskIndex != 0 || final.Grade != "-" {
		t.Fatalf("compatibility final promoted evidence into a grade: %#v", final)
	}
	if source, _ := final.Signals["verdict_source"].(string); source != "EvaluateUnifiedRadarVerdict" {
		t.Fatalf("unexpected final source: %q", source)
	}
}
