package handlers

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIssueTransactionGuardV3EnforcementPermitAllow(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", base64.StdEncoding.EncodeToString(seed))
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_KEY_ID", "tgk_test_allow")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PERMIT_TTL_SECONDS", "45")
	t.Setenv("TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT", "false")

	wallet := guardV3TestAddress(81)
	request := httptest.NewRequest("POST", "https://guard.example/api/v1/shield/transaction", nil)
	request.Header.Set("Origin", "https://app.example")
	input := transactionGuardV2Request{
		Transaction: "AQIDBA==",
		Encoding:    "base64",
		Network:     "solana-mainnet",
		Wallet:      wallet,
	}
	assessment := transactionFirewallAssessment{
		SimulationOK: true,
		Action:       "allow",
		RiskLevel:    "low",
		RiskIndex:    4,
		Summary:      "verified",
		Findings:     []transactionFirewallFinding{},
	}
	program := transactionGuardProgramPolicy{Complete: true}
	intent := transactionGuardIntentPolicy{Complete: true}
	decoded := transactionGuardDecodedTransaction{Complete: true}
	now := time.Date(2026, time.July, 31, 18, 45, 30, 500, time.UTC)

	permit, findings := issueTransactionGuardV3EnforcementPermit(
		request, input, "req-permit-allow", assessment, program, intent, decoded,
		transactionGuardThreatHistoryAnalysis{}, transactionGuardCPIFlowAnalysis{}, transactionGuardAuthoritySurfaceAnalysis{}, true, now,
	)
	if len(findings) != 0 {
		t.Fatalf("unexpected findings: %#v", findings)
	}
	if !permit.Available || !permit.Complete || permit.Status != "issued" {
		t.Fatalf("permit=%#v", permit)
	}
	if permit.Payload.Action != "allow" || permit.Payload.WarnApprovalRequired || !permit.Payload.GuardComplete {
		t.Fatalf("payload=%#v", permit.Payload)
	}
	if permit.Payload.Wallet != wallet || permit.Payload.Origin != "https://app.example" {
		t.Fatalf("wallet/origin binding failed: %#v", permit.Payload)
	}
	if permit.Payload.TransactionFingerprint != transactionFingerprint(input.Transaction) {
		t.Fatalf("fingerprint mismatch: %#v", permit.Payload)
	}
	if permit.Payload.IssuedAt != "2026-07-31T18:45:30Z" || permit.Payload.ExpiresAt != "2026-07-31T18:46:15Z" {
		t.Fatalf("unexpected permit lifetime: %#v", permit.Payload)
	}

	canonical, err := json.Marshal(permit.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != permit.CanonicalPayload {
		t.Fatalf("canonical payload mismatch\nwant=%s\ngot=%s", string(canonical), permit.CanonicalPayload)
	}
	publicKey, err := base64.StdEncoding.DecodeString(permit.VerificationKey)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(permit.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), canonical, signature) {
		t.Fatal("enforcement permit signature did not verify")
	}
}

func TestIssueTransactionGuardV3EnforcementPermitWarnRequiresApproval(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 9
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", base64.StdEncoding.EncodeToString(seed))
	t.Setenv("TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT", "false")
	request := httptest.NewRequest("POST", "https://guard.example", nil)
	request.Header.Set("Origin", "https://warn.example/")
	assessment := transactionFirewallAssessment{SimulationOK: true, Action: "warn", RiskLevel: "medium", RiskIndex: 25, Findings: []transactionFirewallFinding{}}
	input := transactionGuardV2Request{Transaction: "AQID", Network: "solana-mainnet", Wallet: guardV3TestAddress(82)}

	permit, _ := issueTransactionGuardV3EnforcementPermit(
		request, input, "req-permit-warn", assessment,
		transactionGuardProgramPolicy{Complete: true}, transactionGuardIntentPolicy{Complete: true}, transactionGuardDecodedTransaction{Complete: true},
		transactionGuardThreatHistoryAnalysis{}, transactionGuardCPIFlowAnalysis{}, transactionGuardAuthoritySurfaceAnalysis{}, true, time.Now(),
	)
	if permit.Status != "issued" || !permit.Payload.WarnApprovalRequired || permit.Payload.Action != "warn" {
		t.Fatalf("permit=%#v", permit)
	}
	if permit.Payload.Origin != "https://warn.example" {
		t.Fatalf("origin was not normalized: %q", permit.Payload.Origin)
	}
}

func TestIssueTransactionGuardV3EnforcementPermitNeverIssuesForBlock(t *testing.T) {
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", "")
	t.Setenv("TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT", "true")
	assessment := transactionFirewallAssessment{SimulationOK: true, Action: "block", RiskLevel: "critical", RiskIndex: 100}
	permit, findings := issueTransactionGuardV3EnforcementPermit(
		httptest.NewRequest("POST", "https://guard.example", nil),
		transactionGuardV2Request{Transaction: "AQID", Network: "solana-mainnet", Wallet: guardV3TestAddress(83)},
		"req-permit-block", assessment,
		transactionGuardProgramPolicy{Complete: true}, transactionGuardIntentPolicy{Complete: true}, transactionGuardDecodedTransaction{Complete: true},
		transactionGuardThreatHistoryAnalysis{}, transactionGuardCPIFlowAnalysis{}, transactionGuardAuthoritySurfaceAnalysis{}, true, time.Now(),
	)
	if findings != nil || !permit.Complete || permit.Available || permit.Status != "not_issuable_for_decision" || permit.Signature != "" {
		t.Fatalf("permit=%#v findings=%#v", permit, findings)
	}
	if !transactionGuardV3PermitGateComplete(true, permit) {
		t.Fatal("a complete blocking decision must not become incomplete merely because no signing permit is issuable")
	}
}

func TestRequiredEnforcementPermitFailureWithholdsSigningDecision(t *testing.T) {
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", "")
	t.Setenv("TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT", "true")
	request := httptest.NewRequest("POST", "https://guard.example", nil)
	request.Header.Set("Origin", "https://app.example")
	assessment := transactionFirewallAssessment{
		SimulationOK: true,
		Action:       "allow",
		RiskLevel:    "low",
		RiskIndex:    0,
		Summary:      "verified",
		Findings:     []transactionFirewallFinding{},
	}
	permit, findings := issueTransactionGuardV3EnforcementPermit(
		request,
		transactionGuardV2Request{Transaction: "AQID", Network: "solana-mainnet", Wallet: guardV3TestAddress(84)},
		"req-permit-required", assessment,
		transactionGuardProgramPolicy{Complete: true}, transactionGuardIntentPolicy{Complete: true}, transactionGuardDecodedTransaction{Complete: true},
		transactionGuardThreatHistoryAnalysis{}, transactionGuardCPIFlowAnalysis{}, transactionGuardAuthoritySurfaceAnalysis{}, true, time.Now(),
	)
	if permit.Status != "signing_key_unavailable" || len(findings) != 1 || findings[0].Severity != "high" {
		t.Fatalf("permit=%#v findings=%#v", permit, findings)
	}
	updated, changed := applyTransactionGuardV3PermitGate(assessment, permit, findings)
	if !changed || updated.Action != "withhold" || updated.RiskLevel != "unknown" {
		t.Fatalf("updated=%#v changed=%v", updated, changed)
	}
	if !strings.Contains(updated.Summary, "required cryptographic wallet enforcement permit") {
		t.Fatalf("summary=%q", updated.Summary)
	}
	if transactionGuardV3PermitGateComplete(true, permit) {
		t.Fatal("required but unavailable permit must make guard_complete false")
	}
}
