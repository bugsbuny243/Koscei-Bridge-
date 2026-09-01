package handlers

import (
	"strings"
	"testing"
)

func TestAdversarialSetPermanentDelegateAuthorityBlocks(t *testing.T) {
	account := guardV3TestAddress(81)
	currentAuthority := guardV3TestAddress(82)
	newAuthority := guardV3TestAddress(83)
	newAuthorityBytes, err := decodeSolanaPublicKey(newAuthority)
	if err != nil {
		t.Fatal(err)
	}

	// SPL/Token-2022 SetAuthority: opcode=6, authority_type=8
	// (permanent delegate), Some(new authority).
	data := []byte{6, 8, 1}
	data = append(data, newAuthorityBytes...)
	event, relevant, err := decodeTransactionGuardV3AuthorityEvent(transactionGuardAuthorityInstruction{
		Source:    "outer",
		ProgramID: guardV3Token2022ProgramID,
		Accounts:  []string{account, currentAuthority},
		Data:      data,
	})
	if err != nil || !relevant {
		t.Fatalf("relevant=%v err=%v", relevant, err)
	}
	if event.Kind != "set_authority" || event.AuthorityType == nil || *event.AuthorityType != 8 {
		t.Fatalf("unexpected authority event: %#v", event)
	}
	if event.AuthorityTypeName != "permanent_delegate" || !event.MintWide || !event.CanTransfer || !event.CanBurn {
		t.Fatalf("permanent-delegate semantics lost: %#v", event)
	}

	finding, ok := transactionGuardV3AuthorityFinding(event)
	if !ok {
		t.Fatal("critical authority mutation produced no finding")
	}
	if finding.Severity != "critical" || finding.Score != 75 || !strings.HasPrefix(finding.Code, "authority_change_permanent_delegate_") {
		t.Fatalf("finding=%#v", finding)
	}
	if !strings.Contains(finding.Evidence, "kind=set_authority") || !strings.Contains(finding.Evidence, "new_authority="+newAuthority) {
		t.Fatalf("authority provenance missing from evidence: %q", finding.Evidence)
	}

	assessment := finalizeEvidenceFirstGuardAssessment(
		transactionFirewallAssessment{Action: "allow", RiskLevel: "low", SimulationOK: true, Findings: []transactionFirewallFinding{finding}},
		transactionGuardProgramPolicy{Complete: true},
		transactionGuardIntentPolicy{Complete: true},
	)
	if assessment.Action != "block" || assessment.RiskLevel != "critical" {
		t.Fatalf("critical persistent authority mutation must block: %#v", assessment)
	}
}

func TestAdversarialSetFreezeAuthorityWithoutFinalStateWithholds(t *testing.T) {
	mint := guardV3TestAddress(84)
	currentAuthority := guardV3TestAddress(85)
	newAuthority := guardV3TestAddress(86)
	newAuthorityBytes, err := decodeSolanaPublicKey(newAuthority)
	if err != nil {
		t.Fatal(err)
	}

	// SetAuthority authority_type=1 changes the mint-wide freeze authority.
	// Types 0..3 require final simulated account state; omit it deliberately.
	data := []byte{6, 1, 1}
	data = append(data, newAuthorityBytes...)
	decoded := guardV3AuthorityTestDecoded(guardV3SPLTokenProgramID, []string{mint, currentAuthority}, data)
	analysis, findings := analyzeTransactionGuardV3AuthoritySurface(decoded, nil, transactionGuardAuthoritySnapshots{})
	if analysis.Complete || analysis.Status != "partial" || analysis.EventCount != 1 {
		t.Fatalf("missing final authority state must remain partial: %#v", analysis)
	}
	if !hasFindingPrefix(findings, "authority_change_freeze_account_") {
		t.Fatalf("freeze-authority mutation finding missing: %#v", findings)
	}

	assessment := finalizeEvidenceFirstGuardAssessment(
		transactionFirewallAssessment{Action: "allow", RiskLevel: "low", SimulationOK: true, Findings: findings},
		transactionGuardProgramPolicy{Complete: true},
		transactionGuardIntentPolicy{Complete: analysis.Complete},
	)
	if assessment.Action != "withhold" || assessment.RiskLevel != "unknown" {
		t.Fatalf("unverified final authority state must withhold, not allow/warn: %#v", assessment)
	}
}

func TestAdversarialFreezeAccountInstructionWarns(t *testing.T) {
	account := guardV3TestAddress(87)
	mint := guardV3TestAddress(88)
	authority := guardV3TestAddress(89)
	decoded := transactionGuardDecodedTransaction{Available: true, Complete: true}

	kind := classifyTransactionGuardV3TokenInstruction(
		guardV3SPLTokenProgramID,
		[]string{account, mint, authority},
		[]byte{10}, // FreezeAccount
		&decoded,
	)
	if kind != "token_freeze_account" || len(decoded.TokenOperations) != 1 {
		t.Fatalf("freeze instruction not decoded: kind=%q decoded=%#v", kind, decoded)
	}
	findings := transactionGuardV3InstructionFindings(decoded)
	if len(findings) != 1 || findings[0].Code != "decoded_freeze_account" || findings[0].Severity != "high" || findings[0].Score != 30 {
		t.Fatalf("freeze finding=%#v", findings)
	}
	for _, required := range []string{"account=" + account, "mint=" + mint, "authority=" + authority} {
		if !strings.Contains(findings[0].Evidence, required) {
			t.Fatalf("freeze evidence missing %q: %q", required, findings[0].Evidence)
		}
	}

	assessment := finalizeEvidenceFirstGuardAssessment(
		transactionFirewallAssessment{Action: "allow", RiskLevel: "low", SimulationOK: true, Findings: findings},
		transactionGuardProgramPolicy{Complete: true},
		transactionGuardIntentPolicy{Complete: true},
	)
	if assessment.Action != "warn" || assessment.RiskLevel != "medium" {
		t.Fatalf("explicit FreezeAccount must not be allowed silently: %#v", assessment)
	}
}
