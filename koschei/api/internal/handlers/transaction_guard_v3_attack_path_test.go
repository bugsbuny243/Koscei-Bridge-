package handlers

import "testing"

func TestTransactionGuardAttackPathLinksAuthorityFlowAndStateLoss(t *testing.T) {
	wallet := guardV3TestAddress(1)
	delegate := guardV3TestAddress(2)
	destination := guardV3TestAddress(3)
	program := guardV3TestAddress(4)
	mint := guardV3TestAddress(5)

	decoded := transactionGuardDecodedTransaction{
		Available: true,
		Complete:  true,
		TokenOperations: []transactionGuardDecodedTokenOperation{
			{
				Kind:      "approve",
				ProgramID: guardV3SPLTokenProgramID,
				Source:    wallet,
				Authority: wallet,
				Delegate:  delegate,
				AmountRaw: "5000",
			},
		},
		AutomaticBalance: transactionGuardAutomaticBalanceAnalysis{
			Requested: true,
			Available: true,
			Complete:  true,
			Accounts: []transactionGuardAutomaticBalanceDelta{
				{
					Address:         wallet,
					Changed:         true,
					LamportDelta:    "-1000",
					TokenDeltaRaw:   "0",
					EvidenceStatus:  "verified_rpc_simulation",
				},
			},
		},
	}
	cpi := transactionGuardCPIFlowAnalysis{
		Requested: true,
		Required:  true,
		Available: true,
		Complete:  true,
		AssetMovements: []transactionGuardCPIAssetMovement{
			{
				AssetType:                 "token",
				Kind:                      "transfer",
				Source:                    wallet,
				Destination:               destination,
				Mint:                      mint,
				AmountRaw:                 "5000",
				ProgramID:                 program,
				ParentProgramID:           program,
				WalletOrigin:              true,
				InnerOnly:                 true,
				UndeclaredByAccountPolicy: true,
			},
		},
	}
	authority := transactionGuardAuthoritySurfaceAnalysis{
		Requested: true,
		Required:  true,
		Available: true,
		Complete:  true,
		Events: []transactionGuardAuthorityEvent{
			{
				Kind:          "approve",
				ProgramID:     guardV3SPLTokenProgramID,
				Account:       wallet,
				Delegate:      delegate,
				Persistent:    true,
				EvidenceStatus: "verified_post_state",
				Explanation:  "Delegate remains active after simulation.",
			},
		},
	}
	assessment := transactionFirewallAssessment{
		Findings: []transactionFirewallFinding{
			{Code: "delegate_approval", Severity: "high", Title: "Delegate approval", Evidence: "delegate can spend tokens", Score: 40},
		},
	}

	result := buildTransactionGuardAttackPaths(wallet, assessment, decoded, cpi, authority)
	if !result.Complete {
		t.Fatalf("expected complete attack-path evidence: %+v", result)
	}
	if result.Status != "attack_path_observed" || result.PathCount != 1 || len(result.Paths) != 1 {
		t.Fatalf("unexpected attack-path summary: %+v", result)
	}
	path := result.Paths[0]
	if path.Confidence != "high" {
		t.Fatalf("expected high confidence, got %q", path.Confidence)
	}
	if len(path.Steps) < 4 {
		t.Fatalf("expected decoded, authority, CPI and state-diff steps, got %+v", path.Steps)
	}
	for i, step := range path.Steps {
		if step.Sequence != i+1 {
			t.Fatalf("step sequence mismatch at %d: %+v", i, step)
		}
	}
}

func TestTransactionGuardAttackPathMarksIncompleteRequiredEvidence(t *testing.T) {
	decoded := transactionGuardDecodedTransaction{
		Available: true,
		Complete:  true,
		TokenOperations: []transactionGuardDecodedTokenOperation{
			{Kind: "set_authority", ProgramID: guardV3SPLTokenProgramID, Account: guardV3TestAddress(10), NewAuthority: guardV3TestAddress(11)},
		},
		AutomaticBalance: transactionGuardAutomaticBalanceAnalysis{Requested: true, Available: false, Complete: false},
	}
	cpi := transactionGuardCPIFlowAnalysis{Requested: true, Required: true, Available: false, Complete: false}
	authority := transactionGuardAuthoritySurfaceAnalysis{Requested: true, Required: true, Available: false, Complete: false}

	result := buildTransactionGuardAttackPaths("", transactionFirewallAssessment{}, decoded, cpi, authority)
	if result.Complete {
		t.Fatalf("incomplete required evidence must not be marked complete: %+v", result)
	}
	if result.PathCount != 1 || result.Paths[0].Confidence != "medium" {
		t.Fatalf("expected medium-confidence partial path: %+v", result)
	}
	if len(result.Limitations) == 0 {
		t.Fatalf("expected explicit limitations for incomplete evidence")
	}
}

func TestTransactionGuardAttackPathNoRiskPathWhenCompleteAndBenign(t *testing.T) {
	decoded := transactionGuardDecodedTransaction{
		Available: true,
		Complete:  true,
		AutomaticBalance: transactionGuardAutomaticBalanceAnalysis{Requested: true, Available: true, Complete: true, Accounts: []transactionGuardAutomaticBalanceDelta{}},
	}
	cpi := transactionGuardCPIFlowAnalysis{Requested: true, Required: true, Available: true, Complete: true, AssetMovements: []transactionGuardCPIAssetMovement{}}
	authority := transactionGuardAuthoritySurfaceAnalysis{Requested: true, Required: true, Available: true, Complete: true, Events: []transactionGuardAuthorityEvent{}}

	result := buildTransactionGuardAttackPaths("", transactionFirewallAssessment{}, decoded, cpi, authority)
	if !result.Complete || result.Status != "no_attack_path_observed" || result.PathCount != 0 {
		t.Fatalf("expected complete benign result, got %+v", result)
	}
}
