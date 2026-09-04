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
		TokenOperations: []transactionGuardDecodedTokenOperation{{
			Kind: "approve", ProgramID: guardV3SPLTokenProgramID, Source: wallet, Authority: wallet, Delegate: delegate, AmountRaw: "5000",
		}},
		AutomaticBalance: transactionGuardAutomaticBalanceAnalysis{
			Requested: true, Available: true, Complete: true,
			Accounts: []transactionGuardAutomaticBalanceDelta{{Address: wallet, Changed: true, LamportDelta: "-1000", TokenDeltaRaw: "0", EvidenceStatus: "verified_rpc_simulation"}},
		},
	}
	cpi := transactionGuardCPIFlowAnalysis{
		Requested: true, Required: true, Available: true, Complete: true,
		AssetMovements: []transactionGuardCPIAssetMovement{{
			AssetType: "token", Kind: "transfer", Source: wallet, Destination: destination, Mint: mint, AmountRaw: "5000",
			ProgramID: program, ParentProgramID: program, WalletOrigin: true, InnerOnly: true, UndeclaredByAccountPolicy: true,
		}},
	}
	authority := transactionGuardAuthoritySurfaceAnalysis{
		Requested: true, Required: true, Available: true, Complete: true,
		Events: []transactionGuardAuthorityEvent{{
			Kind: "approve", ProgramID: guardV3SPLTokenProgramID, Account: wallet, Delegate: delegate, Persistent: true,
			EvidenceStatus: "verified_post_state", Explanation: "Delegate remains active after simulation.",
		}},
	}
	assessment := transactionFirewallAssessment{Findings: []transactionFirewallFinding{{Code: "delegate_approval", Severity: "high", Title: "Delegate approval", Evidence: "delegate can spend tokens", Score: 40}}}

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

func TestTransactionGuardAttackPathPermanentDelegateIsCritical(t *testing.T) {
	mint := guardV3TestAddress(20)
	delegate := guardV3TestAddress(21)
	decoded := transactionGuardDecodedTransaction{
		Available: true, Complete: true,
		TokenOperations: []transactionGuardDecodedTokenOperation{{Kind: "initialize_permanent_delegate", ProgramID: guardV3Token2022ProgramID, Mint: mint, Account: mint, Delegate: delegate, NewAuthority: delegate}},
		AutomaticBalance: transactionGuardAutomaticBalanceAnalysis{Requested: false, Complete: true},
	}
	authority := transactionGuardAuthoritySurfaceAnalysis{
		Requested: true, Required: true, Available: true, Complete: true,
		Events: []transactionGuardAuthorityEvent{{Kind: "initialize_permanent_delegate", ProgramID: guardV3Token2022ProgramID, Mint: mint, Account: mint, Delegate: delegate, NewAuthority: delegate, Persistent: true, MintWide: true, CanTransfer: true, CanBurn: true, Explanation: "Permanent delegate controls every token account for this mint."}},
	}
	result := buildTransactionGuardAttackPaths("", transactionFirewallAssessment{}, decoded, transactionGuardCPIFlowAnalysis{Required: false, Complete: true}, authority)
	if result.PathCount != 1 || len(result.Paths[0].Steps) < 2 {
		t.Fatalf("permanent delegate path missing: %+v", result)
	}
	if result.Paths[0].Steps[0].Severity != "critical" || result.Paths[0].Steps[1].Severity != "critical" {
		t.Fatalf("permanent delegate must be critical: %+v", result.Paths[0].Steps)
	}
}

func TestTransactionGuardAttackPathTransferHookSurfacesPersistentExecutionControl(t *testing.T) {
	mint := guardV3TestAddress(30)
	hook := guardV3TestAddress(31)
	decoded := transactionGuardDecodedTransaction{
		Available: true, Complete: true,
		TokenOperations: []transactionGuardDecodedTokenOperation{{Kind: "initialize_transfer_hook", ProgramID: guardV3Token2022ProgramID, Mint: mint, Account: mint, NewAuthority: hook}},
		AutomaticBalance: transactionGuardAutomaticBalanceAnalysis{Requested: false, Complete: true},
	}
	authority := transactionGuardAuthoritySurfaceAnalysis{
		Requested: true, Required: true, Available: true, Complete: true,
		Events: []transactionGuardAuthorityEvent{{Kind: "initialize_transfer_hook", ProgramID: guardV3Token2022ProgramID, Mint: mint, Account: mint, TransferHookProgramID: hook, Persistent: true, Explanation: "Future token transfers invoke the configured hook."}},
	}
	result := buildTransactionGuardAttackPaths("", transactionFirewallAssessment{}, decoded, transactionGuardCPIFlowAnalysis{Required: false, Complete: true}, authority)
	if result.Status != "attack_path_observed" || result.PathCount != 1 {
		t.Fatalf("transfer-hook path missing: %+v", result)
	}
	found := false
	for _, step := range result.Paths[0].Steps {
		if step.Layer == "authority_surface" && step.Kind == "initialize_transfer_hook" && step.Counterparty == hook {
			found = true
		}
	}
	if !found {
		t.Fatalf("persistent transfer-hook authority not surfaced: %+v", result.Paths[0].Steps)
	}
}

func TestTransactionGuardAttackPathSignedIntentMismatchHasDedicatedBoundary(t *testing.T) {
	decoded := transactionGuardDecodedTransaction{Available: true, Complete: true, AutomaticBalance: transactionGuardAutomaticBalanceAnalysis{Requested: false, Complete: true}}
	assessment := transactionFirewallAssessment{Findings: []transactionFirewallFinding{{
		Code: "signed_ui_intent_policy_mismatch", Severity: "critical", Title: "Signed UI policy does not match", Evidence: "signed expected_programs differ from submitted transaction policy", Score: 100,
	}}}
	result := buildTransactionGuardAttackPaths("", assessment, decoded, transactionGuardCPIFlowAnalysis{Required: false, Complete: true}, transactionGuardAuthoritySurfaceAnalysis{Required: false, Complete: true})
	if result.PathCount != 1 || len(result.Paths[0].Steps) != 1 {
		t.Fatalf("signed-intent path missing: %+v", result)
	}
	step := result.Paths[0].Steps[0]
	if step.Layer != "signed_intent_boundary" || step.Kind != "signed_ui_intent_policy_mismatch" || step.Severity != "critical" {
		t.Fatalf("signed intent mismatch not isolated as boundary evidence: %+v", step)
	}
}

func TestTransactionGuardAttackPathAccountCloseLinksStateClosure(t *testing.T) {
	wallet := guardV3TestAddress(40)
	account := guardV3TestAddress(41)
	destination := guardV3TestAddress(42)
	decoded := transactionGuardDecodedTransaction{
		Available: true, Complete: true,
		TokenOperations: []transactionGuardDecodedTokenOperation{{Kind: "close_account", ProgramID: guardV3SPLTokenProgramID, Account: account, Destination: destination, Authority: wallet}},
		AutomaticBalance: transactionGuardAutomaticBalanceAnalysis{
			Requested: true, Available: true, Complete: true,
			Accounts: []transactionGuardAutomaticBalanceDelta{{Address: account, PreTokenOwner: wallet, Changed: true, AccountClosed: true, LamportDelta: "-2039280", EvidenceStatus: "verified_rpc_simulation"}},
		},
	}
	result := buildTransactionGuardAttackPaths(wallet, transactionFirewallAssessment{}, decoded, transactionGuardCPIFlowAnalysis{Required: false, Complete: true}, transactionGuardAuthoritySurfaceAnalysis{Required: false, Complete: true})
	if result.PathCount != 1 || len(result.Paths[0].Steps) < 2 {
		t.Fatalf("account-close state path missing: %+v", result)
	}
	if result.Paths[0].Steps[0].Kind != "close_account" || result.Paths[0].Steps[1].Layer != "state_diff" {
		t.Fatalf("account close must link decoded action to simulated closure: %+v", result.Paths[0].Steps)
	}
}

func TestTransactionGuardAttackPathMarksIncompleteRequiredEvidence(t *testing.T) {
	decoded := transactionGuardDecodedTransaction{
		Available: true, Complete: true,
		TokenOperations: []transactionGuardDecodedTokenOperation{{Kind: "set_authority", ProgramID: guardV3SPLTokenProgramID, Account: guardV3TestAddress(10), NewAuthority: guardV3TestAddress(11)}},
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
	decoded := transactionGuardDecodedTransaction{Available: true, Complete: true, AutomaticBalance: transactionGuardAutomaticBalanceAnalysis{Requested: true, Available: true, Complete: true, Accounts: []transactionGuardAutomaticBalanceDelta{}}}
	cpi := transactionGuardCPIFlowAnalysis{Requested: true, Required: true, Available: true, Complete: true, AssetMovements: []transactionGuardCPIAssetMovement{}}
	authority := transactionGuardAuthoritySurfaceAnalysis{Requested: true, Required: true, Available: true, Complete: true, Events: []transactionGuardAuthorityEvent{}}

	result := buildTransactionGuardAttackPaths("", transactionFirewallAssessment{}, decoded, cpi, authority)
	if !result.Complete || result.Status != "no_attack_path_observed" || result.PathCount != 0 {
		t.Fatalf("expected complete benign result, got %+v", result)
	}
}
