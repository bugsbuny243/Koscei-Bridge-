package handlers

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"koschei/api/internal/defense"
	"koschei/api/internal/executioncontainment"
	"koschei/api/internal/executionproof"
	"koschei/api/internal/securityevidence"
)

func TestDefenseValidationAPIValidatesBoundAttackAndBenignPair(t *testing.T) {
	request := defenseValidationAPITestRequest(t)
	response, err := evaluateDefenseValidationAPIRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.Product != "Koschei Defense Validation" {
		t.Fatalf("unexpected response: %#v", response)
	}
	if response.Report.Verdict != defense.DefenseValidationVerdictValidatedV02 {
		t.Fatalf("verdict=%s", response.Report.Verdict)
	}
	if response.VerifiedExecutions != 2 || response.VerifiedObservations != 2 {
		t.Fatalf("coverage executions=%d observations=%d", response.VerifiedExecutions, response.VerifiedObservations)
	}
	if response.Report.ReportHash == "" || response.ScenarioContractHash == "" {
		t.Fatal("deterministic evidence hashes missing")
	}
	if response.MainnetTransactionSent || response.ExecutionAuthority || response.ProductionControlMutation {
		t.Fatal("unsafe authority surfaced in evidence evaluator")
	}
}

func TestDefenseValidationAPIRejectsForgedIndependentCollectorEvent(t *testing.T) {
	request := defenseValidationAPITestRequest(t)
	forged := *request.Cases[0].ObservationEvent
	forged.Authentication = nil
	request.Cases[0].ObservationEvent = &forged
	if _, err := evaluateDefenseValidationAPIRequest(request); err == nil || !strings.Contains(err.Error(), "independent observation rejected") {
		t.Fatalf("forged observation was not rejected: %v", err)
	}
}

func TestDefenseValidationAPIMissingObservationStaysIncomplete(t *testing.T) {
	request := defenseValidationAPITestRequest(t)
	for index := range request.Cases {
		request.Cases[index].ObservationBinding = nil
		request.Cases[index].ObservationEvent = nil
	}
	response, err := evaluateDefenseValidationAPIRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.Report.Verdict != defense.DefenseValidationVerdictIncompleteV02 {
		t.Fatalf("missing observations must remain incomplete, got %s", response.Report.Verdict)
	}
	if response.VerifiedObservations != 0 {
		t.Fatalf("verified observations=%d", response.VerifiedObservations)
	}
}

func TestDefenseValidationAPIRejectsOversizedAction(t *testing.T) {
	_, err := decodeDefenseValidationAPIAction(defenseValidationAPIAction{
		Kind: "safe_transaction", CanonicalBase64: base64.StdEncoding.EncodeToString(make([]byte, defenseValidationAPIMaxActionBytes+1)),
	})
	if err == nil {
		t.Fatal("oversized action accepted")
	}
}

func defenseValidationAPITestRequest(t *testing.T) defenseValidationAPIRequest {
	t.Helper()
	scenarioBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "docs", "defense-validation", "scenarios", "safe-intent-mutation-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	scenario, err := defense.ParseDefenseValidationScenarioV02(scenarioBytes)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := defenseValidationAPITestPrivateKey()
	publicKey := base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
	control, err := defense.NewExecutionIntegrityControlV02(
		"control:execution-integrity",
		"collector:independent-safe-observer",
		defense.DefenseValidationExecutionIntegrityConfigV02{CollectorPublicKey: publicKey, IndependentCollectorRequired: true},
	)
	if err != nil {
		t.Fatal(err)
	}

	approved, mutated := defenseValidationAPITestSafeTransactions()
	attack := defenseValidationAPITestCase(t, scenario, control, privateKey, approved, mutated, defense.DefenseValidationCaseAttackV02)
	benign := defenseValidationAPITestCase(t, scenario, control, privateKey, approved, approved, defense.DefenseValidationCaseBenignV02)

	return defenseValidationAPIRequest{
		RunRef:   "run:enterprise-api:test",
		Scenario: scenarioBytes,
		Controls: []defenseValidationAPIControl{{
			ControlRef: control.ControlRef, CollectorRef: control.CollectorRef, CollectorPublicKey: publicKey,
		}},
		Cases: []defenseValidationAPICase{attack, benign},
	}
}

func defenseValidationAPITestCase(
	t *testing.T,
	scenario defense.DefenseValidationScenarioV02,
	control defense.DefenseValidationControlV02,
	privateKey ed25519.PrivateKey,
	approved executionproof.SafeTransaction,
	candidate executionproof.SafeTransaction,
	kind string,
) defenseValidationAPICase {
	t.Helper()
	proof, receipt := defenseValidationAPITestProofAndReceipt(t, approved, candidate)
	approvedAction, err := executionproof.CanonicalSafeActionArtifact(approved)
	if err != nil {
		t.Fatal(err)
	}
	candidateAction, err := executionproof.CanonicalSafeActionArtifact(candidate)
	if err != nil {
		t.Fatal(err)
	}
	caseRef := "case:evm:safe-authorized-transfer-benign"
	var impact *int64
	if kind == defense.DefenseValidationCaseAttackV02 {
		caseRef = "case:evm:safe-intent-mutation-attack"
		value := int64(1000)
		impact = &value
	}
	execution, err := defense.AdaptExecutionIntegrityCaseV02(defense.DefenseValidationExecutionAdapterInputV02{
		CaseRef: caseRef, CaseKind: kind, TechniqueID: "safe-intent-mutation", ExecutionMode: defense.DefenseValidationExecutionForkV02,
		ImpactOffsetMS: impact, ObservationWindowMS: 3000, Control: control, Scenario: scenario,
		ContainmentReceipt: receipt, ExecutionProof: proof, ApprovedSafeAction: approvedAction, CandidateSafeAction: candidateAction,
	})
	if err != nil {
		t.Fatal(err)
	}

	status := defense.DefenseValidationObservationNoAlertV02
	var alert *int64
	if execution.ControlSignaled {
		status = defense.DefenseValidationObservationAlertedV02
		value := int64(120)
		alert = &value
	}
	binding := defense.DefenseValidationObservationBindingV02{
		Version: defense.DefenseValidationObservationBindingVersionV02, Chain: execution.Case.Chain,
		ControlRef: control.ControlRef, CaseRef: execution.Case.CaseRef, Status: status, ExecutionHash: execution.Case.ExecutionHash,
		AlertObservedOffsetMS: alert, ObservationCompletedOffsetMS: execution.Case.ObservationWindowMS,
	}
	bindingDigest, err := defense.DefenseValidationObservationBindingDigestV02(binding)
	if err != nil {
		t.Fatal(err)
	}
	event, err := (securityevidence.Event{
		Producer: control.CollectorRef,
		Subject:  securityevidence.Subject{Chain: execution.Case.Chain, Type: defense.DefenseValidationObservationSubjectTypeV02, ID: execution.Case.CaseRef},
		Window:   securityevidence.ObservationWindow{FromUnixMS: 0, ToUnixMS: execution.Case.ObservationWindowMS},
		SourceDigests: []string{
			execution.ContainmentReceiptSHA256,
			execution.ExecutionProofSHA256,
		},
		Findings: []securityevidence.Finding{{
			ID:   defense.DefenseValidationObservationFindingIDV02(control.ControlRef, execution.Case.CaseRef),
			Kind: defense.DefenseValidationObservationFindingKindV02, State: securityevidence.StateVerified,
			EvidenceSHA256: bindingDigest, Summary: "Independent observation of the bound defense-validation case.",
		}},
	}).SignEd25519(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	return defenseValidationAPICase{
		CaseRef: caseRef, CaseKind: kind, TechniqueID: "safe-intent-mutation", ControlRef: control.ControlRef,
		ExecutionMode: defense.DefenseValidationExecutionForkV02, ImpactOffsetMS: impact, ObservationWindowMS: 3000,
		ContainmentReceipt: receipt, ExecutionProof: proof,
		ApprovedAction:     defenseValidationAPIAction{Kind: approvedAction.Kind, CanonicalBase64: base64.StdEncoding.EncodeToString(approvedAction.Canonical)},
		CandidateAction:    defenseValidationAPIAction{Kind: candidateAction.Kind, CanonicalBase64: base64.StdEncoding.EncodeToString(candidateAction.Canonical)},
		ObservationBinding: &binding, ObservationEvent: &event,
	}
}

func defenseValidationAPITestSafeTransactions() (executionproof.SafeTransaction, executionproof.SafeTransaction) {
	approved := executionproof.SafeTransaction{
		ChainID: 31337, Safe: "0x1111111111111111111111111111111111111111", To: "0x2222222222222222222222222222222222222222",
		Value: big.NewInt(1_000_000_000_000_000_000), Data: []byte{0xaa, 0xbb, 0xcc, 0x01}, Operation: 0,
		SafeTxGas: big.NewInt(50000), BaseGas: big.NewInt(21000), GasPrice: big.NewInt(0),
		GasToken: "0x0000000000000000000000000000000000000000", RefundReceiver: "0x0000000000000000000000000000000000000000", Nonce: big.NewInt(7),
	}
	candidate := approved
	candidate.To = "0x9999999999999999999999999999999999999999"
	candidate.Data = []byte{0xde, 0xad, 0xbe, 0xef}
	return approved, candidate
}

func defenseValidationAPITestProofAndReceipt(t *testing.T, approved, candidate executionproof.SafeTransaction) (executionproof.Proof, executioncontainment.Receipt) {
	t.Helper()
	approvedHash, err := (executionproof.NativeSafeTxHashComputer{}).ComputeSafeTxHash(approved)
	if err != nil {
		t.Fatal(err)
	}
	candidateHash, err := (executionproof.NativeSafeTxHashComputer{}).ComputeSafeTxHash(candidate)
	if err != nil {
		t.Fatal(err)
	}
	approvedPayload := defenseValidationAPISHA(approved.Data)
	candidatePayload := defenseValidationAPISHA(candidate.Data)
	artifact := strings.Repeat("1", 64)
	invariant := strings.Repeat("2", 64)
	proof, err := executionproof.Evaluate(executionproof.Envelope{
		Source: executionproof.SourceEvidence{CommitID: strings.Repeat("a", 40), TreeID: strings.Repeat("b", 40)},
		Build: executionproof.BuildEvidence{
			ToolchainSHA256: strings.Repeat("3", 64), ApprovedArtifactSHA256: artifact, BuiltArtifactSHA256: artifact,
		},
		Runtime: executionproof.RuntimeEvidence{ObservedArtifactSHA256: artifact, PolicySHA256: strings.Repeat("4", 64)},
		Payload: executionproof.PayloadEvidence{
			ChainID: candidate.ChainID, Target: candidate.To, ApprovedCalldataSHA256: approvedPayload,
			GeneratedCalldataSHA256: candidatePayload, GeneratorSHA256: strings.Repeat("5", 64),
		},
		Simulation: executionproof.SimulationEvidence{InvariantSetSHA256: invariant, Result: "PASS"},
		Authorization: executionproof.AuthorizationEvidence{
			SigningPolicySHA256: strings.Repeat("6", 64), ApprovedSigningRequestID: approvedHash,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	action, err := executionproof.CanonicalSafeActionArtifact(candidate)
	if err != nil {
		t.Fatal(err)
	}
	blockHash := strings.Repeat("7", 64)
	runnerHash := strings.Repeat("8", 64)
	receipt, err := executioncontainment.Evaluate(executioncontainment.CellInput{
		ChainID: candidate.ChainID, BlockNumber: 23456789, BlockHash: blockHash, Target: candidate.To,
		ApprovedIntentSHA256: strings.TrimPrefix(approvedHash, "0x"), CandidateIntentSHA256: strings.TrimPrefix(candidateHash, "0x"),
		ApprovedPayloadSHA256: approvedPayload, CandidatePayloadSHA256: candidatePayload, ActionSHA256: action.SHA256(),
		InvariantSetSHA256: invariant, ApprovedRunnerSHA256: runnerHash,
	}, executioncontainment.Observation{
		BackendAvailable: true, ObservedChainID: candidate.ChainID, ObservedBlockNumber: 23456789,
		ObservedBlockHash: blockHash, ObservedRunnerSHA256: runnerHash,
		PreStateSHA256: strings.Repeat("9", 64), PostStateSHA256: strings.Repeat("a", 64), EffectSetSHA256: strings.Repeat("b", 64),
		AuthorityPreserved: true, AssetBoundsPreserved: true, CodeIntegrityPreserved: true,
		ExecutionPathFullyObserved: true, InvariantsPass: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return proof, receipt
}

func defenseValidationAPITestPrivateKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = 0x64
	}
	return ed25519.NewKeyFromSeed(seed)
}

func defenseValidationAPISHA(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
