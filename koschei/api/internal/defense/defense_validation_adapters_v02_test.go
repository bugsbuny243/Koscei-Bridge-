package defense

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"koschei/api/internal/executioncontainment"
	"koschei/api/internal/executionproof"
	"koschei/api/internal/securityevidence"
)

func TestSafeIntentMutationWeakBindingFailsAndExactBindingValidates(t *testing.T) {
	control := dvControl(t)
	scenario := readDefenseValidationScenarioFixtureV02(t, "safe-intent-mutation-v1.json")
	scenarioHash, err := DefenseValidationScenarioDigestV02(scenario)
	if err != nil {
		t.Fatal(err)
	}
	approved, mutated := dvSafeTransactions()

	weakProof, weakReceipt := dvProofAndReceipt(t, approved, mutated, true)
	impact := int64(1000)
	_, err = AdaptExecutionIntegrityCaseV02(DefenseValidationExecutionAdapterInputV02{
		CaseRef: "case:evm:safe-intent-mutation-attack", CaseKind: DefenseValidationCaseAttackV02,
		TechniqueID: "safe-intent-mutation", ExecutionMode: DefenseValidationExecutionForkV02,
		ImpactOffsetMS: &impact, ObservationWindowMS: 3000, Control: control, Scenario: scenario,
		ContainmentReceipt: weakReceipt, ExecutionProof: weakProof,
		ApprovedSafeAction: dvAction(t, mutated), CandidateSafeAction: dvAction(t, mutated),
	})
	if err == nil || !strings.Contains(err.Error(), "scenario-declared intent or payload mismatch") {
		t.Fatalf("weak approved-action rebinding was accepted as the declared attack: %v", err)
	}
	benign := dvExecution(t, approved, approved, false, DefenseValidationCaseBenignV02)

	exactAttack := dvExecution(t, approved, mutated, false, DefenseValidationCaseAttackV02)
	alert := int64(120)
	exactReport, err := EvaluateDefenseValidationV02(DefenseValidationInputV02{
		RunRef: "run:exact", Scenario: scenario, ScenarioRef: scenario.ScenarioRef, ScenarioVersion: scenario.ScenarioVersion, ScenarioContractHash: scenarioHash, Chain: scenario.Chain, ChainID: approved.ChainID, RulesetVersion: DefenseValidationRulesetVersionV02,
		Controls: []DefenseValidationControlV02{control}, Cases: []DefenseValidationCaseV02{exactAttack.Case, benign.Case},
		Observations: []DefenseValidationObservationV02{dvObservation(t, control, exactAttack, &alert), dvObservation(t, control, benign, nil)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if exactReport.Verdict != DefenseValidationVerdictValidatedV02 {
		t.Fatalf("exact verdict=%s", exactReport.Verdict)
	}
	attackResult := dvCaseResult(t, exactReport, exactAttack.Case.CaseRef)
	if attackResult.Outcome != DefenseValidationOutcomeCaughtInTimeV02 {
		t.Fatalf("exact attack outcome=%s", attackResult.Outcome)
	}
	if attackResult.LeadTimeMS == nil || *attackResult.LeadTimeMS != 880 {
		t.Fatalf("lead time=%v", attackResult.LeadTimeMS)
	}
	if got := dvCaseResult(t, exactReport, benign.Case.CaseRef); got.Outcome != DefenseValidationOutcomeCleanV02 {
		t.Fatalf("benign outcome=%s", got.Outcome)
	}
	if !exactAttack.ControlSignaled || exactAttack.ContainmentDecision != executioncontainment.DecisionContain || exactAttack.ExecutionProofDecision != executionproof.DecisionBlock {
		t.Fatalf("exact control signals=%s/%s/%v", exactAttack.ContainmentDecision, exactAttack.ExecutionProofDecision, exactAttack.ControlSignaled)
	}
	if benign.ControlSignaled || benign.ContainmentDecision != executioncontainment.DecisionRelease || benign.ExecutionProofDecision != executionproof.DecisionAllow {
		t.Fatalf("benign control signals=%s/%s/%v", benign.ContainmentDecision, benign.ExecutionProofDecision, benign.ControlSignaled)
	}
}

func TestDefenseValidationAdapterRejectsSelfAttestedObservation(t *testing.T) {
	control := dvControl(t)
	approved, mutated := dvSafeTransactions()
	execution := dvExecution(t, approved, mutated, false, DefenseValidationCaseAttackV02)
	alert := int64(120)
	binding := dvBinding(control, execution, &alert)
	digest, err := DefenseValidationObservationBindingDigestV02(binding)
	if err != nil {
		t.Fatal(err)
	}
	event, err := (securityevidence.Event{
		Producer:      control.ControlRef,
		Subject:       securityevidence.Subject{Chain: "evm", Type: DefenseValidationObservationSubjectTypeV02, ID: execution.Case.CaseRef},
		Window:        securityevidence.ObservationWindow{FromUnixMS: 0, ToUnixMS: execution.Case.ObservationWindowMS},
		SourceDigests: []string{execution.ContainmentReceiptSHA256, execution.ExecutionProofSHA256},
		Findings:      []securityevidence.Finding{{ID: DefenseValidationObservationFindingIDV02(control.ControlRef, execution.Case.CaseRef), Kind: DefenseValidationObservationFindingKindV02, State: securityevidence.StateVerified, EvidenceSHA256: digest}},
	}).SignEd25519(dvCollectorPrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdaptSecurityEvidenceObservationV02(control, execution, binding, event); err == nil {
		t.Fatal("self-attestation accepted")
	}
}

func TestDefenseValidationAdapterRejectsCallerResealedCollectorEvent(t *testing.T) {
	control := dvControl(t)
	approved, mutated := dvSafeTransactions()
	execution := dvExecution(t, approved, mutated, false, DefenseValidationCaseAttackV02)
	alert := int64(120)
	binding := dvBinding(control, execution, &alert)
	digest, err := DefenseValidationObservationBindingDigestV02(binding)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := (securityevidence.Event{
		Producer:      control.CollectorRef,
		Subject:       securityevidence.Subject{Chain: "evm", Type: DefenseValidationObservationSubjectTypeV02, ID: execution.Case.CaseRef},
		Window:        securityevidence.ObservationWindow{FromUnixMS: 0, ToUnixMS: execution.Case.ObservationWindowMS},
		SourceDigests: []string{execution.ContainmentReceiptSHA256, execution.ExecutionProofSHA256},
		Findings:      []securityevidence.Finding{{ID: DefenseValidationObservationFindingIDV02(control.ControlRef, execution.Case.CaseRef), Kind: DefenseValidationObservationFindingKindV02, State: securityevidence.StateVerified, EvidenceSHA256: digest}},
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdaptSecurityEvidenceObservationV02(control, execution, binding, forged); err == nil || !strings.Contains(err.Error(), "authenticate") {
		t.Fatalf("caller-resealed collector event was accepted: %v", err)
	}
}

func TestDefenseValidationAdapterRejectsTamperedExecutionProof(t *testing.T) {
	approved, mutated := dvSafeTransactions()
	proof, receipt := dvProofAndReceipt(t, approved, mutated, false)
	proof.Evaluation.Decision = executionproof.DecisionAllow
	impact := int64(1000)
	_, err := AdaptExecutionIntegrityCaseV02(DefenseValidationExecutionAdapterInputV02{CaseRef: "case:evm:safe-intent-mutation-attack", CaseKind: DefenseValidationCaseAttackV02, TechniqueID: "safe-intent-mutation", ExecutionMode: DefenseValidationExecutionForkV02, ImpactOffsetMS: &impact, ObservationWindowMS: 3000, Control: dvControl(t), Scenario: readDefenseValidationScenarioFixtureV02(t, "safe-intent-mutation-v1.json"), ContainmentReceipt: receipt, ExecutionProof: proof, ApprovedSafeAction: dvAction(t, approved), CandidateSafeAction: dvAction(t, mutated)})
	if err == nil {
		t.Fatal("tampered proof accepted")
	}
}

func TestExecutionIntegrityAdapterBindsEveryDeclaredScenarioValue(t *testing.T) {
	tests := map[string]struct {
		mutateActions  func(*executionproof.SafeTransaction, *executionproof.SafeTransaction)
		mutateScenario func([]byte) []byte
	}{
		"safe": {mutateActions: func(approved, candidate *executionproof.SafeTransaction) {
			approved.Safe = "0x3333333333333333333333333333333333333333"
			candidate.Safe = approved.Safe
		}},
		"chain_id": {mutateActions: func(approved, candidate *executionproof.SafeTransaction) {
			approved.ChainID = 31338
			candidate.ChainID = approved.ChainID
		}},
		"transfer_amount": {mutateActions: func(approved, candidate *executionproof.SafeTransaction) {
			approved.Value = big.NewInt(2_000_000_000_000_000_000)
			candidate.Value = new(big.Int).Set(approved.Value)
		}},
		"treasury_asset": {mutateScenario: func(data []byte) []byte {
			return bytes.ReplaceAll(data, []byte(`"treasury_asset": "native"`), []byte(`"treasury_asset": "erc20"`))
		}},
	}
	for field, test := range tests {
		t.Run(field, func(t *testing.T) {
			approved, _ := dvSafeTransactions()
			candidate := approved
			if test.mutateActions != nil {
				test.mutateActions(&approved, &candidate)
			}
			data := readDefenseValidationScenarioFixtureBytesV02(t, "safe-intent-mutation-v1.json")
			if test.mutateScenario != nil {
				data = test.mutateScenario(data)
			}
			scenario, err := ParseDefenseValidationScenarioV02(data)
			if err != nil {
				t.Fatal(err)
			}
			proof, receipt := dvProofAndReceipt(t, approved, candidate, false)
			_, err = AdaptExecutionIntegrityCaseV02(DefenseValidationExecutionAdapterInputV02{
				CaseRef: "case:evm:safe-authorized-transfer-benign", CaseKind: DefenseValidationCaseBenignV02,
				TechniqueID: "safe-intent-mutation", ExecutionMode: DefenseValidationExecutionForkV02,
				ObservationWindowMS: 3000, Control: dvControl(t), Scenario: scenario,
				ContainmentReceipt: receipt, ExecutionProof: proof,
				ApprovedSafeAction: dvAction(t, approved), CandidateSafeAction: dvAction(t, candidate),
			})
			if err == nil || !strings.Contains(err.Error(), `scenario field "`+field+`"`) {
				t.Fatalf("execution mismatch for %q was accepted: %v", field, err)
			}
		})
	}
}

func TestExecutionIntegrityAdapterRejectsUnboundSafeActionMaterial(t *testing.T) {
	approved, mutated := dvSafeTransactions()
	proof, receipt := dvProofAndReceipt(t, approved, mutated, false)
	base := DefenseValidationExecutionAdapterInputV02{
		CaseRef: "case:evm:safe-intent-mutation-attack", CaseKind: DefenseValidationCaseAttackV02,
		TechniqueID: "safe-intent-mutation", ExecutionMode: DefenseValidationExecutionForkV02,
		ObservationWindowMS: 3000, Control: dvControl(t), Scenario: readDefenseValidationScenarioFixtureV02(t, "safe-intent-mutation-v1.json"),
		ContainmentReceipt: receipt, ExecutionProof: proof,
		ApprovedSafeAction: dvAction(t, approved), CandidateSafeAction: dvAction(t, mutated),
	}
	impact := int64(1000)
	base.ImpactOffsetMS = &impact

	wrongCandidate := base
	wrongCandidate.CandidateSafeAction = dvAction(t, approved)
	if _, err := AdaptExecutionIntegrityCaseV02(wrongCandidate); err == nil || !strings.Contains(err.Error(), "containment action digest") {
		t.Fatalf("unbound candidate Safe action was accepted: %v", err)
	}

	wrongApproved := base
	wrongApproved.ApprovedSafeAction = dvAction(t, mutated)
	if _, err := AdaptExecutionIntegrityCaseV02(wrongApproved); err == nil || !strings.Contains(err.Error(), "does not match containment and execution proof") {
		t.Fatalf("unbound approved Safe action was accepted: %v", err)
	}
}

func TestExecutionIntegrityAdapterRequiresDeclaredSafeIntentMismatchSignal(t *testing.T) {
	approved, mutated := dvSafeTransactions()
	impact := int64(1000)
	base := DefenseValidationExecutionAdapterInputV02{
		CaseRef: "case:evm:safe-intent-mutation-attack", CaseKind: DefenseValidationCaseAttackV02,
		TechniqueID: "safe-intent-mutation", ExecutionMode: DefenseValidationExecutionForkV02,
		ImpactOffsetMS: &impact, ObservationWindowMS: 3000, Control: dvControl(t),
		Scenario: readDefenseValidationScenarioFixtureV02(t, "safe-intent-mutation-v1.json"),
	}

	proof, release := dvProofAndReceipt(t, approved, approved, false)
	unrelatedObservation := release.Observation
	unrelatedObservation.AuthorityPreserved = false
	unrelated, err := executioncontainment.Evaluate(release.Input, unrelatedObservation)
	if err != nil {
		t.Fatal(err)
	}
	unchanged := base
	unchanged.ContainmentReceipt = unrelated
	unchanged.ExecutionProof = proof
	unchanged.ApprovedSafeAction = dvAction(t, approved)
	unchanged.CandidateSafeAction = dvAction(t, approved)
	if _, err := AdaptExecutionIntegrityCaseV02(unchanged); err == nil || !strings.Contains(err.Error(), "scenario-declared intent or payload mismatch") {
		t.Fatalf("unchanged action contained for an unrelated reason was accepted as the Safe attack: %v", err)
	}

	proof, receipt := dvProofAndReceipt(t, approved, mutated, false)
	unrelatedObservation = receipt.Observation
	unrelatedObservation.ObservedBlockNumber++
	receipt, err = executioncontainment.Evaluate(receipt.Input, unrelatedObservation)
	if err != nil {
		t.Fatal(err)
	}
	withPinnedStateFailure := base
	withPinnedStateFailure.ContainmentReceipt = receipt
	withPinnedStateFailure.ExecutionProof = proof
	withPinnedStateFailure.ApprovedSafeAction = dvAction(t, approved)
	withPinnedStateFailure.CandidateSafeAction = dvAction(t, mutated)
	if _, err := AdaptExecutionIntegrityCaseV02(withPinnedStateFailure); err == nil || !strings.Contains(err.Error(), "unrelated reason") {
		t.Fatalf("Safe attack with unrelated pinned-state failure was accepted: %v", err)
	}
}

func TestExecutionIntegrityControlRejectsUnsafeClaims(t *testing.T) {
	cfg := DefenseValidationExecutionIntegrityConfigV02{CollectorPublicKey: dvCollectorPublicKey(), IndependentCollectorRequired: true, MainnetSubmissionAllowed: true}
	if _, err := NewExecutionIntegrityControlV02("control", "collector", cfg); err == nil {
		t.Fatal("mainnet-enabled control accepted")
	}
	cfg.MainnetSubmissionAllowed = false
	cfg.ProductionWiringClaim = true
	if _, err := NewExecutionIntegrityControlV02("control", "collector", cfg); err == nil {
		t.Fatal("unproven production claim accepted")
	}
}

func dvControl(t *testing.T) DefenseValidationControlV02 {
	t.Helper()
	control, err := NewExecutionIntegrityControlV02("control:execution-integrity", "collector:independent-safe-observer", DefenseValidationExecutionIntegrityConfigV02{CollectorPublicKey: dvCollectorPublicKey(), IndependentCollectorRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	return control
}

func dvSafeTransactions() (executionproof.SafeTransaction, executionproof.SafeTransaction) {
	approved := executionproof.SafeTransaction{ChainID: 31337, Safe: "0x1111111111111111111111111111111111111111", To: "0x2222222222222222222222222222222222222222", Value: big.NewInt(1_000_000_000_000_000_000), Data: []byte{0xaa, 0xbb, 0xcc, 0x01}, Operation: 0, SafeTxGas: big.NewInt(50000), BaseGas: big.NewInt(21000), GasPrice: big.NewInt(0), GasToken: "0x0000000000000000000000000000000000000000", RefundReceiver: "0x0000000000000000000000000000000000000000", Nonce: big.NewInt(7)}
	mutated := approved
	mutated.To = "0x9999999999999999999999999999999999999999"
	mutated.Data = []byte{0xde, 0xad, 0xbe, 0xef}
	return approved, mutated
}

func dvExecution(t *testing.T, approved, candidate executionproof.SafeTransaction, weak bool, kind string) DefenseValidationExecutionEvidenceV02 {
	t.Helper()
	proof, receipt := dvProofAndReceipt(t, approved, candidate, weak)
	var impact *int64
	caseRef := "case:evm:safe-authorized-transfer-benign"
	if kind == DefenseValidationCaseAttackV02 {
		v := int64(1000)
		impact = &v
		caseRef = "case:evm:safe-intent-mutation-attack"
	}
	boundApproved := approved
	if weak {
		boundApproved = candidate
	}
	evidence, err := AdaptExecutionIntegrityCaseV02(DefenseValidationExecutionAdapterInputV02{CaseRef: caseRef, CaseKind: kind, TechniqueID: "safe-intent-mutation", ExecutionMode: DefenseValidationExecutionForkV02, ImpactOffsetMS: impact, ObservationWindowMS: 3000, Control: dvControl(t), Scenario: readDefenseValidationScenarioFixtureV02(t, "safe-intent-mutation-v1.json"), ContainmentReceipt: receipt, ExecutionProof: proof, ApprovedSafeAction: dvAction(t, boundApproved), CandidateSafeAction: dvAction(t, candidate)})
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func dvAction(t *testing.T, tx executionproof.SafeTransaction) executioncontainment.ActionArtifact {
	t.Helper()
	action, err := executionproof.CanonicalSafeActionArtifact(tx)
	if err != nil {
		t.Fatal(err)
	}
	return action
}

func dvProofAndReceipt(t *testing.T, approved, candidate executionproof.SafeTransaction, weak bool) (executionproof.Proof, executioncontainment.Receipt) {
	t.Helper()
	approvedHash, err := (executionproof.NativeSafeTxHashComputer{}).ComputeSafeTxHash(approved)
	if err != nil {
		t.Fatal(err)
	}
	candidateHash, err := (executionproof.NativeSafeTxHashComputer{}).ComputeSafeTxHash(candidate)
	if err != nil {
		t.Fatal(err)
	}
	approvedPayload, candidatePayload := dvSHA(approved.Data), dvSHA(candidate.Data)
	boundIntent, boundPayload := approvedHash, approvedPayload
	if weak {
		boundIntent, boundPayload = candidateHash, candidatePayload
	}
	artifact, invariant := strings.Repeat("1", 64), strings.Repeat("2", 64)
	proof, err := executionproof.Evaluate(executionproof.Envelope{
		Source:        executionproof.SourceEvidence{CommitID: strings.Repeat("a", 40), TreeID: strings.Repeat("b", 40)},
		Build:         executionproof.BuildEvidence{ToolchainSHA256: strings.Repeat("3", 64), ApprovedArtifactSHA256: artifact, BuiltArtifactSHA256: artifact},
		Runtime:       executionproof.RuntimeEvidence{ObservedArtifactSHA256: artifact, PolicySHA256: strings.Repeat("4", 64)},
		Payload:       executionproof.PayloadEvidence{ChainID: candidate.ChainID, Target: candidate.To, ApprovedCalldataSHA256: boundPayload, GeneratedCalldataSHA256: candidatePayload, GeneratorSHA256: strings.Repeat("5", 64)},
		Simulation:    executionproof.SimulationEvidence{InvariantSetSHA256: invariant, Result: "PASS"},
		Authorization: executionproof.AuthorizationEvidence{SigningPolicySHA256: strings.Repeat("6", 64), ApprovedSigningRequestID: boundIntent},
	})
	if err != nil {
		t.Fatal(err)
	}
	action, err := executionproof.CanonicalSafeActionArtifact(candidate)
	if err != nil {
		t.Fatal(err)
	}
	blockHash, runnerHash := strings.Repeat("7", 64), strings.Repeat("8", 64)
	receipt, err := executioncontainment.Evaluate(executioncontainment.CellInput{ChainID: candidate.ChainID, BlockNumber: 23456789, BlockHash: blockHash, Target: candidate.To, ApprovedIntentSHA256: strings.TrimPrefix(boundIntent, "0x"), CandidateIntentSHA256: strings.TrimPrefix(candidateHash, "0x"), ApprovedPayloadSHA256: boundPayload, CandidatePayloadSHA256: candidatePayload, ActionSHA256: action.SHA256(), InvariantSetSHA256: invariant, ApprovedRunnerSHA256: runnerHash}, executioncontainment.Observation{BackendAvailable: true, ObservedChainID: candidate.ChainID, ObservedBlockNumber: 23456789, ObservedBlockHash: blockHash, ObservedRunnerSHA256: runnerHash, PreStateSHA256: strings.Repeat("9", 64), PostStateSHA256: strings.Repeat("a", 64), EffectSetSHA256: strings.Repeat("b", 64), AuthorityPreserved: true, AssetBoundsPreserved: true, CodeIntegrityPreserved: true, ExecutionPathFullyObserved: true, InvariantsPass: true})
	if err != nil {
		t.Fatal(err)
	}
	return proof, receipt
}

func dvBinding(control DefenseValidationControlV02, execution DefenseValidationExecutionEvidenceV02, alert *int64) DefenseValidationObservationBindingV02 {
	status := DefenseValidationObservationNoAlertV02
	if execution.ControlSignaled {
		status = DefenseValidationObservationAlertedV02
		if alert == nil {
			v := int64(120)
			alert = &v
		}
	} else {
		alert = nil
	}
	return DefenseValidationObservationBindingV02{Version: DefenseValidationObservationBindingVersionV02, Chain: "evm", ControlRef: control.ControlRef, CaseRef: execution.Case.CaseRef, Status: status, ExecutionHash: execution.Case.ExecutionHash, AlertObservedOffsetMS: alert, ObservationCompletedOffsetMS: execution.Case.ObservationWindowMS}
}

func dvObservation(t *testing.T, control DefenseValidationControlV02, execution DefenseValidationExecutionEvidenceV02, alert *int64) DefenseValidationObservationV02 {
	t.Helper()
	binding := dvBinding(control, execution, alert)
	digest, err := DefenseValidationObservationBindingDigestV02(binding)
	if err != nil {
		t.Fatal(err)
	}
	event, err := (securityevidence.Event{Producer: control.CollectorRef, Subject: securityevidence.Subject{Chain: "evm", Type: DefenseValidationObservationSubjectTypeV02, ID: execution.Case.CaseRef}, Window: securityevidence.ObservationWindow{FromUnixMS: 0, ToUnixMS: execution.Case.ObservationWindowMS}, SourceDigests: []string{execution.ContainmentReceiptSHA256, execution.ExecutionProofSHA256}, Findings: []securityevidence.Finding{{ID: DefenseValidationObservationFindingIDV02(control.ControlRef, execution.Case.CaseRef), Kind: DefenseValidationObservationFindingKindV02, State: securityevidence.StateVerified, EvidenceSHA256: digest, Summary: "Independent observation of bound execution integrity control."}}}).SignEd25519(dvCollectorPrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	observation, err := AdaptSecurityEvidenceObservationV02(control, execution, binding, event)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func dvCaseResult(t *testing.T, report DefenseValidationReportV02, caseRef string) DefenseValidationCaseResultV02 {
	t.Helper()
	for _, control := range report.Controls {
		for _, result := range control.Cases {
			if result.CaseRef == caseRef {
				return result
			}
		}
	}
	t.Fatalf("case result %q not found", caseRef)
	return DefenseValidationCaseResultV02{}
}

func dvSHA(value []byte) string { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }

func dvCollectorPrivateKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x64
	}
	return ed25519.NewKeyFromSeed(seed)
}

func dvCollectorPublicKey() string {
	return base64.RawURLEncoding.EncodeToString(dvCollectorPrivateKey().Public().(ed25519.PublicKey))
}
