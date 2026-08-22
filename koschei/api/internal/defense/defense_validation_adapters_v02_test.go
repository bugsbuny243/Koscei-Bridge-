package defense

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"koschei/api/internal/executioncontainment"
	"koschei/api/internal/executionproof"
	"koschei/api/internal/securityevidence"
)

func TestSafeIntentMutationWeakBindingFailsAndExactBindingValidates(t *testing.T) {
	control := defenseValidationExecutionControlFixtureV02(t)
	approved, mutated := defenseValidationSafeTransactionsV02()

	weakAttack := defenseValidationExecutionFixtureV02(t, approved, mutated, true, DefenseValidationCaseAttackV02)
	benign := defenseValidationExecutionFixtureV02(t, approved, approved, false, DefenseValidationCaseBenignV02)
	weakAttackObservation := defenseValidationIndependentObservationFixtureV02(t, control, weakAttack, nil)
	benignObservation := defenseValidationIndependentObservationFixtureV02(t, control, benign, nil)

	weakReport, err := EvaluateDefenseValidationV02(DefenseValidationInputV02{
		RunRef:          "run:safe-intent-mutation:weak-binding",
		ScenarioRef:     "scenario:evm:safe-intent-mutation",
		ScenarioVersion: "v1.0.0",
		Chain:           "evm",
		RulesetVersion:  DefenseValidationRulesetVersionV02,
		Controls:        []DefenseValidationControlV02{control},
		Cases:           []DefenseValidationCaseV02{weakAttack.Case, benign.Case},
		Observations:    []DefenseValidationObservationV02{weakAttackObservation, benignObservation},
	})
	if err != nil {
		t.Fatal(err)
	}
	if weakReport.Verdict != DefenseValidationVerdictFailedV02 {
		t.Fatalf("weak binding verdict=%s, want %s", weakReport.Verdict, DefenseValidationVerdictFailedV02)
	}
	weakAttackResult := defenseValidationCaseResultFixtureV02(t, weakReport, weakAttack.Case.CaseRef)
	if weakAttackResult.Outcome != DefenseValidationOutcomeMissedV02 {
		t.Fatalf("weak attack outcome=%s, want %s", weakAttackResult.Outcome, DefenseValidationOutcomeMissedV02)
	}
	if weakAttack.ControlSignaled {
		t.Fatal("weak upstream binding unexpectedly signaled the mutated Safe action")
	}

	exactAttack := defenseValidationExecutionFixtureV02(t, approved, mutated, false, DefenseValidationCaseAttackV02)
	alertOffset := int64(120)
	exactAttackObservation := defenseValidationIndependentObservationFixtureV02(t, control, exactAttack, &alertOffset)

	exactReport, err := EvaluateDefenseValidationV02(DefenseValidationInputV02{
		RunRef:          "run:safe-intent-mutation:exact-binding",
		ScenarioRef:     "scenario:evm:safe-intent-mutation",
		ScenarioVersion: "v1.0.0",
		Chain:           "evm",
		RulesetVersion:  DefenseValidationRulesetVersionV02,
		Controls:        []DefenseValidationControlV02{control},
		Cases:           []DefenseValidationCaseV02{exactAttack.Case, benign.Case},
		Observations:    []DefenseValidationObservationV02{exactAttackObservation, benignObservation},
	})
	if err != nil {
		t.Fatal(err)
	}
	if exactReport.Verdict != DefenseValidationVerdictValidatedV02 {
		t.Fatalf("exact binding verdict=%s, want %s", exactReport.Verdict, DefenseValidationVerdictValidatedV02)
	}
	exactAttackResult := defenseValidationCaseResultFixtureV02(t, exactReport, exactAttack.Case.CaseRef)
	if exactAttackResult.Outcome != DefenseValidationOutcomeCaughtInTimeV02 {
		t.Fatalf("exact attack outcome=%s, want %s", exactAttackResult.Outcome, DefenseValidationOutcomeCaughtInTimeV02)
	}
	if exactAttackResult.LeadTimeMS == nil || *exactAttackResult.LeadTimeMS != 880 {
		t.Fatalf("lead time=%v, want 880ms", exactAttackResult.LeadTimeMS)
	}
	benignResult := defenseValidationCaseResultFixtureV02(t, exactReport, benign.Case.CaseRef)
	if benignResult.Outcome != DefenseValidationOutcomeCleanV02 {
		t.Fatalf("benign outcome=%s, want %s", benignResult.Outcome, DefenseValidationOutcomeCleanV02)
	}
	if !exactAttack.ControlSignaled || exactAttack.ContainmentDecision != executioncontainment.DecisionContain || exactAttack.ExecutionProofDecision != executionproof.DecisionBlock {
		t.Fatalf("exact attack did not bind both control signals: containment=%s proof=%s signaled=%v", exactAttack.ContainmentDecision, exactAttack.ExecutionProofDecision, exactAttack.ControlSignaled)
	}
	if benign.ControlSignaled || benign.ContainmentDecision != executioncontainment.DecisionRelease || benign.ExecutionProofDecision != executionproof.DecisionAllow {
		t.Fatalf("benign control drifted: containment=%s proof=%s signaled=%v", benign.ContainmentDecision, benign.ExecutionProofDecision, benign.ControlSignaled)
	}
}

func TestDefenseValidationAdapterRejectsSelfAttestedObservation(t *testing.T) {
	control := defenseValidationExecutionControlFixtureV02(t)
	approved, mutated := defenseValidationSafeTransactionsV02()
	execution := defenseValidationExecutionFixtureV02(t, approved, mutated, false, DefenseValidationCaseAttackV02)
	alertOffset := int64(120)
	binding := DefenseValidationObservationBindingV02{
		Version:                      DefenseValidationObservationBindingVersionV02,
		Chain:                        "evm",
		ControlRef:                   control.ControlRef,
		CaseRef:                      execution.Case.CaseRef,
		Status:                       DefenseValidationObservationAlertedV02,
		ExecutionHash:                execution.Case.ExecutionHash,
		AlertObservedOffsetMS:        &alertOffset,
		ObservationCompletedOffsetMS: execution.Case.ObservationWindowMS,
	}
	digest, err := DefenseValidationObservationBindingDigestV02(binding)
	if err != nil {
		t.Fatal(err)
	}
	event, err := (securityevidence.Event{
		Producer: control.ControlRef,
		Subject: securityevidence.Subject{Chain: "evm", Type: DefenseValidationObservationSubjectTypeV02, ID: execution.Case.CaseRef},
		Window: securityevidence.ObservationWindow{FromUnixMS: 0, ToUnixMS: execution.Case.ObservationWindowMS},
		SourceDigests: []string{execution.ContainmentReceiptSHA256, execution.ExecutionProofSHA256},
		Findings: []securityevidence.Finding{{
			ID:             DefenseValidationObservationFindingIDV02(control.ControlRef, execution.Case.CaseRef),
			Kind:           DefenseValidationObservationFindingKindV02,
			State:          securityevidence.StateVerified,
			EvidenceSHA256: digest,
		}},
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdaptSecurityEvidenceObservationV02(control, execution, binding, event); err == nil {
		t.Fatal("self-attested control observation was accepted")
	}
}

func TestDefenseValidationAdapterRejectsTamperedExecutionProof(t *testing.T) {
	approved, mutated := defenseValidationSafeTransactionsV02()
	proof, receipt := defenseValidationProofAndContainmentFixtureV02(t, approved, mutated, false)
	proof.Evaluation.Decision = executionproof.DecisionAllow
	impact := int64(1000)
	if _, err := AdaptExecutionIntegrityCaseV02(DefenseValidationExecutionAdapterInputV02{
		CaseRef:                "case:evm:safe-intent-mutation-attack",
		CaseKind:               DefenseValidationCaseAttackV02,
		TechniqueID:            "safe-intent-mutation",
		ExecutionMode:          DefenseValidationExecutionForkV02,
		ImpactOffsetMS:         &impact,
		ObservationWindowMS:    3000,
		ContainmentReceipt:     receipt,
		ExecutionProof:         proof,
		MainnetTransactionSent: false,
	}); err == nil {
		t.Fatal("tampered execution proof was accepted")
	}
}

func TestExecutionIntegrityControlRejectsProductionOrMainnetClaims(t *testing.T) {
	base := DefenseValidationExecutionIntegrityConfigV02{IndependentCollectorRequired: true}
	base.MainnetSubmissionAllowed = true
	if _, err := NewExecutionIntegrityControlV02("control", "collector", base); err == nil {
		t.Fatal("mainnet-enabled validation control was accepted")
	}
	base.MainnetSubmissionAllowed = false
	base.ProductionWiringClaim = true
	if _, err := NewExecutionIntegrityControlV02("control", "collector", base); err == nil {
		t.Fatal("unproven production wiring claim was accepted")
	}
}

func defenseValidationExecutionControlFixtureV02(t *testing.T) DefenseValidationControlV02 {
	t.Helper()
	control, err := NewExecutionIntegrityControlV02(
		"control:execution-integrity",
		"collector:independent-safe-observer",
		DefenseValidationExecutionIntegrityConfigV02{IndependentCollectorRequired: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	return control
}

func defenseValidationSafeTransactionsV02() (executionproof.SafeTransaction, executionproof.SafeTransaction) {
	approved := executionproof.SafeTransaction{
		ChainID:        1,
		Safe:           "0x1111111111111111111111111111111111111111",
		To:             "0x2222222222222222222222222222222222222222",
		Value:          big.NewInt(0),
		Data:           []byte{0xaa, 0xbb, 0xcc, 0x01},
		Operation:      0,
		SafeTxGas:      big.NewInt(50000),
		BaseGas:        big.NewInt(21000),
		GasPrice:       big.NewInt(0),
		GasToken:       "0x0000000000000000000000000000000000000000",
		RefundReceiver: "0x0000000000000000000000000000000000000000",
		Nonce:          big.NewInt(7),
	}
	mutated := approved
	mutated.To = "0x9999999999999999999999999999999999999999"
	mutated.Data = []byte{0xde, 0xad, 0xbe, 0xef}
	return approved, mutated
}

func defenseValidationExecutionFixtureV02(t *testing.T, approved, candidate executionproof.SafeTransaction, weakBinding bool, caseKind string) DefenseValidationExecutionEvidenceV02 {
	t.Helper()
	proof, receipt := defenseValidationProofAndContainmentFixtureV02(t, approved, candidate, weakBinding)
	var impact *int64
	if caseKind == DefenseValidationCaseAttackV02 {
		value := int64(1000)
		impact = &value
	}
	caseRef := "case:evm:safe-authorized-transfer-benign"
	if caseKind == DefenseValidationCaseAttackV02 {
		caseRef = "case:evm:safe-intent-mutation-attack"
	}
	evidence, err := AdaptExecutionIntegrityCaseV02(DefenseValidationExecutionAdapterInputV02{
		CaseRef:                caseRef,
		CaseKind:               caseKind,
		TechniqueID:            "safe-intent-mutation",
		ExecutionMode:          DefenseValidationExecutionForkV02,
		ImpactOffsetMS:         impact,
		ObservationWindowMS:    3000,
		ContainmentReceipt:     receipt,
		ExecutionProof:         proof,
		MainnetTransactionSent: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func defenseValidationProofAndContainmentFixtureV02(t *testing.T, approved, candidate executionproof.SafeTransaction, weakBinding bool) (executionproof.Proof, executioncontainment.Receipt) {
	t.Helper()
	approvedSafeHash, err := (executionproof.NativeSafeTxHashComputer{}).ComputeSafeTxHash(approved)
	if err != nil {
		t.Fatal(err)
	}
	candidateSafeHash, err := (executionproof.NativeSafeTxHashComputer{}).ComputeSafeTxHash(candidate)
	if err != nil {
		t.Fatal(err)
	}
	approvedPayload := defenseValidationSHA256V02(approved.Data)
	candidatePayload := defenseValidationSHA256V02(candidate.Data)
	boundIntent := approvedSafeHash
	boundPayload := approvedPayload
	if weakBinding {
		boundIntent = candidateSafeHash
		boundPayload = candidatePayload
	}
	artifactHash := strings.Repeat("1", 64)
	invariantHash := strings.Repeat("2", 64)
	proof, err := executionproof.Evaluate(executionproof.Envelope{
		Source: executionproof.SourceEvidence{CommitID: strings.Repeat("a", 40), TreeID: strings.Repeat("b", 40)},
		Build: executionproof.BuildEvidence{
			ToolchainSHA256:        strings.Repeat("3", 64),
			ApprovedArtifactSHA256: artifactHash,
			BuiltArtifactSHA256:    artifactHash,
		},
		Runtime: executionproof.RuntimeEvidence{
			ObservedArtifactSHA256: artifactHash,
			PolicySHA256:           strings.Repeat("4", 64),
		},
		Payload: executionproof.PayloadEvidence{
			ChainID:                 candidate.ChainID,
			Target:                  candidate.To,
			ApprovedCalldataSHA256:  boundPayload,
			GeneratedCalldataSHA256: candidatePayload,
			GeneratorSHA256:         strings.Repeat("5", 64),
		},
		Simulation: executionproof.SimulationEvidence{InvariantSetSHA256: invariantHash, Result: "PASS"},
		Authorization: executionproof.AuthorizationEvidence{
			SigningPolicySHA256:      strings.Repeat("6", 64),
			ApprovedSigningRequestID: boundIntent,
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
		ChainID:                candidate.ChainID,
		BlockNumber:            23456789,
		BlockHash:              blockHash,
		Target:                 candidate.To,
		ApprovedIntentSHA256:   strings.TrimPrefix(boundIntent, "0x"),
		CandidateIntentSHA256:  strings.TrimPrefix(candidateSafeHash, "0x"),
		ApprovedPayloadSHA256:  boundPayload,
		CandidatePayloadSHA256: candidatePayload,
		ActionSHA256:           action.SHA256(),
		InvariantSetSHA256:     invariantHash,
		ApprovedRunnerSHA256:   runnerHash,
	}, executioncontainment.Observation{
		BackendAvailable:           true,
		ObservedChainID:            candidate.ChainID,
		ObservedBlockNumber:        23456789,
		ObservedBlockHash:          blockHash,
		ObservedRunnerSHA256:       runnerHash,
		PreStateSHA256:             strings.Repeat("9", 64),
		PostStateSHA256:            strings.Repeat("a", 64),
		EffectSetSHA256:            strings.Repeat("b", 64),
		AuthorityPreserved:         true,
		AssetBoundsPreserved:       true,
		CodeIntegrityPreserved:     true,
		ExecutionPathFullyObserved: true,
		InvariantsPass:             true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return proof, receipt
}

func defenseValidationIndependentObservationFixtureV02(t *testing.T, control DefenseValidationControlV02, execution DefenseValidationExecutionEvidenceV02, alertOffset *int64) DefenseValidationObservationV02 {
	t.Helper()
	status := DefenseValidationObservationNoAlertV02
	if execution.ControlSignaled {
		status = DefenseValidationObservationAlertedV02
		if alertOffset == nil {
			value := int64(120)
			alertOffset = &value
		}
	} else {
		alertOffset = nil
	}
	binding := DefenseValidationObservationBindingV02{
		Version:                      DefenseValidationObservationBindingVersionV02,
		Chain:                        "evm",
		ControlRef:                   control.ControlRef,
		CaseRef:                      execution.Case.CaseRef,
		Status:                       status,
		ExecutionHash:                execution.Case.ExecutionHash,
		AlertObservedOffsetMS:        alertOffset,
		ObservationCompletedOffsetMS: execution.Case.ObservationWindowMS,
	}
	digest, err := DefenseValidationObservationBindingDigestV02(binding)
	if err != nil {
		t.Fatal(err)
	}
	event, err := (securityevidence.Event{
		Producer: control.CollectorRef,
		Subject: securityevidence.Subject{Chain: "evm", Type: DefenseValidationObservationSubjectTypeV02, ID: execution.Case.CaseRef},
		Window: securityevidence.ObservationWindow{FromUnixMS: 0, ToUnixMS: execution.Case.ObservationWindowMS},
		SourceDigests: []string{execution.ContainmentReceiptSHA256, execution.ExecutionProofSHA256},
		Findings: []securityevidence.Finding{{
			ID:             DefenseValidationObservationFindingIDV02(control.ControlRef, execution.Case.CaseRef),
			Kind:           DefenseValidationObservationFindingKindV02,
			State:          securityevidence.StateVerified,
			EvidenceSHA256: digest,
			Summary:        "Independent observation of the bound execution-integrity control decision.",
		}},
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	observation, err := AdaptSecurityEvidenceObservationV02(control, execution, binding, event)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func defenseValidationCaseResultFixtureV02(t *testing.T, report DefenseValidationReportV02, caseRef string) DefenseValidationCaseResultV02 {
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

func defenseValidationSHA256V02(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
