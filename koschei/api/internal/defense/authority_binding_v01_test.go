package defense

import (
	"strings"
	"testing"

	"koschei/api/internal/executioncontainment"
	"koschei/api/internal/securityevidence"
)

func TestAuthorityBindingMismatchContainsWhileMatchedSourceReleases(t *testing.T) {
	attackBinding := authorityBindingResult(t, "account:victim", "account:caller")
	benignBinding := authorityBindingResult(t, "account:caller", "account:caller")
	if attackBinding.Preserved {
		t.Fatal("unauthorized source account was treated as authority-preserved")
	}
	if !containsAuthorityReason(attackBinding.Reasons, DefenseAuthorityReasonSourceMismatchV01) {
		t.Fatalf("attack reasons=%v", attackBinding.Reasons)
	}
	if !benignBinding.Preserved {
		t.Fatalf("benign binding reasons=%v", benignBinding.Reasons)
	}

	attackReceipt := authorityContainmentReceipt(t, attackBinding)
	benignReceipt := authorityContainmentReceipt(t, benignBinding)
	if attackReceipt.Decision != executioncontainment.DecisionContain {
		t.Fatalf("attack containment decision=%s reasons=%v", attackReceipt.Decision, attackReceipt.Reasons)
	}
	if !containsContainmentReason(attackReceipt.Reasons, executioncontainment.ReasonAuthorityChanged) || !containsContainmentReason(attackReceipt.Reasons, executioncontainment.ReasonInvariantFailed) {
		t.Fatalf("attack containment reasons=%v", attackReceipt.Reasons)
	}
	if containsContainmentReason(attackReceipt.Reasons, executioncontainment.ReasonIntentMismatch) {
		t.Fatalf("authority attack was incorrectly classified as payload mutation: %v", attackReceipt.Reasons)
	}
	if benignReceipt.Decision != executioncontainment.DecisionRelease || len(benignReceipt.Reasons) != 0 {
		t.Fatalf("benign containment=%s reasons=%v", benignReceipt.Decision, benignReceipt.Reasons)
	}
}

func TestAuthorityIntegrityComponentPairValidatesWithIndependentEvidence(t *testing.T) {
	control, err := NewAuthorityIntegrityControlV01(
		"control:authority-integrity",
		"collector:independent-authority-observer",
		DefenseAuthorityIntegrityConfigV01{IndependentCollectorRequired: true},
	)
	if err != nil {
		t.Fatal(err)
	}

	attackBinding := authorityBindingResult(t, "account:victim", "account:caller")
	benignBinding := authorityBindingResult(t, "account:caller", "account:caller")
	attackReceipt := authorityContainmentReceipt(t, attackBinding)
	benignReceipt := authorityContainmentReceipt(t, benignBinding)
	impact := int64(1000)
	attack, err := AdaptAuthorityIntegrityCaseV01(DefenseAuthorityExecutionAdapterInputV01{
		CaseRef:             "case:cosmos-evm:unauthorized-source-account-attack",
		CaseKind:            DefenseValidationCaseAttackV02,
		TechniqueID:         "unauthorized-source-account",
		ExecutionMode:       DefenseValidationExecutionSandboxV02,
		ImpactOffsetMS:      &impact,
		ObservationWindowMS: 3000,
		Binding:             attackBinding,
		ContainmentReceipt:  attackReceipt,
	})
	if err != nil {
		t.Fatal(err)
	}
	benign, err := AdaptAuthorityIntegrityCaseV01(DefenseAuthorityExecutionAdapterInputV01{
		CaseRef:             "case:cosmos-evm:authorized-source-account-benign",
		CaseKind:            DefenseValidationCaseBenignV02,
		TechniqueID:         "unauthorized-source-account",
		ExecutionMode:       DefenseValidationExecutionSandboxV02,
		ObservationWindowMS: 3000,
		Binding:             benignBinding,
		ContainmentReceipt:  benignReceipt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !attack.ControlSignaled || benign.ControlSignaled {
		t.Fatalf("unexpected control signals attack=%v benign=%v", attack.ControlSignaled, benign.ControlSignaled)
	}

	alert := int64(120)
	attackObservation := authorityIndependentObservation(t, control, attack, &alert)
	benignObservation := authorityIndependentObservation(t, control, benign, nil)
	report, err := EvaluateDefenseValidationV02(DefenseValidationInputV02{
		RunRef:          "run:authority-component",
		ScenarioRef:     "scenario:cosmos-evm:unauthorized-source-account",
		ScenarioVersion: "v1.0.0",
		Chain:           "cosmos-evm",
		RulesetVersion:  DefenseValidationRulesetVersionV02,
		Controls:        []DefenseValidationControlV02{control},
		Cases:           []DefenseValidationCaseV02{attack.Case, benign.Case},
		Observations:    []DefenseValidationObservationV02{attackObservation, benignObservation},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != DefenseValidationVerdictValidatedV02 {
		t.Fatalf("authority component verdict=%s", report.Verdict)
	}
	attackResult := dvCaseResult(t, report, attack.Case.CaseRef)
	if attackResult.Outcome != DefenseValidationOutcomeCaughtInTimeV02 || attackResult.LeadTimeMS == nil || *attackResult.LeadTimeMS != 880 {
		t.Fatalf("attack result=%#v", attackResult)
	}
	if got := dvCaseResult(t, report, benign.Case.CaseRef); got.Outcome != DefenseValidationOutcomeCleanV02 {
		t.Fatalf("benign result=%#v", got)
	}
}

func TestAuthorityBindingRejectsUnverifiedEvidence(t *testing.T) {
	evidence := authorityBindingEvidence("account:caller", "account:caller")
	evidence.EvidenceState = DefenseValidationEvidenceObservedV02
	if _, err := EvaluateDefenseAuthorityBindingV01(evidence); err == nil {
		t.Fatal("unverified authority binding evidence was accepted")
	}
}

func TestAuthorityObservationRejectsSelfAttestation(t *testing.T) {
	control, err := NewAuthorityIntegrityControlV01("control:authority-integrity", "collector:independent-authority-observer", DefenseAuthorityIntegrityConfigV01{IndependentCollectorRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	binding := authorityBindingResult(t, "account:victim", "account:caller")
	receipt := authorityContainmentReceipt(t, binding)
	impact := int64(1000)
	execution, err := AdaptAuthorityIntegrityCaseV01(DefenseAuthorityExecutionAdapterInputV01{CaseRef: "case:attack", CaseKind: DefenseValidationCaseAttackV02, TechniqueID: "unauthorized-source-account", ExecutionMode: DefenseValidationExecutionSandboxV02, ImpactOffsetMS: &impact, ObservationWindowMS: 3000, Binding: binding, ContainmentReceipt: receipt})
	if err != nil {
		t.Fatal(err)
	}
	alert := int64(120)
	observationBinding := authorityObservationBinding(control, execution, &alert)
	digest, err := DefenseAuthorityObservationBindingDigestV01(observationBinding)
	if err != nil {
		t.Fatal(err)
	}
	event, err := (securityevidence.Event{
		Producer:      control.ControlRef,
		Subject:       securityevidence.Subject{Chain: "cosmos-evm", Type: DefenseValidationObservationSubjectTypeV02, ID: execution.Case.CaseRef},
		Window:        securityevidence.ObservationWindow{FromUnixMS: 0, ToUnixMS: execution.Case.ObservationWindowMS},
		SourceDigests: []string{execution.ContainmentReceiptSHA256, execution.AuthorityBindingSHA256},
		Findings:      []securityevidence.Finding{{ID: DefenseValidationObservationFindingIDV02(control.ControlRef, execution.Case.CaseRef), Kind: DefenseValidationObservationFindingKindV02, State: securityevidence.StateVerified, EvidenceSHA256: digest}},
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdaptAuthoritySecurityEvidenceObservationV01(control, execution, observationBinding, event); err == nil {
		t.Fatal("authority control self-attestation was accepted")
	}
}

func authorityBindingEvidence(declaredSource, authorizedSource string) DefenseAuthorityBindingEvidenceV01 {
	return DefenseAuthorityBindingEvidenceV01{
		EvidenceState:               DefenseValidationEvidenceVerifiedV02,
		CallerPrincipal:             "principal:contract-a",
		DeclaredSourceAccount:       declaredSource,
		RequestedOperation:          "debit",
		RequestedAsset:              "asset:bb",
		AuthorizedPrincipal:         "principal:contract-a",
		AuthorizedSourceAccount:     authorizedSource,
		AuthorizedOperation:         "debit",
		AuthorizedAsset:             "asset:bb",
		CallPayloadSHA256:           strings.Repeat("1", 64),
		PrincipalEvidenceSHA256:     strings.Repeat("2", 64),
		AuthorizationEvidenceSHA256: strings.Repeat("3", 64),
		PreStateSHA256:              strings.Repeat("4", 64),
		PostStateSHA256:             strings.Repeat("5", 64),
		DebitEffectSHA256:           strings.Repeat("6", 64),
	}
}

func authorityBindingResult(t *testing.T, declaredSource, authorizedSource string) DefenseAuthorityBindingResultV01 {
	t.Helper()
	result, err := EvaluateDefenseAuthorityBindingV01(authorityBindingEvidence(declaredSource, authorizedSource))
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDefenseAuthorityBindingV01(result) {
		t.Fatal("authority binding did not verify")
	}
	return result
}

func authorityContainmentReceipt(t *testing.T, binding DefenseAuthorityBindingResultV01) executioncontainment.Receipt {
	t.Helper()
	input := executioncontainment.CellInput{
		ChainID:                9001,
		BlockNumber:            123456,
		BlockHash:              strings.Repeat("7", 64),
		Target:                 "native:authorization-module",
		ApprovedIntentSHA256:   strings.Repeat("8", 64),
		CandidateIntentSHA256:  strings.Repeat("8", 64),
		ApprovedPayloadSHA256:  binding.Evidence.CallPayloadSHA256,
		CandidatePayloadSHA256: binding.Evidence.CallPayloadSHA256,
		ActionSHA256:           strings.Repeat("9", 64),
		InvariantSetSHA256:     strings.Repeat("a", 64),
		ApprovedRunnerSHA256:   strings.Repeat("b", 64),
	}
	observation := executioncontainment.Observation{
		BackendAvailable:           true,
		ObservedChainID:            input.ChainID,
		ObservedBlockNumber:        input.BlockNumber,
		ObservedBlockHash:          input.BlockHash,
		ObservedRunnerSHA256:       input.ApprovedRunnerSHA256,
		PreStateSHA256:             binding.Evidence.PreStateSHA256,
		PostStateSHA256:            binding.Evidence.PostStateSHA256,
		EffectSetSHA256:            binding.Evidence.DebitEffectSHA256,
		AuthorityPreserved:         true,
		AssetBoundsPreserved:       true,
		CodeIntegrityPreserved:     true,
		ExecutionPathFullyObserved: true,
		InvariantsPass:             true,
	}
	observation, err := ApplyDefenseAuthorityBindingToContainmentV01(observation, binding)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := executioncontainment.Evaluate(input, observation)
	if err != nil {
		t.Fatal(err)
	}
	if !executioncontainment.Verify(receipt) {
		t.Fatal("authority containment receipt did not verify")
	}
	return receipt
}

func authorityObservationBinding(control DefenseValidationControlV02, execution DefenseAuthorityExecutionEvidenceV01, alert *int64) DefenseAuthorityObservationBindingV01 {
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
	return DefenseAuthorityObservationBindingV01{Chain: "cosmos-evm", ControlRef: control.ControlRef, CaseRef: execution.Case.CaseRef, Status: status, ExecutionHash: execution.Case.ExecutionHash, AlertObservedOffsetMS: alert, ObservationCompletedOffsetMS: execution.Case.ObservationWindowMS}
}

func authorityIndependentObservation(t *testing.T, control DefenseValidationControlV02, execution DefenseAuthorityExecutionEvidenceV01, alert *int64) DefenseValidationObservationV02 {
	t.Helper()
	binding := authorityObservationBinding(control, execution, alert)
	digest, err := DefenseAuthorityObservationBindingDigestV01(binding)
	if err != nil {
		t.Fatal(err)
	}
	event, err := (securityevidence.Event{
		Producer:      control.CollectorRef,
		Subject:       securityevidence.Subject{Chain: "cosmos-evm", Type: DefenseValidationObservationSubjectTypeV02, ID: execution.Case.CaseRef},
		Window:        securityevidence.ObservationWindow{FromUnixMS: 0, ToUnixMS: execution.Case.ObservationWindowMS},
		SourceDigests: []string{execution.ContainmentReceiptSHA256, execution.AuthorityBindingSHA256},
		Findings:      []securityevidence.Finding{{ID: DefenseValidationObservationFindingIDV02(control.ControlRef, execution.Case.CaseRef), Kind: DefenseValidationObservationFindingKindV02, State: securityevidence.StateVerified, EvidenceSHA256: digest, Summary: "Independent authority-binding observation."}},
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	observation, err := AdaptAuthoritySecurityEvidenceObservationV01(control, execution, binding, event)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func containsAuthorityReason(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func containsContainmentReason(values []executioncontainment.ReasonCode, wanted executioncontainment.ReasonCode) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
