package defense

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"koschei/api/internal/executioncontainment"
	"koschei/api/internal/securityevidence"
)

const (
	authorityAttackCaseRefV01 = "case:cosmos-evm:unauthorized-source-account-attack"
	authorityBenignCaseRefV01 = "case:cosmos-evm:authorized-source-account-benign"
)

func authorityIntegrityControl(t *testing.T) DefenseValidationControlV02 {
	t.Helper()
	control, err := NewAuthorityIntegrityControlV01(
		"control:authority-integrity",
		"collector:independent-authority-observer",
		DefenseAuthorityIntegrityConfigV01{
			EvidenceTrust:                authorityBindingTrust(),
			IndependentCollectorRequired: true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return control
}

func authorityIntegrityScenario(t *testing.T) DefenseValidationScenarioV02 {
	t.Helper()
	return readDefenseValidationScenarioFixtureV02(t, "unauthorized-source-account-v1.json")
}

func authorityIntegrityScenarioHash(t *testing.T) string {
	t.Helper()
	digest, err := DefenseValidationScenarioDigestV02(authorityIntegrityScenario(t))
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func authorityIntegrityAdapterInput(
	t *testing.T,
	control DefenseValidationControlV02,
	caseRef, caseKind string,
	binding DefenseAuthorityBindingResultV01,
	receipt executioncontainment.Receipt,
) DefenseAuthorityExecutionAdapterInputV01 {
	t.Helper()
	input := DefenseAuthorityExecutionAdapterInputV01{
		CaseRef:             caseRef,
		CaseKind:            caseKind,
		TechniqueID:         "unauthorized-source-account",
		ExecutionMode:       DefenseValidationExecutionSandboxV02,
		ObservationWindowMS: 3000,
		Control:             control,
		Scenario:            authorityIntegrityScenario(t),
		EvidenceTrust:       authorityBindingTrust(),
		Binding:             binding,
		ContainmentReceipt:  receipt,
	}
	if caseKind == DefenseValidationCaseAttackV02 {
		impact := int64(1000)
		input.ImpactOffsetMS = &impact
	}
	return input
}

func authorityIntegrityValidationInput(
	t *testing.T,
	runRef string,
	control DefenseValidationControlV02,
	cases []DefenseValidationCaseV02,
	observations []DefenseValidationObservationV02,
) DefenseValidationInputV02 {
	t.Helper()
	scenario := authorityIntegrityScenario(t)
	digest, err := DefenseValidationScenarioDigestV02(scenario)
	if err != nil {
		t.Fatal(err)
	}
	return DefenseValidationInputV02{
		RunRef:               runRef,
		ScenarioRef:          scenario.ScenarioRef,
		ScenarioVersion:      scenario.ScenarioVersion,
		ScenarioContractHash: digest,
		Chain:                scenario.Chain,
		ChainID:              9001,
		RulesetVersion:       DefenseValidationRulesetVersionV02,
		Controls:             []DefenseValidationControlV02{control},
		Cases:                cases,
		Observations:         observations,
	}
}

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
	control := authorityIntegrityControl(t)

	attackBinding := authorityBindingResult(t, "account:victim", "account:caller")
	benignBinding := authorityBindingResult(t, "account:caller", "account:caller")
	attackReceipt := authorityContainmentReceipt(t, attackBinding)
	benignReceipt := authorityContainmentReceipt(t, benignBinding)
	attack, err := AdaptAuthorityIntegrityCaseV01(authorityIntegrityAdapterInput(
		t, control, authorityAttackCaseRefV01, DefenseValidationCaseAttackV02, attackBinding, attackReceipt,
	))
	if err != nil {
		t.Fatal(err)
	}
	benign, err := AdaptAuthorityIntegrityCaseV01(authorityIntegrityAdapterInput(
		t, control, authorityBenignCaseRefV01, DefenseValidationCaseBenignV02, benignBinding, benignReceipt,
	))
	if err != nil {
		t.Fatal(err)
	}
	if !attack.ControlSignaled || benign.ControlSignaled {
		t.Fatalf("unexpected control signals attack=%v benign=%v", attack.ControlSignaled, benign.ControlSignaled)
	}

	alert := int64(120)
	attackObservation := authorityIndependentObservation(t, control, attack, &alert)
	benignObservation := authorityIndependentObservation(t, control, benign, nil)
	report, err := EvaluateDefenseValidationV02(authorityIntegrityValidationInput(
		t,
		"run:authority-component",
		control,
		[]DefenseValidationCaseV02{attack.Case, benign.Case},
		[]DefenseValidationObservationV02{attackObservation, benignObservation},
	))
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
	evidence := authorityBindingEvidence(t, "account:caller", "account:caller")
	evidence.EvidenceState = DefenseValidationEvidenceObservedV02
	if _, err := EvaluateDefenseAuthorityBindingV01(evidence, authorityBindingTrust()); err == nil {
		t.Fatal("unverified authority binding evidence was accepted")
	}
}

func TestAuthorityObservationRejectsSelfAttestation(t *testing.T) {
	control := authorityIntegrityControl(t)
	binding := authorityBindingResult(t, "account:victim", "account:caller")
	receipt := authorityContainmentReceipt(t, binding)
	execution, err := AdaptAuthorityIntegrityCaseV01(authorityIntegrityAdapterInput(
		t, control, authorityAttackCaseRefV01, DefenseValidationCaseAttackV02, binding, receipt,
	))
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

func TestAuthorityBindingRequiresAuthenticatedEvidenceAndExternalTrust(t *testing.T) {
	evidence := authorityBindingEvidence(t, "account:caller", "account:caller")
	if _, err := EvaluateDefenseAuthorityBindingV01(evidence); err == nil {
		t.Fatal("authority evidence without an external trust policy was accepted")
	}

	unsigned := evidence
	unsigned.PrincipalEvidence = DefenseAuthorityEvidenceArtifactV01{}
	unsigned.AuthorizationEvidence = DefenseAuthorityEvidenceArtifactV01{}
	unsigned.PrincipalEvidenceSHA256 = strings.Repeat("2", 64)
	unsigned.AuthorizationEvidenceSHA256 = strings.Repeat("3", 64)
	if _, err := EvaluateDefenseAuthorityBindingV01(unsigned, authorityBindingTrust()); err == nil {
		t.Fatal("caller-supplied verified label and arbitrary digests were accepted")
	}

	forged := evidence
	forged.PrincipalEvidence.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	var err error
	forged.PrincipalEvidenceSHA256, err = defenseAuthorityCanonicalSHA256V01(forged.PrincipalEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EvaluateDefenseAuthorityBindingV01(forged, authorityBindingTrust()); err == nil {
		t.Fatal("forged principal evidence signature was accepted")
	}
}

func TestAuthorityIntegrityControlPinsEvidenceTrust(t *testing.T) {
	principalSeed := make([]byte, ed25519.SeedSize)
	authorizationSeed := make([]byte, ed25519.SeedSize)
	for i := range principalSeed {
		principalSeed[i] = 0x31
		authorizationSeed[i] = 0x52
	}
	principalPrivateKey := ed25519.NewKeyFromSeed(principalSeed)
	authorizationPrivateKey := ed25519.NewKeyFromSeed(authorizationSeed)
	alternateTrust := DefenseAuthorityEvidenceTrustV01{
		PrincipalProducerRef:     "collector:principal-execution",
		PrincipalPublicKey:       base64.RawURLEncoding.EncodeToString(principalPrivateKey.Public().(ed25519.PublicKey)),
		AuthorizationProducerRef: "collector:authorization-state",
		AuthorizationPublicKey:   base64.RawURLEncoding.EncodeToString(authorizationPrivateKey.Public().(ed25519.PublicKey)),
	}
	evidence := authorityBindingEvidenceWithTrustAndKeys(
		t, "account:victim", "account:caller", alternateTrust, principalPrivateKey, authorizationPrivateKey,
	)
	binding, err := EvaluateDefenseAuthorityBindingV01(evidence, alternateTrust)
	if err != nil {
		t.Fatal(err)
	}
	receipt := authorityContainmentReceiptWithTrust(t, binding, alternateTrust)
	alternateControl, err := NewAuthorityIntegrityControlV01(
		"control:authority-integrity",
		"collector:independent-authority-observer",
		DefenseAuthorityIntegrityConfigV01{EvidenceTrust: alternateTrust, IndependentCollectorRequired: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	input := authorityIntegrityAdapterInput(
		t, alternateControl, authorityAttackCaseRefV01, DefenseValidationCaseAttackV02, binding, receipt,
	)
	input.EvidenceTrust = alternateTrust
	if _, err := AdaptAuthorityIntegrityCaseV01(input); err != nil {
		t.Fatalf("alternate trust fixture is not otherwise valid: %v", err)
	}

	input.Control = authorityIntegrityControl(t)
	if _, err := AdaptAuthorityIntegrityCaseV01(input); err == nil || !strings.Contains(err.Error(), "does not match control configuration") {
		t.Fatalf("execution trust was not pinned to the control configuration: %v", err)
	}
}

func TestAuthorityAdapterRequiresExactScenarioCaseMembership(t *testing.T) {
	control := authorityIntegrityControl(t)
	binding := authorityBindingResult(t, "account:victim", "account:caller")
	input := authorityIntegrityAdapterInput(
		t, control, authorityAttackCaseRefV01, DefenseValidationCaseAttackV02, binding, authorityContainmentReceipt(t, binding),
	)
	input.CaseRef = "case:cosmos-evm:unlisted-authority-attack"
	if _, err := AdaptAuthorityIntegrityCaseV01(input); err == nil || !strings.Contains(err.Error(), "not an exact scenario member") {
		t.Fatalf("unlisted scenario case was accepted: %v", err)
	}
}

func TestAuthorityReportRequiresExactControlConfigurationBinding(t *testing.T) {
	control := authorityIntegrityControl(t)
	binding := authorityBindingResult(t, "account:victim", "account:caller")
	execution, err := AdaptAuthorityIntegrityCaseV01(authorityIntegrityAdapterInput(
		t, control, authorityAttackCaseRefV01, DefenseValidationCaseAttackV02, binding, authorityContainmentReceipt(t, binding),
	))
	if err != nil {
		t.Fatal(err)
	}
	tamperedControl := control
	tamperedControl.ConfigurationHash = defenseValidationV02TestHash("e")
	input := authorityIntegrityValidationInput(t, "run:wrong-control-config", tamperedControl, []DefenseValidationCaseV02{execution.Case}, nil)
	if _, err := EvaluateDefenseValidationV02(input); err == nil || !strings.Contains(err.Error(), "does not match report control") {
		t.Fatalf("control-bound execution was accepted under another configuration: %v", err)
	}
}

func TestApplyAuthorityBindingPreservesBackendAuthorityFailure(t *testing.T) {
	binding := authorityBindingResult(t, "account:caller", "account:caller")
	observation := executioncontainment.Observation{AuthorityPreserved: false, InvariantsPass: true}
	applied, err := ApplyDefenseAuthorityBindingToContainmentV01(observation, binding, authorityBindingTrust())
	if err != nil {
		t.Fatal(err)
	}
	if applied.AuthorityPreserved {
		t.Fatal("positive binding overwrote the backend authority failure")
	}
}

func TestAuthorityAdapterRejectsReceiptFromDifferentExecution(t *testing.T) {
	control := authorityIntegrityControl(t)
	binding := authorityBindingResult(t, "account:victim", "account:caller")
	receipt := authorityContainmentReceipt(t, binding)
	mutations := map[string]func(*executioncontainment.CellInput, *executioncontainment.Observation){
		"chain": func(input *executioncontainment.CellInput, observation *executioncontainment.Observation) {
			input.ChainID++
			observation.ObservedChainID++
		},
		"payload": func(input *executioncontainment.CellInput, _ *executioncontainment.Observation) {
			input.ApprovedPayloadSHA256 = strings.Repeat("c", 64)
			input.CandidatePayloadSHA256 = strings.Repeat("c", 64)
		},
		"pre_state": func(_ *executioncontainment.CellInput, observation *executioncontainment.Observation) {
			observation.PreStateSHA256 = strings.Repeat("c", 64)
		},
		"post_state": func(_ *executioncontainment.CellInput, observation *executioncontainment.Observation) {
			observation.PostStateSHA256 = strings.Repeat("c", 64)
		},
		"effect": func(_ *executioncontainment.CellInput, observation *executioncontainment.Observation) {
			observation.EffectSetSHA256 = strings.Repeat("c", 64)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			input, observation := receipt.Input, receipt.Observation
			mutate(&input, &observation)
			unrelated, err := executioncontainment.Evaluate(input, observation)
			if err != nil {
				t.Fatal(err)
			}
			if !executioncontainment.Verify(unrelated) {
				t.Fatal("unrelated receipt fixture did not verify")
			}
			_, err = AdaptAuthorityIntegrityCaseV01(authorityIntegrityAdapterInput(
				t, control, authorityAttackCaseRefV01, DefenseValidationCaseAttackV02, binding, unrelated,
			))
			if err == nil {
				t.Fatal("verified receipt from a different execution was accepted")
			}
		})
	}
}

func TestAuthorityAdapterRequiresAuthoritySpecificAttackSignal(t *testing.T) {
	control := authorityIntegrityControl(t)
	preserved := authorityBindingResult(t, "account:caller", "account:caller")
	release := authorityContainmentReceipt(t, preserved)
	if _, err := AdaptAuthorityIntegrityCaseV01(authorityIntegrityAdapterInput(
		t, control, authorityAttackCaseRefV01, DefenseValidationCaseAttackV02, preserved, release,
	)); err == nil {
		t.Fatal("preserved authority execution was accepted as an attack")
	}

	failed := authorityBindingResult(t, "account:victim", "account:caller")
	receipt := authorityContainmentReceipt(t, failed)
	observation := receipt.Observation
	observation.AssetBoundsPreserved = false
	unrelated, err := executioncontainment.Evaluate(receipt.Input, observation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdaptAuthorityIntegrityCaseV01(authorityIntegrityAdapterInput(
		t, control, authorityAttackCaseRefV01, DefenseValidationCaseAttackV02, failed, unrelated,
	)); err == nil {
		t.Fatal("authority attack with unrelated containment reasons was accepted")
	}
}

func TestAuthorityChainIdentityCannotBeRelabeled(t *testing.T) {
	control := authorityIntegrityControl(t)
	binding := authorityBindingResult(t, "account:victim", "account:caller")
	execution, err := AdaptAuthorityIntegrityCaseV01(authorityIntegrityAdapterInput(
		t, control, authorityAttackCaseRefV01, DefenseValidationCaseAttackV02, binding, authorityContainmentReceipt(t, binding),
	))
	if err != nil {
		t.Fatal(err)
	}
	alert := int64(120)
	observationBinding := authorityObservationBinding(control, execution, &alert)
	observationBinding.Chain = "other-chain"
	digest, err := DefenseAuthorityObservationBindingDigestV01(observationBinding)
	if err != nil {
		t.Fatal(err)
	}
	event, err := (securityevidence.Event{
		Producer: control.CollectorRef, Subject: securityevidence.Subject{Chain: observationBinding.Chain, Type: DefenseValidationObservationSubjectTypeV02, ID: execution.Case.CaseRef},
		Window: securityevidence.ObservationWindow{FromUnixMS: 0, ToUnixMS: execution.Case.ObservationWindowMS}, SourceDigests: []string{execution.ContainmentReceiptSHA256, execution.AuthorityBindingSHA256},
		Findings: []securityevidence.Finding{{ID: DefenseValidationObservationFindingIDV02(control.ControlRef, execution.Case.CaseRef), Kind: DefenseValidationObservationFindingKindV02, State: securityevidence.StateVerified, EvidenceSHA256: digest}},
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdaptAuthoritySecurityEvidenceObservationV01(control, execution, observationBinding, event); err == nil {
		t.Fatal("execution was relabeled to a different observation chain")
	}
	base := authorityIntegrityValidationInput(t, "run:authority-binding", control, []DefenseValidationCaseV02{execution.Case}, nil)
	wrongChain := base
	wrongChain.RunRef = "run:wrong-chain"
	wrongChain.Chain = "other-chain"
	if _, err := EvaluateDefenseValidationV02(wrongChain); err == nil {
		t.Fatal("chain-bound execution was relabeled in the validation report")
	}
	wrongChainID := base
	wrongChainID.RunRef = "run:wrong-chain-id"
	wrongChainID.ChainID++
	if _, err := EvaluateDefenseValidationV02(wrongChainID); err == nil {
		t.Fatal("chain-bound execution ID was relabeled in the validation report")
	}
	wrongScenario := base
	wrongScenario.RunRef = "run:wrong-scenario"
	wrongScenario.ScenarioRef = "scenario:cosmos-evm:relabeled"
	if _, err := EvaluateDefenseValidationV02(wrongScenario); err == nil {
		t.Fatal("scenario-bound execution was relabeled in the validation report")
	}
	wrongScenarioVersion := base
	wrongScenarioVersion.RunRef = "run:wrong-scenario-version"
	wrongScenarioVersion.ScenarioVersion = "v9.9.9"
	if _, err := EvaluateDefenseValidationV02(wrongScenarioVersion); err == nil {
		t.Fatal("scenario-bound execution version was relabeled in the validation report")
	}
	wrongScenarioHash := base
	wrongScenarioHash.RunRef = "run:wrong-scenario-hash"
	wrongScenarioHash.ScenarioContractHash = defenseValidationV02TestHash("f")
	if _, err := EvaluateDefenseValidationV02(wrongScenarioHash); err == nil {
		t.Fatal("scenario-bound execution contract hash was relabeled in the validation report")
	}
}

func TestIndependentAuthorityDisagreementProducesMissAndFalsePositive(t *testing.T) {
	control := authorityIntegrityControl(t)
	attackBinding := authorityBindingResult(t, "account:victim", "account:caller")
	attack, err := AdaptAuthorityIntegrityCaseV01(authorityIntegrityAdapterInput(
		t, control, authorityAttackCaseRefV01, DefenseValidationCaseAttackV02, attackBinding, authorityContainmentReceipt(t, attackBinding),
	))
	if err != nil {
		t.Fatal(err)
	}
	benignBinding := authorityBindingResult(t, "account:caller", "account:caller")
	benign, err := AdaptAuthorityIntegrityCaseV01(authorityIntegrityAdapterInput(
		t, control, authorityBenignCaseRefV01, DefenseValidationCaseBenignV02, benignBinding, authorityContainmentReceipt(t, benignBinding),
	))
	if err != nil {
		t.Fatal(err)
	}
	falsePositiveOffset := int64(150)
	attackObservation := authorityIndependentObservationWithStatus(t, control, attack, DefenseValidationObservationNoAlertV02, nil)
	benignObservation := authorityIndependentObservationWithStatus(t, control, benign, DefenseValidationObservationAlertedV02, &falsePositiveOffset)
	report, err := EvaluateDefenseValidationV02(authorityIntegrityValidationInput(
		t,
		"run:disagreement",
		control,
		[]DefenseValidationCaseV02{attack.Case, benign.Case},
		[]DefenseValidationObservationV02{attackObservation, benignObservation},
	))
	if err != nil {
		t.Fatal(err)
	}
	if got := dvCaseResult(t, report, attack.Case.CaseRef); got.Outcome != DefenseValidationOutcomeMissedV02 {
		t.Fatalf("attack disagreement outcome=%s", got.Outcome)
	}
	if got := dvCaseResult(t, report, benign.Case.CaseRef); got.Outcome != DefenseValidationOutcomeFalsePositiveV02 {
		t.Fatalf("benign disagreement outcome=%s", got.Outcome)
	}
	if report.Verdict != DefenseValidationVerdictFailedV02 {
		t.Fatalf("disagreement report verdict=%s", report.Verdict)
	}
}

func authorityBindingEvidence(t *testing.T, declaredSource, authorizedSource string) DefenseAuthorityBindingEvidenceV01 {
	t.Helper()
	trust, principalPrivateKey, authorizationPrivateKey := authorityBindingTestTrustAndKeys()
	return authorityBindingEvidenceWithTrustAndKeys(t, declaredSource, authorizedSource, trust, principalPrivateKey, authorizationPrivateKey)
}

func authorityBindingEvidenceWithTrustAndKeys(
	t *testing.T,
	declaredSource, authorizedSource string,
	trust DefenseAuthorityEvidenceTrustV01,
	principalPrivateKey, authorizationPrivateKey ed25519.PrivateKey,
) DefenseAuthorityBindingEvidenceV01 {
	t.Helper()
	evidence := DefenseAuthorityBindingEvidenceV01{
		EvidenceState:           DefenseValidationEvidenceVerifiedV02,
		Chain:                   "cosmos-evm",
		ChainID:                 9001,
		CallerPrincipal:         "principal:contract-a",
		DeclaredSourceAccount:   declaredSource,
		RequestedOperation:      "debit",
		RequestedAsset:          "asset:bb",
		AuthorizedPrincipal:     "principal:contract-a",
		AuthorizedSourceAccount: authorizedSource,
		AuthorizedOperation:     "debit",
		AuthorizedAsset:         "asset:bb",
		CallPayloadSHA256:       strings.Repeat("1", 64),
		PreStateSHA256:          strings.Repeat("4", 64),
		PostStateSHA256:         strings.Repeat("5", 64),
		DebitEffectSHA256:       strings.Repeat("6", 64),
	}
	evidence.PrincipalEvidence = authoritySignedEvidenceArtifact(t, evidence, false, DefenseAuthorityEvidencePrincipalV01, trust.PrincipalProducerRef, principalPrivateKey)
	evidence.AuthorizationEvidence = authoritySignedEvidenceArtifact(t, evidence, true, DefenseAuthorityEvidenceAuthorizationV01, trust.AuthorizationProducerRef, authorizationPrivateKey)
	var err error
	evidence.PrincipalEvidenceSHA256, err = defenseAuthorityCanonicalSHA256V01(evidence.PrincipalEvidence)
	if err != nil {
		t.Fatal(err)
	}
	evidence.AuthorizationEvidenceSHA256, err = defenseAuthorityCanonicalSHA256V01(evidence.AuthorizationEvidence)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func authorityBindingTrust() DefenseAuthorityEvidenceTrustV01 {
	trust, _, _ := authorityBindingTestTrustAndKeys()
	return trust
}

func authorityBindingTestTrustAndKeys() (DefenseAuthorityEvidenceTrustV01, ed25519.PrivateKey, ed25519.PrivateKey) {
	principalSeed := make([]byte, ed25519.SeedSize)
	authorizationSeed := make([]byte, ed25519.SeedSize)
	for i := range principalSeed {
		principalSeed[i] = 0x21
		authorizationSeed[i] = 0x42
	}
	principalPrivateKey := ed25519.NewKeyFromSeed(principalSeed)
	authorizationPrivateKey := ed25519.NewKeyFromSeed(authorizationSeed)
	trust := DefenseAuthorityEvidenceTrustV01{
		PrincipalProducerRef:     "collector:principal-execution",
		PrincipalPublicKey:       base64.RawURLEncoding.EncodeToString(principalPrivateKey.Public().(ed25519.PublicKey)),
		AuthorizationProducerRef: "collector:authorization-state",
		AuthorizationPublicKey:   base64.RawURLEncoding.EncodeToString(authorizationPrivateKey.Public().(ed25519.PublicKey)),
	}
	return trust, principalPrivateKey, authorizationPrivateKey
}

func authoritySignedEvidenceArtifact(t *testing.T, evidence DefenseAuthorityBindingEvidenceV01, authorized bool, kind, producer string, privateKey ed25519.PrivateKey) DefenseAuthorityEvidenceArtifactV01 {
	t.Helper()
	principal, source, operation, asset := evidence.CallerPrincipal, evidence.DeclaredSourceAccount, evidence.RequestedOperation, evidence.RequestedAsset
	if authorized {
		principal, source, operation, asset = evidence.AuthorizedPrincipal, evidence.AuthorizedSourceAccount, evidence.AuthorizedOperation, evidence.AuthorizedAsset
	}
	artifact := DefenseAuthorityEvidenceArtifactV01{
		EvidenceState:     DefenseValidationEvidenceVerifiedV02,
		EvidenceKind:      kind,
		Producer:          producer,
		Chain:             evidence.Chain,
		ChainID:           evidence.ChainID,
		Principal:         principal,
		SourceAccount:     source,
		Operation:         operation,
		Asset:             asset,
		CallPayloadSHA256: evidence.CallPayloadSHA256,
		PreStateSHA256:    evidence.PreStateSHA256,
		PostStateSHA256:   evidence.PostStateSHA256,
		DebitEffectSHA256: evidence.DebitEffectSHA256,
	}
	payload, err := defenseAuthorityEvidenceArtifactSigningBytesV01(artifact)
	if err != nil {
		t.Fatal(err)
	}
	artifact = normalizeDefenseAuthorityEvidenceArtifactV01(artifact)
	artifact.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return artifact
}

func authorityBindingResult(t *testing.T, declaredSource, authorizedSource string) DefenseAuthorityBindingResultV01 {
	t.Helper()
	result, err := EvaluateDefenseAuthorityBindingV01(authorityBindingEvidence(t, declaredSource, authorizedSource), authorityBindingTrust())
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDefenseAuthorityBindingV01(result, authorityBindingTrust()) {
		t.Fatal("authority binding did not verify")
	}
	return result
}

func authorityContainmentReceipt(t *testing.T, binding DefenseAuthorityBindingResultV01) executioncontainment.Receipt {
	t.Helper()
	return authorityContainmentReceiptWithTrust(t, binding, authorityBindingTrust())
}

func authorityContainmentReceiptWithTrust(t *testing.T, binding DefenseAuthorityBindingResultV01, trust DefenseAuthorityEvidenceTrustV01) executioncontainment.Receipt {
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
	observation, err := ApplyDefenseAuthorityBindingToContainmentV01(observation, binding, trust)
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
	return DefenseAuthorityObservationBindingV01{Chain: execution.Chain, ChainID: execution.ChainID, ControlRef: control.ControlRef, CaseRef: execution.Case.CaseRef, Status: status, ExecutionHash: execution.Case.ExecutionHash, AlertObservedOffsetMS: alert, ObservationCompletedOffsetMS: execution.Case.ObservationWindowMS}
}

func authorityIndependentObservation(t *testing.T, control DefenseValidationControlV02, execution DefenseAuthorityExecutionEvidenceV01, alert *int64) DefenseValidationObservationV02 {
	t.Helper()
	binding := authorityObservationBinding(control, execution, alert)
	return authorityIndependentObservationWithStatus(t, control, execution, binding.Status, binding.AlertObservedOffsetMS)
}

func authorityIndependentObservationWithStatus(t *testing.T, control DefenseValidationControlV02, execution DefenseAuthorityExecutionEvidenceV01, status string, alert *int64) DefenseValidationObservationV02 {
	t.Helper()
	binding := authorityObservationBinding(control, execution, alert)
	binding.Status = status
	if status == DefenseValidationObservationNoAlertV02 {
		binding.AlertObservedOffsetMS = nil
	} else {
		binding.AlertObservedOffsetMS = cloneDefenseValidationInt64V02(alert)
	}
	digest, err := DefenseAuthorityObservationBindingDigestV01(binding)
	if err != nil {
		t.Fatal(err)
	}
	event, err := (securityevidence.Event{
		Producer:      control.CollectorRef,
		Subject:       securityevidence.Subject{Chain: execution.Chain, Type: DefenseValidationObservationSubjectTypeV02, ID: execution.Case.CaseRef},
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
