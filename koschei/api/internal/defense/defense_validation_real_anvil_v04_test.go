package defense_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"koschei/api/internal/defense"
	"koschei/api/internal/defensecollector"
	"koschei/api/internal/executioncontainment"
	"koschei/api/internal/executionproof"
	"koschei/api/internal/securityevidence"
)

func TestRealAnvilSafeIntentMutationValidationV05(t *testing.T) {
	if os.Getenv("KOSCHEI_SAFE_ANVIL_INTEGRATION") != "1" {
		t.Skip("real Anvil integration is opt-in")
	}

	cfg := realAnvilValidationConfigV05{
		anvilPath:        mustEnvDefenseV04(t, "KOSCHEI_ANVIL_PATH"),
		forkURL:          mustEnvDefenseV04(t, "KOSCHEI_SAFE_FORK_URL"),
		safe:             mustEnvDefenseV04(t, "KOSCHEI_SAFE_ADDRESS"),
		accessor:         mustEnvDefenseV04(t, "KOSCHEI_SAFE_ACCESSOR_ADDRESS"),
		target:           mustEnvDefenseV04(t, "KOSCHEI_SAFE_TARGET_ADDRESS"),
		blockHash:        strings.TrimPrefix(mustEnvDefenseV04(t, "KOSCHEI_SAFE_BLOCK_HASH"), "0x"),
		runnerHash:       strings.TrimPrefix(mustEnvDefenseV04(t, "KOSCHEI_ANVIL_SHA256"), "0x"),
		sourceCommit:     mustEnvDefenseV04(t, "KOSCHEI_SOURCE_COMMIT"),
		sourceTree:       mustEnvDefenseV04(t, "KOSCHEI_SOURCE_TREE"),
		toolchainHash:    mustEnvDefenseV04(t, "KOSCHEI_TOOLCHAIN_SHA256"),
		approvedArtifact: mustEnvDefenseV04(t, "KOSCHEI_APPROVED_ARTIFACT_SHA256"),
		builtArtifact:    mustEnvDefenseV04(t, "KOSCHEI_BUILT_ARTIFACT_SHA256"),
		observedArtifact: mustEnvDefenseV04(t, "KOSCHEI_OBSERVED_ARTIFACT_SHA256"),
		policyHash:       mustEnvDefenseV04(t, "KOSCHEI_POLICY_SHA256"),
		generatorHash:    mustEnvDefenseV04(t, "KOSCHEI_GENERATOR_SHA256"),
		observerPath:     mustEnvDefenseV04(t, "KOSCHEI_ALERT_OBSERVER_PATH"),
	}
	var err error
	cfg.blockNumber, err = strconv.ParseUint(mustEnvDefenseV04(t, "KOSCHEI_SAFE_BLOCK_NUMBER"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	cfg.chainID, err = strconv.ParseUint(mustEnvDefenseV04(t, "KOSCHEI_SAFE_CHAIN_ID"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}

	control, err := defense.NewExecutionIntegrityControlV02(
		"control:execution-integrity-real-anvil-v05",
		"collector:independent-real-anvil-v05",
		defense.DefenseValidationExecutionIntegrityConfigV02{IndependentCollectorRequired: true},
	)
	if err != nil {
		t.Fatal(err)
	}

	approved := realSafeTxV05(cfg, big.NewInt(1_000_000_000_000_000_000))
	mutated := realSafeTxV05(cfg, big.NewInt(2_000_000_000_000_000_000))

	benign := realValidationCaseV05(t, cfg, control, approved, approved, defense.DefenseValidationCaseBenignV02)
	attack := realValidationCaseV05(t, cfg, control, approved, mutated, defense.DefenseValidationCaseAttackV02)

	if benign.execution.ContainmentDecision != executioncontainment.DecisionRelease || benign.execution.ControlSignaled {
		t.Fatalf("benign control signal=%s/%v", benign.execution.ContainmentDecision, benign.execution.ControlSignaled)
	}
	if attack.execution.ContainmentDecision != executioncontainment.DecisionContain || !attack.execution.ControlSignaled {
		t.Fatalf("attack control signal=%s/%v", attack.execution.ContainmentDecision, attack.execution.ControlSignaled)
	}
	if !hasContainmentReasonV04(attack.receipt.Reasons, executioncontainment.ReasonIntentMismatch) {
		t.Fatalf("mutated SafeTxHash did not produce intent mismatch: %#v", attack.receipt.Reasons)
	}

	report, err := defense.EvaluateDefenseValidationV02(defense.DefenseValidationInputV02{
		RunRef:          "run:real-anvil-safe-intent-mutation-v05",
		ScenarioRef:     "scenario:evm:safe-intent-mutation",
		ScenarioVersion: "v1.0.0",
		Chain:           "evm",
		RulesetVersion:  defense.DefenseValidationRulesetVersionV02,
		Controls:        []defense.DefenseValidationControlV02{control},
		Cases:           []defense.DefenseValidationCaseV02{attack.execution.Case, benign.execution.Case},
		Observations:    []defense.DefenseValidationObservationV02{attack.observation, benign.observation},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != defense.DefenseValidationVerdictValidatedV02 {
		t.Fatalf("real Anvil hardened verdict=%s", report.Verdict)
	}
	attackResult := realCaseResultV04(t, report, attack.execution.Case.CaseRef)
	if attackResult.Outcome != defense.DefenseValidationOutcomeCaughtInTimeV02 {
		t.Fatalf("real attack outcome=%s", attackResult.Outcome)
	}
	if attackResult.LeadTimeMS == nil || *attackResult.LeadTimeMS <= 0 {
		t.Fatalf("real attack lead time=%v", attackResult.LeadTimeMS)
	}
	if got := realCaseResultV04(t, report, benign.execution.Case.CaseRef); got.Outcome != defense.DefenseValidationOutcomeCleanV02 {
		t.Fatalf("real benign outcome=%s", got.Outcome)
	}
}

type realAnvilValidationConfigV05 struct {
	anvilPath        string
	forkURL          string
	safe             string
	accessor         string
	target           string
	blockHash        string
	runnerHash       string
	sourceCommit     string
	sourceTree       string
	toolchainHash    string
	approvedArtifact string
	builtArtifact    string
	observedArtifact string
	policyHash       string
	generatorHash    string
	observerPath     string
	blockNumber      uint64
	chainID          uint64
}

type realValidationCaseResultV05 struct {
	receipt     executioncontainment.Receipt
	execution   defense.DefenseValidationExecutionEvidenceV02
	observation defense.DefenseValidationObservationV02
}

func realValidationCaseV05(t *testing.T, cfg realAnvilValidationConfigV05, control defense.DefenseValidationControlV02, approved, candidate executionproof.SafeTransaction, kind string) realValidationCaseResultV05 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	approvedHash, err := (executionproof.NativeSafeTxHashComputer{}).ComputeSafeTxHash(approved)
	if err != nil {
		t.Fatal(err)
	}
	candidateHash, err := (executionproof.NativeSafeTxHashComputer{}).ComputeSafeTxHash(candidate)
	if err != nil {
		t.Fatal(err)
	}
	action, err := executionproof.CanonicalSafeActionArtifact(candidate)
	if err != nil {
		t.Fatal(err)
	}
	payloadHash := sha256HexDefenseV04(candidate.Data)
	invariantHash := sha256HexDefenseV04([]byte("koschei-real-anvil-safe-inert-target-invariants/v0.5"))

	input := executioncontainment.CellInput{
		ChainID:                cfg.chainID,
		BlockNumber:            cfg.blockNumber,
		BlockHash:              cfg.blockHash,
		Target:                 candidate.To,
		ApprovedIntentSHA256:   strings.TrimPrefix(approvedHash, "0x"),
		CandidateIntentSHA256:  strings.TrimPrefix(candidateHash, "0x"),
		ApprovedPayloadSHA256:  sha256HexDefenseV04(approved.Data),
		CandidatePayloadSHA256: payloadHash,
		ActionSHA256:           action.SHA256(),
		InvariantSetSHA256:     invariantHash,
		ApprovedRunnerSHA256:   cfg.runnerHash,
	}
	backend := executionproof.PinnedSafeBackend{
		Engine: executionproof.AnvilSafeInertTargetEngineV05{AnvilSafeSimulationEngine: executionproof.AnvilSafeSimulationEngine{
			AnvilPath: cfg.anvilPath, ForkURL: cfg.forkURL, Accessor: cfg.accessor,
			StartupTimeout: 20 * time.Second, RPCTimeout: 10 * time.Second,
		}},
		Accessor: cfg.accessor,
	}
	evidence, err := backend.ExecuteSafe(ctx, input, candidate)
	if err != nil {
		t.Fatalf("real Safe execution %s: %v", kind, err)
	}
	authorityPreserved := equalAuthorityDefenseV04(evidence.Before, evidence.After)
	movementPreserved := exactNativeMovementDefenseV04(evidence, candidate)
	codePreserved := strings.EqualFold(evidence.Before.Implementation, evidence.After.Implementation) && strings.EqualFold(evidence.Before.CodeHash, evidence.After.CodeHash)
	traceObserved := evidence.Trace.TraceSHA256 != "" && len(evidence.Trace.Frames) >= 2
	observation := executioncontainment.Observation{
		BackendAvailable:           true,
		ObservedChainID:            evidence.ChainID,
		ObservedBlockNumber:        evidence.BlockNumber,
		ObservedBlockHash:          strings.TrimPrefix(evidence.BlockHash, "0x"),
		ObservedRunnerSHA256:       strings.TrimPrefix(evidence.RunnerSHA256, "0x"),
		PreStateSHA256:             strings.TrimPrefix(evidence.PreStateSHA256, "0x"),
		PostStateSHA256:            strings.TrimPrefix(evidence.PostStateSHA256, "0x"),
		EffectSetSHA256:            strings.TrimPrefix(evidence.EffectSetSHA256, "0x"),
		AuthorityPreserved:         authorityPreserved,
		AssetBoundsPreserved:       movementPreserved,
		CodeIntegrityPreserved:     codePreserved,
		ExecutionPathFullyObserved: traceObserved,
		InvariantsPass:             authorityPreserved && movementPreserved && codePreserved && traceObserved,
	}
	receipt, err := executioncontainment.Evaluate(input, observation)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := executionproof.Evaluate(executionproof.Envelope{
		Source:        executionproof.SourceEvidence{CommitID: cfg.sourceCommit, TreeID: cfg.sourceTree},
		Build:         executionproof.BuildEvidence{ToolchainSHA256: cfg.toolchainHash, ApprovedArtifactSHA256: cfg.approvedArtifact, BuiltArtifactSHA256: cfg.builtArtifact},
		Runtime:       executionproof.RuntimeEvidence{ObservedArtifactSHA256: cfg.observedArtifact, PolicySHA256: cfg.policyHash},
		Payload:       executionproof.PayloadEvidence{ChainID: cfg.chainID, Target: candidate.To, ApprovedCalldataSHA256: sha256HexDefenseV04(approved.Data), GeneratedCalldataSHA256: payloadHash, GeneratorSHA256: cfg.generatorHash},
		Simulation:    executionproof.SimulationEvidence{InvariantSetSHA256: invariantHash, Result: "PASS"},
		Authorization: executionproof.AuthorizationEvidence{SigningPolicySHA256: strings.TrimPrefix(strings.ToLower(control.ConfigurationHash), "sha256:"), ApprovedSigningRequestID: approvedHash},
	})
	if err != nil {
		t.Fatal(err)
	}

	const observationWindowMS = int64(800)
	var impact *int64
	caseRef := "case:evm:safe-authorized-native-transfer-real-anvil-v05"
	if kind == defense.DefenseValidationCaseAttackV02 {
		impactValue := int64(600)
		impact = &impactValue
		caseRef = "case:evm:safe-intent-value-mutation-real-anvil-v05"
	}

	request := defensecollector.RequestV04{
		Version: defensecollector.VersionV04, CollectorRef: control.CollectorRef, Control: control, Chain: "evm",
		CaseRef: caseRef, CaseKind: kind, TechniqueID: "safe-intent-mutation", ExecutionMode: defense.DefenseValidationExecutionForkV02,
		ImpactOffsetMS: impact, ObservationWindowMS: observationWindowMS, MainnetTransactionSent: false,
		ContainmentReceipt: receipt, ExecutionProof: proof,
	}

	var alerts chan securityevidence.Event
	var observerDone chan error
	if kind == defense.DefenseValidationCaseAttackV02 {
		alerts = make(chan securityevidence.Event, 1)
		observerDone = make(chan error, 1)
		go func() {
			time.Sleep(100 * time.Millisecond)
			event, observeErr := runIndependentAlertObserverV05(ctx, cfg.observerPath, control, receipt, proof, caseRef, kind, impact, observationWindowMS)
			if observeErr == nil {
				alerts <- event
			}
			close(alerts)
			observerDone <- observeErr
		}()
	}

	collected, err := defensecollector.CollectLiveV04(ctx, request, alerts)
	if err != nil {
		t.Fatalf("collect live independent execution %s: %v", kind, err)
	}
	if observerDone != nil {
		if observeErr := <-observerDone; observeErr != nil {
			t.Fatalf("independent alert observer: %v", observeErr)
		}
	}
	adaptedObservation, err := defense.AdaptSecurityEvidenceObservationV03(control, collected.Execution, collected.Binding, collected.Event, collected.AlertEvent)
	if err != nil {
		t.Fatalf("adapt hardened independent observation %s: %v", kind, err)
	}
	if collected.Binding.ObservationCompletedOffsetMS < observationWindowMS {
		t.Fatalf("real observation window did not elapse: %dms", collected.Binding.ObservationCompletedOffsetMS)
	}
	if kind == defense.DefenseValidationCaseAttackV02 {
		if collected.AlertEvent == nil || collected.Binding.AlertObservedOffsetMS == nil || *collected.Binding.AlertObservedOffsetMS <= 0 || *collected.Binding.AlertObservedOffsetMS >= *impact {
			t.Fatalf("independent alert timing is not before impact: event=%v offset=%v impact=%v", collected.AlertEvent != nil, collected.Binding.AlertObservedOffsetMS, impact)
		}
	} else if collected.AlertEvent != nil || collected.Binding.AlertObservedOffsetMS != nil {
		t.Fatal("benign case unexpectedly carried alert evidence")
	}
	return realValidationCaseResultV05{receipt: receipt, execution: collected.Execution, observation: adaptedObservation}
}

func runIndependentAlertObserverV05(ctx context.Context, path string, control defense.DefenseValidationControlV02, receipt executioncontainment.Receipt, proof executionproof.Proof, caseRef, kind string, impact *int64, windowMS int64) (securityevidence.Event, error) {
	request := struct {
		ObserverRef         string                              `json:"observer_ref"`
		Chain               string                              `json:"chain"`
		Control             defense.DefenseValidationControlV02 `json:"control"`
		CaseRef             string                              `json:"case_ref"`
		CaseKind            string                              `json:"case_kind"`
		TechniqueID         string                              `json:"technique_id"`
		ExecutionMode       string                              `json:"execution_mode"`
		ImpactOffsetMS      *int64                              `json:"impact_offset_ms,omitempty"`
		ObservationWindowMS int64                               `json:"observation_window_ms"`
		ContainmentReceipt  executioncontainment.Receipt        `json:"containment_receipt"`
		ExecutionProof      executionproof.Proof                `json:"execution_proof"`
	}{
		ObserverRef: "observer:real-anvil-alert-v05", Chain: "evm", Control: control, CaseRef: caseRef, CaseKind: kind,
		TechniqueID: "safe-intent-mutation", ExecutionMode: defense.DefenseValidationExecutionForkV02, ImpactOffsetMS: impact,
		ObservationWindowMS: windowMS, ContainmentReceipt: receipt, ExecutionProof: proof,
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return securityevidence.Event{}, err
	}
	cmd := exec.CommandContext(ctx, path)
	cmd.Stdin = bytes.NewReader(payload)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return securityevidence.Event{}, fmt.Errorf("observer process: %w: %s", err, strings.TrimSpace(string(output)))
	}
	var event securityevidence.Event
	if err := json.Unmarshal(output, &event); err != nil {
		return securityevidence.Event{}, fmt.Errorf("decode observer event: %w", err)
	}
	return event, nil
}

func realSafeTxV05(cfg realAnvilValidationConfigV05, value *big.Int) executionproof.SafeTransaction {
	return executionproof.SafeTransaction{
		ChainID: cfg.chainID, Safe: cfg.safe, To: cfg.target, Value: new(big.Int).Set(value), Data: nil, Operation: 0,
		SafeTxGas: big.NewInt(0), BaseGas: big.NewInt(0), GasPrice: big.NewInt(0),
		GasToken: "0x0000000000000000000000000000000000000000", RefundReceiver: "0x0000000000000000000000000000000000000000", Nonce: big.NewInt(0),
	}
}

func equalAuthorityDefenseV04(a, b executionproof.SafeAuthoritySnapshot) bool {
	if a.Threshold != b.Threshold || !strings.EqualFold(a.Guard, b.Guard) || !strings.EqualFold(a.FallbackHandler, b.FallbackHandler) || len(a.Owners) != len(b.Owners) || len(a.Modules) != len(b.Modules) {
		return false
	}
	for i := range a.Owners {
		if !strings.EqualFold(a.Owners[i], b.Owners[i]) {
			return false
		}
	}
	for i := range a.Modules {
		if !strings.EqualFold(a.Modules[i], b.Modules[i]) {
			return false
		}
	}
	return true
}

func exactNativeMovementDefenseV04(e executionproof.SafeExecutionEvidence, tx executionproof.SafeTransaction) bool {
	return len(e.AssetMovements) == 1 &&
		strings.EqualFold(e.AssetMovements[0].Kind, "native") &&
		strings.EqualFold(e.AssetMovements[0].From, tx.Safe) &&
		strings.EqualFold(e.AssetMovements[0].To, tx.To) &&
		e.AssetMovements[0].Amount == tx.Value.String()
}

func realCaseResultV04(t *testing.T, report defense.DefenseValidationReportV02, caseRef string) defense.DefenseValidationCaseResultV02 {
	t.Helper()
	for _, control := range report.Controls {
		for _, result := range control.Cases {
			if result.CaseRef == caseRef {
				return result
			}
		}
	}
	t.Fatalf("case result %q not found", caseRef)
	return defense.DefenseValidationCaseResultV02{}
}

func hasContainmentReasonV04(reasons []executioncontainment.ReasonCode, want executioncontainment.ReasonCode) bool {
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}

func mustEnvDefenseV04(t *testing.T, key string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		t.Fatalf("%s is required", key)
	}
	return value
}

func sha256HexDefenseV04(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
