package defense_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"koschei/api/internal/defense"
	"koschei/api/internal/defensecollector"
	"koschei/api/internal/executioncontainment"
	"koschei/api/internal/executionproof"
)

func TestRealAnvilSafeIntentMutationValidationV04(t *testing.T) {
	if os.Getenv("KOSCHEI_SAFE_ANVIL_INTEGRATION") != "1" {
		t.Skip("real Anvil integration is opt-in")
	}

	cfg := realAnvilValidationConfigV04{
		anvilPath:  mustEnvDefenseV04(t, "KOSCHEI_ANVIL_PATH"),
		forkURL:    mustEnvDefenseV04(t, "KOSCHEI_SAFE_FORK_URL"),
		safe:       mustEnvDefenseV04(t, "KOSCHEI_SAFE_ADDRESS"),
		accessor:   mustEnvDefenseV04(t, "KOSCHEI_SAFE_ACCESSOR_ADDRESS"),
		target:     mustEnvDefenseV04(t, "KOSCHEI_SAFE_TARGET_ADDRESS"),
		blockHash:  strings.TrimPrefix(mustEnvDefenseV04(t, "KOSCHEI_SAFE_BLOCK_HASH"), "0x"),
		runnerHash: strings.TrimPrefix(mustEnvDefenseV04(t, "KOSCHEI_ANVIL_SHA256"), "0x"),
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
		"control:execution-integrity-real-anvil",
		"collector:independent-real-anvil",
		defense.DefenseValidationExecutionIntegrityConfigV02{IndependentCollectorRequired: true},
	)
	if err != nil {
		t.Fatal(err)
	}

	approved := realSafeTxV04(cfg, big.NewInt(1_000_000_000_000_000_000))
	mutated := realSafeTxV04(cfg, big.NewInt(2_000_000_000_000_000_000))

	benign := realValidationCaseV04(t, cfg, control, approved, approved, defense.DefenseValidationCaseBenignV02)
	attack := realValidationCaseV04(t, cfg, control, approved, mutated, defense.DefenseValidationCaseAttackV02)

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
		RunRef:          "run:real-anvil-safe-intent-mutation-v04",
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
		t.Fatalf("real Anvil verdict=%s", report.Verdict)
	}
	attackResult := realCaseResultV04(t, report, attack.execution.Case.CaseRef)
	if attackResult.Outcome != defense.DefenseValidationOutcomeCaughtInTimeV02 {
		t.Fatalf("real attack outcome=%s", attackResult.Outcome)
	}
	if attackResult.LeadTimeMS == nil || *attackResult.LeadTimeMS != 880 {
		t.Fatalf("real attack lead time=%v", attackResult.LeadTimeMS)
	}
	if got := realCaseResultV04(t, report, benign.execution.Case.CaseRef); got.Outcome != defense.DefenseValidationOutcomeCleanV02 {
		t.Fatalf("real benign outcome=%s", got.Outcome)
	}
}

type realAnvilValidationConfigV04 struct {
	anvilPath   string
	forkURL     string
	safe        string
	accessor    string
	target      string
	blockHash   string
	runnerHash  string
	blockNumber uint64
	chainID     uint64
}

type realValidationCaseResultV04 struct {
	receipt     executioncontainment.Receipt
	execution   defense.DefenseValidationExecutionEvidenceV02
	observation defense.DefenseValidationObservationV02
}

func realValidationCaseV04(t *testing.T, cfg realAnvilValidationConfigV04, control defense.DefenseValidationControlV02, approved, candidate executionproof.SafeTransaction, kind string) realValidationCaseResultV04 {
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
	invariantHash := sha256HexDefenseV04([]byte("koschei-real-anvil-safe-native-call-invariants/v0.4"))

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
		Engine: executionproof.AnvilSafeSimulationEngine{
			AnvilPath: cfg.anvilPath, ForkURL: cfg.forkURL, Accessor: cfg.accessor,
			StartupTimeout: 20 * time.Second, RPCTimeout: 10 * time.Second,
		},
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
		Source:        executionproof.SourceEvidence{CommitID: strings.Repeat("a", 40), TreeID: strings.Repeat("b", 40)},
		Build:         executionproof.BuildEvidence{ToolchainSHA256: strings.Repeat("3", 64), ApprovedArtifactSHA256: strings.Repeat("1", 64), BuiltArtifactSHA256: strings.Repeat("1", 64)},
		Runtime:       executionproof.RuntimeEvidence{ObservedArtifactSHA256: strings.Repeat("1", 64), PolicySHA256: strings.Repeat("4", 64)},
		Payload:       executionproof.PayloadEvidence{ChainID: cfg.chainID, Target: candidate.To, ApprovedCalldataSHA256: sha256HexDefenseV04(approved.Data), GeneratedCalldataSHA256: payloadHash, GeneratorSHA256: strings.Repeat("5", 64)},
		Simulation:    executionproof.SimulationEvidence{InvariantSetSHA256: invariantHash, Result: "PASS"},
		Authorization: executionproof.AuthorizationEvidence{SigningPolicySHA256: strings.Repeat("6", 64), ApprovedSigningRequestID: approvedHash},
	})
	if err != nil {
		t.Fatal(err)
	}

	var impact *int64
	caseRef := "case:evm:safe-authorized-native-transfer-real-anvil"
	var alert *int64
	if kind == defense.DefenseValidationCaseAttackV02 {
		impactValue := int64(1000)
		impact = &impactValue
		caseRef = "case:evm:safe-intent-value-mutation-real-anvil"
		alertValue := int64(120)
		alert = &alertValue
	}
	collected, err := defensecollector.CollectV03(defensecollector.RequestV03{
		Version:                      defensecollector.VersionV03,
		CollectorRef:                 control.CollectorRef,
		Control:                      control,
		Chain:                        "evm",
		CaseRef:                      caseRef,
		CaseKind:                     kind,
		TechniqueID:                  "safe-intent-mutation",
		ExecutionMode:                defense.DefenseValidationExecutionForkV02,
		ImpactOffsetMS:               impact,
		ObservationWindowMS:          3000,
		ObservationCompletedOffsetMS: 3000,
		AlertObservedOffsetMS:        alert,
		WindowFromUnixMS:             0,
		WindowToUnixMS:               3000,
		MainnetTransactionSent:       false,
		ContainmentReceipt:           receipt,
		ExecutionProof:               proof,
	})
	if err != nil {
		t.Fatalf("collect independent real execution %s: %v", kind, err)
	}
	adaptedObservation, err := defense.AdaptSecurityEvidenceObservationV02(control, collected.Execution, collected.Binding, collected.Event)
	if err != nil {
		t.Fatalf("adapt independent real observation %s: %v", kind, err)
	}
	return realValidationCaseResultV04{receipt: receipt, execution: collected.Execution, observation: adaptedObservation}
}

func realSafeTxV04(cfg realAnvilValidationConfigV04, value *big.Int) executionproof.SafeTransaction {
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
