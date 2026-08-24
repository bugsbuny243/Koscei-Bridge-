package defensecollector

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"koschei/api/internal/defense"
	"koschei/api/internal/executioncontainment"
	"koschei/api/internal/executionproof"
)

func TestCollectV03ProducesEvidenceAcceptedByDefenseAdapter(t *testing.T) {
	req := collectorRequestV03(t, false)
	result, err := CollectV03(req, collectorPrivateKeyV03())
	if err != nil {
		t.Fatal(err)
	}
	if result.Version != VersionV03 {
		t.Fatalf("version=%s", result.Version)
	}
	if err := result.Event.Verify(); err != nil {
		t.Fatalf("event verification: %v", err)
	}
	if err := result.Event.VerifyEd25519(req.CollectorRef, req.Control.CollectorPublicKey); err != nil {
		t.Fatalf("event authentication: %v", err)
	}
	observation, err := defense.AdaptSecurityEvidenceObservationV02(req.Control, result.Execution, result.Binding, result.Event)
	if err != nil {
		t.Fatal(err)
	}
	if observation.Status != defense.DefenseValidationObservationNoAlertV02 || observation.CollectorRef != req.CollectorRef {
		t.Fatalf("observation=%#v", observation)
	}
}

func TestCollectV03RejectsSelfAttestation(t *testing.T) {
	req := collectorRequestV03(t, false)
	req.CollectorRef = req.Control.ControlRef
	req.Control.CollectorRef = req.Control.ControlRef
	if _, err := CollectV03(req, collectorPrivateKeyV03()); err == nil {
		t.Fatal("self-attested collector accepted")
	}
}

func TestCollectV03RejectsSigningKeyOutsideControlTrust(t *testing.T) {
	req := collectorRequestV03(t, false)
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x2f
	}
	if _, err := CollectV03(req, ed25519.NewKeyFromSeed(seed)); err == nil || !strings.Contains(err.Error(), "does not match control trust") {
		t.Fatalf("untrusted collector signing key was accepted: %v", err)
	}
}

func TestCollectV03RejectsTamperedExecutionProof(t *testing.T) {
	req := collectorRequestV03(t, false)
	req.ExecutionProof.Evaluation.Decision = executionproof.DecisionBlock
	if _, err := CollectV03(req, collectorPrivateKeyV03()); err == nil || !strings.Contains(err.Error(), "recompute execution evidence") {
		t.Fatalf("tampered proof error=%v", err)
	}
}

func TestCollectV03RejectsIncompleteObservationWindow(t *testing.T) {
	req := collectorRequestV03(t, false)
	req.ObservationCompletedOffsetMS = req.ObservationWindowMS - 1
	if _, err := CollectV03(req, collectorPrivateKeyV03()); err == nil || !strings.Contains(err.Error(), "window is incomplete") {
		t.Fatalf("incomplete window error=%v", err)
	}
}

func TestCollectV03RequiresIndependentAlertForSignaledControl(t *testing.T) {
	req := collectorRequestV03(t, true)
	req.AlertObservedOffsetMS = nil
	if _, err := CollectV03(req, collectorPrivateKeyV03()); err == nil || !strings.Contains(err.Error(), "requires independently observed alert offset") {
		t.Fatalf("missing alert error=%v", err)
	}
	alert := int64(120)
	req.AlertObservedOffsetMS = &alert
	result, err := CollectV03(req, collectorPrivateKeyV03())
	if err != nil {
		t.Fatal(err)
	}
	if result.Binding.Status != defense.DefenseValidationObservationAlertedV02 {
		t.Fatalf("status=%s", result.Binding.Status)
	}
	if _, err := defense.AdaptSecurityEvidenceObservationV02(req.Control, result.Execution, result.Binding, result.Event); err != nil {
		t.Fatal(err)
	}
}

func TestCollectV03SubprocessRoundTrip(t *testing.T) {
	req := collectorRequestV03(t, false)
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCollectV03HelperProcess$", "--")
	cmd.Env = append(os.Environ(), "KOSCHEI_COLLECTOR_HELPER=1")
	cmd.Stdin = bytes.NewReader(payload)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("collector helper: %v", err)
	}
	var result ResultV03
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("decode collector result: %v; output=%s", err, out)
	}
	if err := result.Event.Verify(); err != nil {
		t.Fatal(err)
	}
	if result.Event.Producer != req.CollectorRef {
		t.Fatalf("producer=%s", result.Event.Producer)
	}
	if _, err := defense.AdaptSecurityEvidenceObservationV02(req.Control, result.Execution, result.Binding, result.Event); err != nil {
		t.Fatal(err)
	}
}

func TestCollectV03HelperProcess(t *testing.T) {
	if os.Getenv("KOSCHEI_COLLECTOR_HELPER") != "1" {
		return
	}
	decoder := json.NewDecoder(os.Stdin)
	decoder.DisallowUnknownFields()
	var req RequestV03
	if err := decoder.Decode(&req); err != nil {
		os.Exit(2)
	}
	result, err := CollectV03(req, collectorPrivateKeyV03())
	if err != nil {
		os.Exit(3)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		os.Exit(4)
	}
	os.Exit(0)
}

func collectorRequestV03(t *testing.T, signaled bool) RequestV03 {
	t.Helper()
	control, err := defense.NewExecutionIntegrityControlV02(
		"control:execution-integrity",
		"collector:independent-process",
		defense.DefenseValidationExecutionIntegrityConfigV02{CollectorPublicKey: collectorPublicKeyV03(), IndependentCollectorRequired: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	scenario := collectorScenarioV03(t)
	approved := collectorSafeTxV03("0x2222222222222222222222222222222222222222", nil)
	candidate := approved
	if signaled {
		candidate = collectorSafeTxV03("0x9999999999999999999999999999999999999999", nil)
	}
	proof, receipt := collectorProofReceiptV03(t, approved, candidate)
	var impact *int64
	caseKind := defense.DefenseValidationCaseBenignV02
	caseRef := "case:evm:safe-authorized-transfer-benign"
	if signaled {
		value := int64(1000)
		impact = &value
		caseKind = defense.DefenseValidationCaseAttackV02
		caseRef = "case:evm:safe-intent-mutation-attack"
	}
	return RequestV03{
		Version:                      VersionV03,
		CollectorRef:                 control.CollectorRef,
		Control:                      control,
		Scenario:                     scenario,
		Chain:                        "evm",
		CaseRef:                      caseRef,
		CaseKind:                     caseKind,
		TechniqueID:                  "safe-intent-mutation",
		ExecutionMode:                defense.DefenseValidationExecutionForkV02,
		ImpactOffsetMS:               impact,
		ObservationWindowMS:          3000,
		ObservationCompletedOffsetMS: 3000,
		WindowFromUnixMS:             10000,
		WindowToUnixMS:               13000,
		ContainmentReceipt:           receipt,
		ExecutionProof:               proof,
	}
}

func collectorSafeTxV03(to string, data []byte) executionproof.SafeTransaction {
	return executionproof.SafeTransaction{
		ChainID:        31337,
		Safe:           "0x1111111111111111111111111111111111111111",
		To:             to,
		Value:          big.NewInt(0),
		Data:           append([]byte(nil), data...),
		Operation:      0,
		SafeTxGas:      big.NewInt(50000),
		BaseGas:        big.NewInt(21000),
		GasPrice:       big.NewInt(0),
		GasToken:       "0x0000000000000000000000000000000000000000",
		RefundReceiver: "0x0000000000000000000000000000000000000000",
		Nonce:          big.NewInt(7),
	}
}

func collectorProofReceiptV03(t *testing.T, approved, candidate executionproof.SafeTransaction) (executionproof.Proof, executioncontainment.Receipt) {
	t.Helper()
	approvedIntent, err := (executionproof.NativeSafeTxHashComputer{}).ComputeSafeTxHash(approved)
	if err != nil {
		t.Fatal(err)
	}
	candidateIntent, err := (executionproof.NativeSafeTxHashComputer{}).ComputeSafeTxHash(candidate)
	if err != nil {
		t.Fatal(err)
	}
	approvedPayload := collectorSHA256V03(approved.Data)
	candidatePayload := collectorSHA256V03(candidate.Data)
	artifact := strings.Repeat("1", 64)
	invariant := strings.Repeat("2", 64)
	proof, err := executionproof.Evaluate(executionproof.Envelope{
		Source:  executionproof.SourceEvidence{CommitID: strings.Repeat("a", 40), TreeID: strings.Repeat("b", 40)},
		Build:   executionproof.BuildEvidence{ToolchainSHA256: strings.Repeat("3", 64), ApprovedArtifactSHA256: artifact, BuiltArtifactSHA256: artifact},
		Runtime: executionproof.RuntimeEvidence{ObservedArtifactSHA256: artifact, PolicySHA256: strings.Repeat("4", 64)},
		Payload: executionproof.PayloadEvidence{
			ChainID: candidate.ChainID, Target: candidate.To,
			ApprovedCalldataSHA256: approvedPayload, GeneratedCalldataSHA256: candidatePayload,
			GeneratorSHA256: strings.Repeat("5", 64),
		},
		Simulation:    executionproof.SimulationEvidence{InvariantSetSHA256: invariant, Result: "PASS"},
		Authorization: executionproof.AuthorizationEvidence{SigningPolicySHA256: strings.Repeat("6", 64), ApprovedSigningRequestID: approvedIntent},
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
		ApprovedIntentSHA256:   strings.TrimPrefix(approvedIntent, "0x"),
		CandidateIntentSHA256:  strings.TrimPrefix(candidateIntent, "0x"),
		ApprovedPayloadSHA256:  approvedPayload,
		CandidatePayloadSHA256: candidatePayload,
		ActionSHA256:           action.SHA256(),
		InvariantSetSHA256:     invariant,
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

func collectorSHA256V03(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func collectorPrivateKeyV03() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x6c
	}
	return ed25519.NewKeyFromSeed(seed)
}

func collectorPublicKeyV03() string {
	return base64.RawURLEncoding.EncodeToString(collectorPrivateKeyV03().Public().(ed25519.PublicKey))
}

func collectorScenarioV03(t *testing.T) defense.DefenseValidationScenarioV02 {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "docs", "defense-validation", "scenarios", "safe-intent-mutation-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	scenario, err := defense.ParseDefenseValidationScenarioV02(data)
	if err != nil {
		t.Fatal(err)
	}
	return scenario
}
