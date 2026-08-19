package executionproof

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"koschei/api/internal/matrixcontainment"
)

type SafeAuthoritySnapshot struct {
	Owners          []string `json:"owners"`
	Threshold       uint64   `json:"threshold"`
	Modules         []string `json:"modules"`
	Guard           string   `json:"guard"`
	FallbackHandler string   `json:"fallback_handler"`
	Implementation  string   `json:"implementation"`
	CodeHash        string   `json:"code_hash"`
}

type SafeAssetMovement struct {
	Kind   string `json:"kind"`
	Token  string `json:"token"`
	From   string `json:"from"`
	To     string `json:"to"`
	ID     string `json:"id"`
	Amount string `json:"amount"`
}

type SafeOutflowBound struct {
	Kind      string `json:"kind"`
	Token     string `json:"token"`
	To        string `json:"to"`
	ID        string `json:"id"`
	MaxAmount string `json:"max_amount"`
}

type SafeContainmentPolicy struct {
	Version        string             `json:"version"`
	Safe           string             `json:"safe"`
	AllowAuthority bool               `json:"allow_authority_change"`
	AllowedOutflow []SafeOutflowBound `json:"allowed_outflow"`
}

const SafeContainmentPolicyVersion = "koschei-safe-containment-policy/v0.1"

type SafeExecutionEvidence struct {
	ChainID          uint64                `json:"chain_id"`
	BlockNumber      uint64                `json:"block_number"`
	BlockHash        string                `json:"block_hash"`
	RunnerSHA256     string                `json:"runner_sha256"`
	PreStateSHA256   string                `json:"pre_state_sha256"`
	PostStateSHA256  string                `json:"post_state_sha256"`
	EffectSetSHA256  string                `json:"effect_set_sha256"`
	Before           SafeAuthoritySnapshot `json:"before"`
	After            SafeAuthoritySnapshot `json:"after"`
	AssetMovements   []SafeAssetMovement   `json:"asset_movements"`
	Trace            SafeTraceEvidence     `json:"trace"`
}

// SafeIsolatedBackend is deliberately observation-only. It executes the exact
// Safe action in an isolated pinned-state runtime and returns evidence. It has
// no production forwarding, signing or custody authority.
type SafeIsolatedBackend interface {
	ExecuteSafe(ctx context.Context, input matrixcontainment.CellInput, tx SafeTransaction) (SafeExecutionEvidence, error)
}

type SafeIsolatedRunner struct {
	Backend SafeIsolatedBackend
	Policy  SafeContainmentPolicy
}

func (r SafeIsolatedRunner) Observe(ctx context.Context, input matrixcontainment.CellInput, action matrixcontainment.ActionArtifact) (matrixcontainment.Observation, error) {
	if r.Backend == nil {
		return matrixcontainment.Observation{}, fmt.Errorf("Safe isolated backend unavailable")
	}
	policyHash, err := safeContainmentPolicySHA256(r.Policy)
	if err != nil || !strings.EqualFold(policyHash, input.InvariantSetSHA256) {
		return matrixcontainment.Observation{}, fmt.Errorf("Safe containment policy identity mismatch")
	}
	if !strings.EqualFold(action.SHA256(), input.ActionSHA256) {
		return matrixcontainment.Observation{}, fmt.Errorf("Safe action identity mismatch")
	}

	tx, err := decodeCanonicalSafeAction(action)
	if err != nil {
		return matrixcontainment.Observation{}, err
	}
	if tx.ChainID != input.ChainID || !strings.EqualFold(normalizeAddress(tx.To), normalizeAddress(input.Target)) {
		return matrixcontainment.Observation{}, fmt.Errorf("Safe action/input identity mismatch")
	}
	if normalizeAddress(tx.Safe) != normalizeAddress(r.Policy.Safe) {
		return matrixcontainment.Observation{}, fmt.Errorf("Safe policy address mismatch")
	}

	evidence, err := r.Backend.ExecuteSafe(ctx, input, tx)
	if err != nil {
		return matrixcontainment.Observation{}, err
	}
	if err := validateSafeExecutionEvidence(evidence); err != nil {
		return matrixcontainment.Observation{}, err
	}

	authorityPreserved := r.Policy.AllowAuthority || equalSafeAuthority(evidence.Before, evidence.After)
	codePreserved := strings.EqualFold(normalizeHexOrAddress(evidence.Before.Implementation), normalizeHexOrAddress(evidence.After.Implementation)) &&
		strings.EqualFold(strings.TrimSpace(evidence.Before.CodeHash), strings.TrimSpace(evidence.After.CodeHash))
	assetBoundsPreserved := (SafeOutflowBudgetVerifier{}).Verify(r.Policy, evidence.AssetMovements)
	traceObserved := (SafeTraceVerifier{}).Verify(evidence.Trace) && normalizeAddress(evidence.Trace.RootSafe) == normalizeAddress(tx.Safe)

	return matrixcontainment.Observation{
		BackendAvailable:           true,
		ObservedChainID:            evidence.ChainID,
		ObservedBlockNumber:        evidence.BlockNumber,
		ObservedBlockHash:          strings.TrimPrefix(strings.TrimSpace(evidence.BlockHash), "0x"),
		ObservedRunnerSHA256:       strings.TrimPrefix(strings.TrimSpace(evidence.RunnerSHA256), "0x"),
		PreStateSHA256:             strings.TrimPrefix(strings.TrimSpace(evidence.PreStateSHA256), "0x"),
		PostStateSHA256:            strings.TrimPrefix(strings.TrimSpace(evidence.PostStateSHA256), "0x"),
		EffectSetSHA256:            strings.TrimPrefix(strings.TrimSpace(evidence.EffectSetSHA256), "0x"),
		AuthorityPreserved:         authorityPreserved,
		AssetBoundsPreserved:       assetBoundsPreserved,
		CodeIntegrityPreserved:     codePreserved,
		ExecutionPathFullyObserved: traceObserved,
		InvariantsPass:             authorityPreserved && assetBoundsPreserved && codePreserved && traceObserved,
	}, nil
}

func safeContainmentPolicySHA256(policy SafeContainmentPolicy) (string, error) {
	if policy.Version == "" {
		policy.Version = SafeContainmentPolicyVersion
	}
	if policy.Version != SafeContainmentPolicyVersion || !validAddress(policy.Safe) {
		return "", fmt.Errorf("invalid Safe containment policy")
	}

	policy.Safe = normalizeAddress(policy.Safe)
	bounds := append([]SafeOutflowBound(nil), policy.AllowedOutflow...)
	for i := range bounds {
		bounds[i].Kind = strings.ToLower(strings.TrimSpace(bounds[i].Kind))
		bounds[i].Token = normalizeOptionalAddress(bounds[i].Token)
		bounds[i].To = normalizeAddress(bounds[i].To)
		if !validOutflowBound(bounds[i]) {
			return "", fmt.Errorf("invalid Safe outflow bound")
		}
	}
	sort.Slice(bounds, func(i, j int) bool {
		bi, _ := json.Marshal(bounds[i])
		bj, _ := json.Marshal(bounds[j])
		return string(bi) < string(bj)
	})
	policy.AllowedOutflow = bounds

	encoded, err := json.Marshal(policy)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func validateSafeExecutionEvidence(e SafeExecutionEvidence) error {
	if e.ChainID == 0 || e.BlockNumber == 0 ||
		!validHex32(e.BlockHash) || !validSHA256Text(e.RunnerSHA256) ||
		!validSHA256Text(e.PreStateSHA256) || !validSHA256Text(e.PostStateSHA256) || !validSHA256Text(e.EffectSetSHA256) {
		return fmt.Errorf("invalid Safe execution evidence identity")
	}
	if !validAuthoritySnapshot(e.Before) || !validAuthoritySnapshot(e.After) {
		return fmt.Errorf("invalid Safe authority snapshot")
	}
	for _, movement := range e.AssetMovements {
		if !validAssetMovement(movement) {
			return fmt.Errorf("invalid Safe asset movement")
		}
	}
	if !(SafeTraceVerifier{}).Verify(e.Trace) {
		return fmt.Errorf("invalid or incomplete Safe execution trace")
	}
	return nil
}

func validAuthoritySnapshot(s SafeAuthoritySnapshot) bool {
	if s.Threshold == 0 || len(s.Owners) == 0 || s.Threshold > uint64(len(s.Owners)) {
		return false
	}
	for _, owner := range s.Owners {
		if !validAddress(owner) {
			return false
		}
	}
	for _, module := range s.Modules {
		if !validAddress(module) {
			return false
		}
	}
	return validAddress(s.Guard) && validAddress(s.FallbackHandler) && validAddress(s.Implementation) && validHex32(s.CodeHash)
}

func equalSafeAuthority(a, b SafeAuthoritySnapshot) bool {
	return a.Threshold == b.Threshold &&
		equalAddressSets(a.Owners, b.Owners) &&
		equalAddressSets(a.Modules, b.Modules) &&
		strings.EqualFold(normalizeAddress(a.Guard), normalizeAddress(b.Guard)) &&
		strings.EqualFold(normalizeAddress(a.FallbackHandler), normalizeAddress(b.FallbackHandler))
}

func equalAddressSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ca := append([]string(nil), a...)
	cb := append([]string(nil), b...)
	for i := range ca {
		ca[i] = normalizeAddress(ca[i])
	}
	for i := range cb {
		cb[i] = normalizeAddress(cb[i])
	}
	sort.Strings(ca)
	sort.Strings(cb)
	for i := range ca {
		if ca[i] != cb[i] {
			return false
		}
	}
	return true
}

func safeOutflowsWithinPolicy(policy SafeContainmentPolicy, movements []SafeAssetMovement) bool {
	return (SafeOutflowBudgetVerifier{}).Verify(policy, movements)
}

func validOutflowBound(b SafeOutflowBound) bool {
	if strings.TrimSpace(b.Kind) == "" || !validAddress(b.To) {
		return false
	}
	if b.Token != "" && !validAddress(b.Token) {
		return false
	}
	amount, ok := new(big.Int).SetString(b.MaxAmount, 10)
	return ok && amount.Sign() >= 0
}

func validAssetMovement(m SafeAssetMovement) bool {
	if strings.TrimSpace(m.Kind) == "" || !validAddress(m.From) || !validAddress(m.To) {
		return false
	}
	if strings.TrimSpace(m.Token) != "" && !validAddress(m.Token) {
		return false
	}
	amount, ok := new(big.Int).SetString(m.Amount, 10)
	return ok && amount.Sign() >= 0
}

func validSHA256Text(value string) bool {
	value = strings.TrimPrefix(strings.TrimSpace(value), "0x")
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func normalizeOptionalAddress(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return normalizeAddress(value)
}

func normalizeHexOrAddress(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
