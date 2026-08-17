package executionproof

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// InvariantPolicyRegistry is deliberately local-authority-first. The fork
// request contains only a policy digest; executable parameters are resolved
// from a locally approved registry and can never be expanded by caller input.
type InvariantPolicyRegistry interface {
	ResolveProxyCodehash(parametersSHA256 string) (ProxyCodehashPolicy, bool)
	ResolvePrivilegedRole(parametersSHA256 string) (PrivilegedRolePolicy, bool)
	ResolveTreasuryBound(parametersSHA256 string) (TreasuryBoundPolicy, bool)
	ResolveBridgeReserve(parametersSHA256 string) (BridgeReservePolicy, bool)
}

type ProxyCodehashPolicy struct {
	Address            string `json:"address"`
	ExpectedCodeSHA256 string `json:"expected_code_sha256"`
}

type PrivilegedRolePolicy struct {
	Contract      string `json:"contract"`
	StorageSlot   string `json:"storage_slot"`
	ExpectedValue string `json:"expected_value"`
}

type TreasuryBoundPolicy struct {
	Target      string `json:"target"`
	MaxValueWei string `json:"max_value_wei"`
}

type BridgeReadProbe struct {
	Contract string `json:"contract"`
	DataHex  string `json:"data"`
}

type BridgeReservePolicy struct {
	ReserveProbe BridgeReadProbe `json:"reserve_probe"`
	SupplyProbe  BridgeReadProbe `json:"supply_probe"`
}

type StaticInvariantPolicyRegistry struct {
	ProxyCodehash  map[string]ProxyCodehashPolicy
	PrivilegedRole map[string]PrivilegedRolePolicy
	TreasuryBound  map[string]TreasuryBoundPolicy
	BridgeReserve  map[string]BridgeReservePolicy
}

func (r StaticInvariantPolicyRegistry) ResolveProxyCodehash(parametersSHA256 string) (ProxyCodehashPolicy, bool) {
	policy, ok := r.ProxyCodehash[strings.ToLower(strings.TrimSpace(parametersSHA256))]
	if !ok { return ProxyCodehashPolicy{}, false }
	address, validAddress := canonicalEVMAddress(policy.Address)
	if !validAddress || !validSHA256(policy.ExpectedCodeSHA256) { return ProxyCodehashPolicy{}, false }
	policy.Address = address
	policy.ExpectedCodeSHA256 = strings.ToLower(strings.TrimSpace(policy.ExpectedCodeSHA256))
	return policy, true
}

func (r StaticInvariantPolicyRegistry) ResolvePrivilegedRole(parametersSHA256 string) (PrivilegedRolePolicy, bool) {
	policy, ok := r.PrivilegedRole[strings.ToLower(strings.TrimSpace(parametersSHA256))]
	if !ok { return PrivilegedRolePolicy{}, false }
	contract, validContract := canonicalEVMAddress(policy.Contract)
	if !validContract || !validHex32(policy.StorageSlot) || !validHex32(policy.ExpectedValue) { return PrivilegedRolePolicy{}, false }
	policy.Contract = contract
	policy.StorageSlot = normalizeHex32(policy.StorageSlot)
	policy.ExpectedValue = normalizeHex32(policy.ExpectedValue)
	return policy, true
}

func (r StaticInvariantPolicyRegistry) ResolveTreasuryBound(parametersSHA256 string) (TreasuryBoundPolicy, bool) {
	policy, ok := r.TreasuryBound[strings.ToLower(strings.TrimSpace(parametersSHA256))]
	if !ok { return TreasuryBoundPolicy{}, false }
	target, validTarget := canonicalEVMAddress(policy.Target)
	max, ok := parseHexUint256(policy.MaxValueWei)
	if !validTarget || !ok { return TreasuryBoundPolicy{}, false }
	policy.Target = target
	policy.MaxValueWei = "0x" + max.Text(16)
	return policy, true
}

func canonicalBridgeReadProbe(probe BridgeReadProbe) (BridgeReadProbe, bool) {
	contract, okContract := canonicalEVMAddress(probe.Contract)
	data, okData := canonicalHexBytes(probe.DataHex)
	if !okContract || !okData || data == "0x" { return BridgeReadProbe{}, false }
	return BridgeReadProbe{Contract: contract, DataHex: data}, true
}

func (r StaticInvariantPolicyRegistry) ResolveBridgeReserve(parametersSHA256 string) (BridgeReservePolicy, bool) {
	policy, ok := r.BridgeReserve[strings.ToLower(strings.TrimSpace(parametersSHA256))]
	if !ok { return BridgeReservePolicy{}, false }
	reserve, okReserve := canonicalBridgeReadProbe(policy.ReserveProbe)
	supply, okSupply := canonicalBridgeReadProbe(policy.SupplyProbe)
	if !okReserve || !okSupply { return BridgeReservePolicy{}, false }
	policy.ReserveProbe = reserve
	policy.SupplyProbe = supply
	return policy, true
}

func policyDigest(value any) (string, bool) {
	encoded, err := json.Marshal(value)
	if err != nil { return "", false }
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), true
}

func ProxyCodehashPolicyDigest(policy ProxyCodehashPolicy) (string, bool) {
	address, ok := canonicalEVMAddress(policy.Address)
	if !ok || !validSHA256(policy.ExpectedCodeSHA256) { return "", false }
	policy.Address = address
	policy.ExpectedCodeSHA256 = strings.ToLower(strings.TrimSpace(policy.ExpectedCodeSHA256))
	return policyDigest(policy)
}

func PrivilegedRolePolicyDigest(policy PrivilegedRolePolicy) (string, bool) {
	contract, ok := canonicalEVMAddress(policy.Contract)
	if !ok || !validHex32(policy.StorageSlot) || !validHex32(policy.ExpectedValue) { return "", false }
	policy.Contract = contract
	policy.StorageSlot = normalizeHex32(policy.StorageSlot)
	policy.ExpectedValue = normalizeHex32(policy.ExpectedValue)
	return policyDigest(policy)
}

func TreasuryBoundPolicyDigest(policy TreasuryBoundPolicy) (string, bool) {
	target, okTarget := canonicalEVMAddress(policy.Target)
	max, okMax := parseHexUint256(policy.MaxValueWei)
	if !okTarget || !okMax { return "", false }
	policy.Target = target
	policy.MaxValueWei = "0x" + max.Text(16)
	return policyDigest(policy)
}

func BridgeReservePolicyDigest(policy BridgeReservePolicy) (string, bool) {
	reserve, okReserve := canonicalBridgeReadProbe(policy.ReserveProbe)
	supply, okSupply := canonicalBridgeReadProbe(policy.SupplyProbe)
	if !okReserve || !okSupply { return "", false }
	policy.ReserveProbe = reserve
	policy.SupplyProbe = supply
	return policyDigest(policy)
}

// PolicyBoundInvariantEvaluator only implements invariant classes with explicit,
// locally approved semantics. Unsupported classes fail the whole simulation.
type PolicyBoundInvariantEvaluator struct { Registry InvariantPolicyRegistry }

func (e PolicyBoundInvariantEvaluator) EvaluatePostState(ctx context.Context, rpcURL string, request PreparedVerifiedForkRequest, txHash string) ([]InvariantCheck, error) {
	if e.Registry == nil || strings.TrimSpace(rpcURL) == "" || !validHex32(txHash) { return nil, errors.New("invalid invariant evaluator boundary") }
	client := &evmRPCClient{url: rpcURL, http: &http.Client{Timeout: 5 * time.Second}}
	checks := make([]InvariantCheck, 0, len(request.Invariants))
	for _, definition := range request.Invariants {
		var check InvariantCheck
		var err error
		switch definition.Class {
		case InvariantProxyCodehash:
			check, err = e.evaluateProxyCodehash(ctx, client, definition)
		case InvariantPrivilegedRole:
			check, err = e.evaluatePrivilegedRole(ctx, client, definition)
		case InvariantTreasuryBound:
			check, err = e.evaluateTreasuryBound(definition, request.Payload)
		case InvariantBridgeReserve:
			check, err = e.evaluateBridgeReserve(ctx, client, definition)
		default:
			return nil, fmt.Errorf("invariant %s class %s is not implemented by policy-bound evaluator", definition.ID, definition.Class)
		}
		if err != nil { return nil, fmt.Errorf("invariant %s: %w", definition.ID, err) }
		checks = append(checks, check)
	}
	return checks, nil
}

func (e PolicyBoundInvariantEvaluator) evaluateProxyCodehash(ctx context.Context, client *evmRPCClient, definition ApprovedInvariantDefinition) (InvariantCheck, error) {
	policy, ok := e.Registry.ResolveProxyCodehash(definition.ParametersSHA256)
	if !ok { return InvariantCheck{}, errors.New("approved proxy codehash policy not found") }
	var codeHex string
	if err := client.call(ctx, "eth_getCode", []any{policy.Address, "latest"}, &codeHex); err != nil { return InvariantCheck{}, err }
	code, err := decodeCanonicalHexBytes(codeHex)
	if err != nil { return InvariantCheck{}, errors.New("invalid eth_getCode result") }
	observed := sha256Hex(code)
	return InvariantCheck{ID: definition.ID, Class: InvariantProxyCodehash, Passed: equalDigest(observed, policy.ExpectedCodeSHA256), Evidence: proxyCodehashEvidenceDigest(policy.Address, observed)}, nil
}

func (e PolicyBoundInvariantEvaluator) evaluatePrivilegedRole(ctx context.Context, client *evmRPCClient, definition ApprovedInvariantDefinition) (InvariantCheck, error) {
	policy, ok := e.Registry.ResolvePrivilegedRole(definition.ParametersSHA256)
	if !ok { return InvariantCheck{}, errors.New("approved privileged-role policy not found") }
	var observed string
	if err := client.call(ctx, "eth_getStorageAt", []any{policy.Contract, policy.StorageSlot, "latest"}, &observed); err != nil { return InvariantCheck{}, err }
	if !validHex32(observed) { return InvariantCheck{}, errors.New("invalid eth_getStorageAt result") }
	observed = normalizeHex32(observed)
	evidence := struct { Contract string `json:"contract"`; StorageSlot string `json:"storage_slot"`; ObservedValue string `json:"observed_value"` }{policy.Contract, policy.StorageSlot, observed}
	digest, _ := policyDigest(evidence)
	return InvariantCheck{ID: definition.ID, Class: InvariantPrivilegedRole, Passed: equalHex32(observed, policy.ExpectedValue), Evidence: digest}, nil
}

func (e PolicyBoundInvariantEvaluator) evaluateTreasuryBound(definition ApprovedInvariantDefinition, payload EVMPayload) (InvariantCheck, error) {
	policy, ok := e.Registry.ResolveTreasuryBound(definition.ParametersSHA256)
	if !ok { return InvariantCheck{}, errors.New("approved treasury-bound policy not found") }
	canonical, ok := canonicalEVMPayload(payload)
	if !ok || !equalAddress(canonical.To, policy.Target) { return InvariantCheck{}, errors.New("treasury target mismatch") }
	value, okValue := parseHexUint256(canonical.ValueHex)
	max, okMax := parseHexUint256(policy.MaxValueWei)
	if !okValue || !okMax { return InvariantCheck{}, errors.New("invalid treasury value policy") }
	evidence := struct { Target string `json:"target"`; ValueWei string `json:"value_wei"`; MaxValueWei string `json:"max_value_wei"` }{canonical.To, "0x"+value.Text(16), "0x"+max.Text(16)}
	digest, _ := policyDigest(evidence)
	return InvariantCheck{ID: definition.ID, Class: InvariantTreasuryBound, Passed: value.Cmp(max) <= 0, Evidence: digest}, nil
}

func (e PolicyBoundInvariantEvaluator) evaluateBridgeReserve(ctx context.Context, client *evmRPCClient, definition ApprovedInvariantDefinition) (InvariantCheck, error) {
	policy, ok := e.Registry.ResolveBridgeReserve(definition.ParametersSHA256)
	if !ok { return InvariantCheck{}, errors.New("approved bridge reserve policy not found") }
	reserve, err := callUint256(ctx, client, policy.ReserveProbe)
	if err != nil { return InvariantCheck{}, fmt.Errorf("reserve probe: %w", err) }
	supply, err := callUint256(ctx, client, policy.SupplyProbe)
	if err != nil { return InvariantCheck{}, fmt.Errorf("supply probe: %w", err) }
	evidence := struct { Reserve string `json:"reserve"`; Supply string `json:"supply"` }{"0x"+reserve.Text(16), "0x"+supply.Text(16)}
	digest, _ := policyDigest(evidence)
	return InvariantCheck{ID: definition.ID, Class: InvariantBridgeReserve, Passed: reserve.Cmp(supply) >= 0, Evidence: digest}, nil
}

func callUint256(ctx context.Context, client *evmRPCClient, probe BridgeReadProbe) (*big.Int, error) {
	var result string
	call := map[string]any{"to": probe.Contract, "data": probe.DataHex}
	if err := client.call(ctx, "eth_call", []any{call, "latest"}, &result); err != nil { return nil, err }
	value, ok := parseHexUint256(result)
	if !ok { return nil, errors.New("invalid uint256 eth_call result") }
	return value, nil
}

func proxyCodehashEvidenceDigest(address, observedCodeSHA256 string) string {
	evidence := struct { Address string `json:"address"`; ObservedCodeSHA256 string `json:"observed_code_sha256"` }{Address: address, ObservedCodeSHA256: strings.ToLower(observedCodeSHA256)}
	digest, _ := policyDigest(evidence)
	return digest
}
