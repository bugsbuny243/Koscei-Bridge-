package executionproof

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// InvariantPolicyRegistry is deliberately local-authority-first. The fork
// request contains only a policy digest; executable parameters are resolved
// from a locally approved registry and can never be expanded by caller input.
type InvariantPolicyRegistry interface {
	ResolveProxyCodehash(parametersSHA256 string) (ProxyCodehashPolicy, bool)
}

type ProxyCodehashPolicy struct {
	Address            string `json:"address"`
	ExpectedCodeSHA256 string `json:"expected_code_sha256"`
}

type StaticInvariantPolicyRegistry struct {
	ProxyCodehash map[string]ProxyCodehashPolicy
}

func (r StaticInvariantPolicyRegistry) ResolveProxyCodehash(parametersSHA256 string) (ProxyCodehashPolicy, bool) {
	policy, ok := r.ProxyCodehash[strings.ToLower(strings.TrimSpace(parametersSHA256))]
	if !ok {
		return ProxyCodehashPolicy{}, false
	}
	address, validAddress := canonicalEVMAddress(policy.Address)
	if !validAddress || !validSHA256(policy.ExpectedCodeSHA256) {
		return ProxyCodehashPolicy{}, false
	}
	policy.Address = address
	policy.ExpectedCodeSHA256 = strings.ToLower(policy.ExpectedCodeSHA256)
	return policy, true
}

func ProxyCodehashPolicyDigest(policy ProxyCodehashPolicy) (string, bool) {
	address, ok := canonicalEVMAddress(policy.Address)
	if !ok || !validSHA256(policy.ExpectedCodeSHA256) {
		return "", false
	}
	policy.Address = address
	policy.ExpectedCodeSHA256 = strings.ToLower(strings.TrimSpace(policy.ExpectedCodeSHA256))
	encoded, err := json.Marshal(policy)
	if err != nil {
		return "", false
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), true
}

// PolicyBoundInvariantEvaluator is the first concrete v0.3 evaluator. It only
// implements invariant classes with explicit, locally approved semantics.
// Unsupported classes fail the whole simulation rather than returning an
// unverifiable PASS.
type PolicyBoundInvariantEvaluator struct {
	Registry InvariantPolicyRegistry
}

func (e PolicyBoundInvariantEvaluator) EvaluatePostState(ctx context.Context, rpcURL string, request PreparedVerifiedForkRequest, txHash string) ([]InvariantCheck, error) {
	if e.Registry == nil || strings.TrimSpace(rpcURL) == "" || !validHex32(txHash) {
		return nil, errors.New("invalid invariant evaluator boundary")
	}
	client := &evmRPCClient{url: rpcURL, http: defaultInvariantHTTPClient()}
	checks := make([]InvariantCheck, 0, len(request.Invariants))
	for _, definition := range request.Invariants {
		switch definition.Class {
		case InvariantProxyCodehash:
			check, err := e.evaluateProxyCodehash(ctx, client, definition)
			if err != nil {
				return nil, fmt.Errorf("invariant %s: %w", definition.ID, err)
			}
			checks = append(checks, check)
		default:
			return nil, fmt.Errorf("invariant %s class %s is not implemented by policy-bound evaluator", definition.ID, definition.Class)
		}
	}
	return checks, nil
}

func (e PolicyBoundInvariantEvaluator) evaluateProxyCodehash(ctx context.Context, client *evmRPCClient, definition ApprovedInvariantDefinition) (InvariantCheck, error) {
	policy, ok := e.Registry.ResolveProxyCodehash(definition.ParametersSHA256)
	if !ok {
		return InvariantCheck{}, errors.New("approved proxy codehash policy not found")
	}
	var codeHex string
	if err := client.call(ctx, "eth_getCode", []any{policy.Address, "latest"}, &codeHex); err != nil {
		return InvariantCheck{}, err
	}
	code, err := decodeCanonicalHexBytes(codeHex)
	if err != nil {
		return InvariantCheck{}, errors.New("invalid eth_getCode result")
	}
	observed := sha256Hex(code)
	evidence := proxyCodehashEvidenceDigest(policy.Address, observed)
	return InvariantCheck{
		ID:       definition.ID,
		Class:    InvariantProxyCodehash,
		Passed:   equalDigest(observed, policy.ExpectedCodeSHA256),
		Evidence: evidence,
	}, nil
}

func proxyCodehashEvidenceDigest(address, observedCodeSHA256 string) string {
	evidence := struct {
		Address            string `json:"address"`
		ObservedCodeSHA256 string `json:"observed_code_sha256"`
	}{Address: address, ObservedCodeSHA256: strings.ToLower(observedCodeSHA256)}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		panic("proxy codehash evidence must remain JSON serializable")
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
