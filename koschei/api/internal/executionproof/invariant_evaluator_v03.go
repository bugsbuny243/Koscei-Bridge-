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

type InvariantPolicyRegistry interface {
	ResolveProxyCodehash(string) (ProxyCodehashPolicy, bool)
	ResolvePrivilegedRole(string) (PrivilegedRolePolicy, bool)
	ResolveTreasuryBound(string) (TreasuryBoundPolicy, bool)
	ResolveBridgeReserve(string) (BridgeReservePolicy, bool)
	ResolveAssetConservation(string) (AssetConservationPolicy, bool)
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

// AssetConservationPolicy proves that a locally approved set of accounting
// buckets exactly covers the asset's reported supply after execution. It is
// intentionally explicit: an incomplete bucket set must not be treated as a
// conservation proof.
type AssetConservationPolicy struct {
	SupplyProbe     BridgeReadProbe   `json:"supply_probe"`
	AccountedProbes []BridgeReadProbe `json:"accounted_probes"`
}

type StaticInvariantPolicyRegistry struct {
	ProxyCodehash     map[string]ProxyCodehashPolicy
	PrivilegedRole    map[string]PrivilegedRolePolicy
	TreasuryBound     map[string]TreasuryBoundPolicy
	BridgeReserve     map[string]BridgeReservePolicy
	AssetConservation map[string]AssetConservationPolicy
}

func (r StaticInvariantPolicyRegistry) ResolveProxyCodehash(d string) (ProxyCodehashPolicy, bool) {
	p, ok := r.ProxyCodehash[strings.ToLower(strings.TrimSpace(d))]
	if !ok {
		return ProxyCodehashPolicy{}, false
	}
	a, v := canonicalEVMAddress(p.Address)
	if !v || !validSHA256(p.ExpectedCodeSHA256) {
		return ProxyCodehashPolicy{}, false
	}
	p.Address = a
	p.ExpectedCodeSHA256 = strings.ToLower(strings.TrimSpace(p.ExpectedCodeSHA256))
	return p, true
}
func (r StaticInvariantPolicyRegistry) ResolvePrivilegedRole(d string) (PrivilegedRolePolicy, bool) {
	p, ok := r.PrivilegedRole[strings.ToLower(strings.TrimSpace(d))]
	if !ok {
		return PrivilegedRolePolicy{}, false
	}
	a, v := canonicalEVMAddress(p.Contract)
	if !v || !validHex32(p.StorageSlot) || !validHex32(p.ExpectedValue) {
		return PrivilegedRolePolicy{}, false
	}
	p.Contract = a
	p.StorageSlot = normalizeHex32(p.StorageSlot)
	p.ExpectedValue = normalizeHex32(p.ExpectedValue)
	return p, true
}
func (r StaticInvariantPolicyRegistry) ResolveTreasuryBound(d string) (TreasuryBoundPolicy, bool) {
	p, ok := r.TreasuryBound[strings.ToLower(strings.TrimSpace(d))]
	if !ok {
		return TreasuryBoundPolicy{}, false
	}
	a, v := canonicalEVMAddress(p.Target)
	m, mok := parseHexUint256(p.MaxValueWei)
	if !v || !mok {
		return TreasuryBoundPolicy{}, false
	}
	p.Target = a
	p.MaxValueWei = "0x" + m.Text(16)
	return p, true
}
func canonicalBridgeReadProbe(p BridgeReadProbe) (BridgeReadProbe, bool) {
	a, aok := canonicalEVMAddress(p.Contract)
	d, dok := canonicalHexBytes(p.DataHex)
	if !aok || !dok || d == "0x" {
		return BridgeReadProbe{}, false
	}
	return BridgeReadProbe{Contract: a, DataHex: d}, true
}
func (r StaticInvariantPolicyRegistry) ResolveBridgeReserve(d string) (BridgeReservePolicy, bool) {
	p, ok := r.BridgeReserve[strings.ToLower(strings.TrimSpace(d))]
	if !ok {
		return BridgeReservePolicy{}, false
	}
	a, aok := canonicalBridgeReadProbe(p.ReserveProbe)
	b, bok := canonicalBridgeReadProbe(p.SupplyProbe)
	if !aok || !bok {
		return BridgeReservePolicy{}, false
	}
	p.ReserveProbe = a
	p.SupplyProbe = b
	return p, true
}
func (r StaticInvariantPolicyRegistry) ResolveAssetConservation(d string) (AssetConservationPolicy, bool) {
	p, ok := r.AssetConservation[strings.ToLower(strings.TrimSpace(d))]
	if !ok || len(p.AccountedProbes) == 0 {
		return AssetConservationPolicy{}, false
	}
	s, sok := canonicalBridgeReadProbe(p.SupplyProbe)
	if !sok {
		return AssetConservationPolicy{}, false
	}
	out := make([]BridgeReadProbe, len(p.AccountedProbes))
	for i, probe := range p.AccountedProbes {
		c, cok := canonicalBridgeReadProbe(probe)
		if !cok {
			return AssetConservationPolicy{}, false
		}
		out[i] = c
	}
	p.SupplyProbe = s
	p.AccountedProbes = out
	return p, true
}

func policyDigest(v any) (string, bool) {
	b, e := json.Marshal(v)
	if e != nil {
		return "", false
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), true
}
func ProxyCodehashPolicyDigest(p ProxyCodehashPolicy) (string, bool) {
	a, ok := canonicalEVMAddress(p.Address)
	if !ok || !validSHA256(p.ExpectedCodeSHA256) {
		return "", false
	}
	p.Address = a
	p.ExpectedCodeSHA256 = strings.ToLower(strings.TrimSpace(p.ExpectedCodeSHA256))
	return policyDigest(p)
}
func PrivilegedRolePolicyDigest(p PrivilegedRolePolicy) (string, bool) {
	a, ok := canonicalEVMAddress(p.Contract)
	if !ok || !validHex32(p.StorageSlot) || !validHex32(p.ExpectedValue) {
		return "", false
	}
	p.Contract = a
	p.StorageSlot = normalizeHex32(p.StorageSlot)
	p.ExpectedValue = normalizeHex32(p.ExpectedValue)
	return policyDigest(p)
}
func TreasuryBoundPolicyDigest(p TreasuryBoundPolicy) (string, bool) {
	a, aok := canonicalEVMAddress(p.Target)
	m, mok := parseHexUint256(p.MaxValueWei)
	if !aok || !mok {
		return "", false
	}
	p.Target = a
	p.MaxValueWei = "0x" + m.Text(16)
	return policyDigest(p)
}
func BridgeReservePolicyDigest(p BridgeReservePolicy) (string, bool) {
	a, aok := canonicalBridgeReadProbe(p.ReserveProbe)
	b, bok := canonicalBridgeReadProbe(p.SupplyProbe)
	if !aok || !bok {
		return "", false
	}
	p.ReserveProbe = a
	p.SupplyProbe = b
	return policyDigest(p)
}
func AssetConservationPolicyDigest(p AssetConservationPolicy) (string, bool) {
	if len(p.AccountedProbes) == 0 {
		return "", false
	}
	s, ok := canonicalBridgeReadProbe(p.SupplyProbe)
	if !ok {
		return "", false
	}
	out := make([]BridgeReadProbe, len(p.AccountedProbes))
	for i, x := range p.AccountedProbes {
		c, cok := canonicalBridgeReadProbe(x)
		if !cok {
			return "", false
		}
		out[i] = c
	}
	p.SupplyProbe = s
	p.AccountedProbes = out
	return policyDigest(p)
}

type PolicyBoundInvariantEvaluator struct{ Registry InvariantPolicyRegistry }

func (e PolicyBoundInvariantEvaluator) EvaluatePostState(ctx context.Context, rpcURL string, request PreparedVerifiedForkRequest, txHash string) ([]InvariantCheck, error) {
	if e.Registry == nil || strings.TrimSpace(rpcURL) == "" || !validHex32(txHash) {
		return nil, errors.New("invalid invariant evaluator boundary")
	}
	c := &evmRPCClient{url: rpcURL, http: &http.Client{Timeout: 5 * time.Second}}
	checks := make([]InvariantCheck, 0, len(request.Invariants))
	for _, d := range request.Invariants {
		var ch InvariantCheck
		var err error
		switch d.Class {
		case InvariantProxyCodehash:
			ch, err = e.evaluateProxyCodehash(ctx, c, d)
		case InvariantPrivilegedRole:
			ch, err = e.evaluatePrivilegedRole(ctx, c, d)
		case InvariantTreasuryBound:
			ch, err = e.evaluateTreasuryBound(d, request.Payload)
		case InvariantBridgeReserve:
			ch, err = e.evaluateBridgeReserve(ctx, c, d)
		case InvariantAssetConservation:
			ch, err = e.evaluateAssetConservation(ctx, c, d)
		default:
			return nil, fmt.Errorf("invariant %s class %s is not implemented by policy-bound evaluator", d.ID, d.Class)
		}
		if err != nil {
			return nil, fmt.Errorf("invariant %s: %w", d.ID, err)
		}
		checks = append(checks, ch)
	}
	return checks, nil
}
func (e PolicyBoundInvariantEvaluator) evaluateProxyCodehash(ctx context.Context, c *evmRPCClient, d ApprovedInvariantDefinition) (InvariantCheck, error) {
	p, ok := e.Registry.ResolveProxyCodehash(d.ParametersSHA256)
	if !ok {
		return InvariantCheck{}, errors.New("approved proxy codehash policy not found")
	}
	var h string
	if err := c.call(ctx, "eth_getCode", []any{p.Address, "latest"}, &h); err != nil {
		return InvariantCheck{}, err
	}
	b, err := decodeCanonicalHexBytes(h)
	if err != nil {
		return InvariantCheck{}, errors.New("invalid eth_getCode result")
	}
	o := sha256Hex(b)
	return InvariantCheck{ID: d.ID, Class: InvariantProxyCodehash, Passed: equalDigest(o, p.ExpectedCodeSHA256), Evidence: proxyCodehashEvidenceDigest(p.Address, o)}, nil
}
func (e PolicyBoundInvariantEvaluator) evaluatePrivilegedRole(ctx context.Context, c *evmRPCClient, d ApprovedInvariantDefinition) (InvariantCheck, error) {
	p, ok := e.Registry.ResolvePrivilegedRole(d.ParametersSHA256)
	if !ok {
		return InvariantCheck{}, errors.New("approved privileged-role policy not found")
	}
	var o string
	if err := c.call(ctx, "eth_getStorageAt", []any{p.Contract, p.StorageSlot, "latest"}, &o); err != nil {
		return InvariantCheck{}, err
	}
	if !validHex32(o) {
		return InvariantCheck{}, errors.New("invalid eth_getStorageAt result")
	}
	o = normalizeHex32(o)
	ev := struct {
		Contract      string `json:"contract"`
		StorageSlot   string `json:"storage_slot"`
		ObservedValue string `json:"observed_value"`
	}{p.Contract, p.StorageSlot, o}
	h, _ := policyDigest(ev)
	return InvariantCheck{ID: d.ID, Class: InvariantPrivilegedRole, Passed: equalHex32(o, p.ExpectedValue), Evidence: h}, nil
}
func (e PolicyBoundInvariantEvaluator) evaluateTreasuryBound(d ApprovedInvariantDefinition, payload EVMPayload) (InvariantCheck, error) {
	p, ok := e.Registry.ResolveTreasuryBound(d.ParametersSHA256)
	if !ok {
		return InvariantCheck{}, errors.New("approved treasury-bound policy not found")
	}
	x, ok := canonicalEVMPayload(payload)
	if !ok || !equalAddress(x.To, p.Target) {
		return InvariantCheck{}, errors.New("treasury target mismatch")
	}
	v, vok := parseHexUint256(x.ValueHex)
	m, mok := parseHexUint256(p.MaxValueWei)
	if !vok || !mok {
		return InvariantCheck{}, errors.New("invalid treasury value policy")
	}
	ev := struct {
		Target      string `json:"target"`
		ValueWei    string `json:"value_wei"`
		MaxValueWei string `json:"max_value_wei"`
	}{x.To, "0x" + v.Text(16), "0x" + m.Text(16)}
	h, _ := policyDigest(ev)
	return InvariantCheck{ID: d.ID, Class: InvariantTreasuryBound, Passed: v.Cmp(m) <= 0, Evidence: h}, nil
}
func (e PolicyBoundInvariantEvaluator) evaluateBridgeReserve(ctx context.Context, c *evmRPCClient, d ApprovedInvariantDefinition) (InvariantCheck, error) {
	p, ok := e.Registry.ResolveBridgeReserve(d.ParametersSHA256)
	if !ok {
		return InvariantCheck{}, errors.New("approved bridge reserve policy not found")
	}
	r, err := callUint256(ctx, c, p.ReserveProbe)
	if err != nil {
		return InvariantCheck{}, fmt.Errorf("reserve probe: %w", err)
	}
	s, err := callUint256(ctx, c, p.SupplyProbe)
	if err != nil {
		return InvariantCheck{}, fmt.Errorf("supply probe: %w", err)
	}
	ev := struct {
		Reserve string `json:"reserve"`
		Supply  string `json:"supply"`
	}{"0x" + r.Text(16), "0x" + s.Text(16)}
	h, _ := policyDigest(ev)
	return InvariantCheck{ID: d.ID, Class: InvariantBridgeReserve, Passed: r.Cmp(s) >= 0, Evidence: h}, nil
}
func (e PolicyBoundInvariantEvaluator) evaluateAssetConservation(ctx context.Context, c *evmRPCClient, d ApprovedInvariantDefinition) (InvariantCheck, error) {
	p, ok := e.Registry.ResolveAssetConservation(d.ParametersSHA256)
	if !ok {
		return InvariantCheck{}, errors.New("approved asset-conservation policy not found")
	}
	supply, err := callUint256(ctx, c, p.SupplyProbe)
	if err != nil {
		return InvariantCheck{}, fmt.Errorf("supply probe: %w", err)
	}
	sum := new(big.Int)
	observed := make([]string, 0, len(p.AccountedProbes))
	for i, probe := range p.AccountedProbes {
		v, e := callUint256(ctx, c, probe)
		if e != nil {
			return InvariantCheck{}, fmt.Errorf("accounted probe %d: %w", i, e)
		}
		sum.Add(sum, v)
		observed = append(observed, "0x"+v.Text(16))
	}
	ev := struct {
		Supply       string   `json:"supply"`
		Accounted    []string `json:"accounted"`
		AccountedSum string   `json:"accounted_sum"`
	}{"0x" + supply.Text(16), observed, "0x" + sum.Text(16)}
	h, _ := policyDigest(ev)
	return InvariantCheck{ID: d.ID, Class: InvariantAssetConservation, Passed: sum.Cmp(supply) == 0, Evidence: h}, nil
}
func callUint256(ctx context.Context, c *evmRPCClient, p BridgeReadProbe) (*big.Int, error) {
	var r string
	if err := c.call(ctx, "eth_call", []any{map[string]any{"to": p.Contract, "data": p.DataHex}, "latest"}, &r); err != nil {
		return nil, err
	}
	v, ok := parseHexUint256(r)
	if !ok {
		return nil, errors.New("invalid uint256 eth_call result")
	}
	return v, nil
}
func proxyCodehashEvidenceDigest(a, o string) string {
	ev := struct {
		Address            string `json:"address"`
		ObservedCodeSHA256 string `json:"observed_code_sha256"`
	}{a, strings.ToLower(o)}
	h, _ := policyDigest(ev)
	return h
}
