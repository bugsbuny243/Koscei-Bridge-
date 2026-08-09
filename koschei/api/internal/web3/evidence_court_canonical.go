package web3

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// EvidenceCourtCanonicalizer converts a provider result into the exact value
// identity that a higher-level evidence contract wants to corroborate. It must
// be deterministic and must not depend on provider identity.
type EvidenceCourtCanonicalizer func(json.RawMessage) (valueHash string, contextSlot uint64, nullValue bool, err error)

// EvidenceCourtWithCanonicalizer performs the same bounded independent-provider
// collection as EvidenceCourt, but lets the caller define the canonical value
// being compared. This is used by state-bound Transaction Guard rechecks so the
// quorum compares State Witness account roots rather than generic RPC JSON.
func (s *SolanaRPC) EvidenceCourtWithCanonicalizer(ctx context.Context, network, method string, params any, canonicalize EvidenceCourtCanonicalizer) EvidenceCourtResult {
	return s.evidenceCourtWithCanonicalizerPolicy(ctx, network, method, params, "", 0, false, canonicalize)
}

// EvidenceCourtWithCanonicalizerExcluding additionally removes the provider
// identity used by excludedURL from the witness pool. The exclusion is by
// recognized provider identity, not only by exact hostname, so two endpoints
// from the same provider cannot make a primary observation look independent.
func (s *SolanaRPC) EvidenceCourtWithCanonicalizerExcluding(ctx context.Context, network, method string, params any, excludedURL string, canonicalize EvidenceCourtCanonicalizer) EvidenceCourtResult {
	return s.evidenceCourtWithCanonicalizerPolicy(ctx, network, method, params, excludedURL, 0, false, canonicalize)
}

// EvidenceCourtWithCanonicalizerExcludingRequired is reserved for a caller that
// already authenticated a signed policy requiring corroboration. It can force
// bounded collection even when the deployment-wide Evidence Court flag is off.
// It does not bypass method allowlists, provider independence, timeouts, or the
// configured provider cap.
func (s *SolanaRPC) EvidenceCourtWithCanonicalizerExcludingRequired(ctx context.Context, network, method string, params any, excludedURL string, required int, canonicalize EvidenceCourtCanonicalizer) EvidenceCourtResult {
	return s.evidenceCourtWithCanonicalizerPolicy(ctx, network, method, params, excludedURL, required, true, canonicalize)
}

func (s *SolanaRPC) evidenceCourtWithCanonicalizerPolicy(ctx context.Context, network, method string, params any, excludedURL string, required int, force bool, canonicalize EvidenceCourtCanonicalizer) EvidenceCourtResult {
	if required <= 0 {
		required = evidenceCourtRequiredWitnesses()
	}
	if required < 2 {
		required = 2
	}
	if required > evidenceCourtMaxProviders {
		required = evidenceCourtMaxProviders
	}
	enabled := EvidenceCourtEnabled() || force
	result := EvidenceCourtResult{
		SchemaVersion: evidenceCourtSchemaVersion,
		Enabled:       enabled,
		Method:        strings.TrimSpace(method),
		Status:        "disabled",
		Required:      required,
		Witnesses:     []EvidenceCourtWitness{},
		Limitations:   []string{},
	}
	if !result.Enabled {
		result.Limitations = append(result.Limitations, "Multi-provider evidence collection is disabled by configuration.")
		return result
	}
	if canonicalize == nil {
		result.Status = "insufficient"
		result.Limitations = append(result.Limitations, "Evidence Court canonicalizer is unavailable.")
		return result
	}
	if !evidenceCourtAllowedMethod(method) {
		result.Status = "unsupported_method"
		result.Limitations = append(result.Limitations, "Evidence Court permits only bounded account-state and token-supply RPC methods.")
		return result
	}
	if s == nil {
		result.Status = "insufficient"
		result.Limitations = append(result.Limitations, "Solana RPC client is unavailable.")
		return result
	}

	endpoints := evidenceCourtEndpointsExcluding(s.evidenceCourtEndpoints(network), excludedURL)
	result.Requested = len(endpoints)
	if len(endpoints) < required {
		result.Status = "insufficient"
		limitation := "Fewer independent providers are configured than the required witness quorum."
		if strings.TrimSpace(excludedURL) != "" {
			limitation = "Fewer independent providers are configured than the required witness quorum after excluding the primary RPC provider."
		}
		result.Limitations = append(result.Limitations, limitation)
		for _, endpoint := range endpoints {
			result.Witnesses = append(result.Witnesses, EvidenceCourtWitness{Provider: endpoint.Provider, Host: endpoint.Host, Status: "not_queried"})
		}
		return result
	}

	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		result.Status = "insufficient"
		result.Limitations = append(result.Limitations, "RPC request could not be encoded.")
		return result
	}
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}

	responses := make(chan EvidenceCourtSample, len(endpoints))
	for _, endpoint := range endpoints {
		endpoint := endpoint
		go func() {
			attemptCtx := ctx
			cancel := func() {}
			if timeout := solanaRPCEndpointTimeout(); timeout > 0 {
				attemptCtx, cancel = context.WithTimeout(ctx, timeout)
			}
			defer cancel()
			var raw json.RawMessage
			err := callSolanaRPC(attemptCtx, client, endpoint.URL, method, body, &raw)
			responses <- EvidenceCourtSample{Provider: endpoint.Provider, Host: endpoint.Host, Result: raw, Err: err}
		}()
	}

	samples := make([]EvidenceCourtSample, 0, len(endpoints))
	for range endpoints {
		select {
		case sample := <-responses:
			samples = append(samples, sample)
		case <-ctx.Done():
			samples = append(samples, EvidenceCourtSample{Provider: "context", Host: "context", Err: ctx.Err()})
		}
	}
	return EvaluateEvidenceCourtWithCanonicalizer(method, samples, required, canonicalize)
}

func evidenceCourtEndpointsExcluding(endpoints []evidenceCourtEndpoint, excludedURL string) []evidenceCourtEndpoint {
	excludedIdentity := evidenceCourtProviderIdentityForURL(excludedURL)
	out := make([]evidenceCourtEndpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if excludedIdentity != "" && evidenceCourtProviderIdentity(endpoint.Provider, endpoint.Host) == excludedIdentity {
			continue
		}
		out = append(out, endpoint)
	}
	return out
}

func evidenceCourtProviderIdentityForURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	host := RPCProviderHost(raw)
	if host == "unconfigured" || host == "invalid-host" {
		return ""
	}
	return evidenceCourtProviderIdentity(providerLabel(host), host)
}

// EvaluateEvidenceCourtWithCanonicalizer is the deterministic aggregation core
// for custom evidence identities. The same samples and canonicalizer always
// produce the same ordered witness set and verdict.
func EvaluateEvidenceCourtWithCanonicalizer(method string, samples []EvidenceCourtSample, required int, canonicalize EvidenceCourtCanonicalizer) EvidenceCourtResult {
	if required < 2 {
		required = 2
	}
	if required > evidenceCourtMaxProviders {
		required = evidenceCourtMaxProviders
	}
	out := EvidenceCourtResult{
		SchemaVersion: evidenceCourtSchemaVersion,
		Enabled:       true,
		Method:        strings.TrimSpace(method),
		Status:        "insufficient",
		Required:      required,
		Requested:     len(samples),
		Witnesses:     make([]EvidenceCourtWitness, 0, len(samples)),
		Limitations:   []string{},
	}
	if canonicalize == nil {
		out.Limitations = append(out.Limitations, "Evidence Court canonicalizer is unavailable.")
		return out
	}

	counts := map[string]int{}
	minSlot := uint64(0)
	maxSlot := uint64(0)
	for _, sample := range samples {
		witness := EvidenceCourtWitness{
			Provider: strings.TrimSpace(sample.Provider),
			Host:     evidenceCourtSafeHost(sample.Host),
			Status:   "unavailable",
		}
		if witness.Provider == "" {
			witness.Provider = providerLabel(witness.Host)
		}
		if sample.Err != nil {
			witness.ErrorClass = evidenceCourtErrorClass(sample.Err)
			out.Witnesses = append(out.Witnesses, witness)
			continue
		}
		hash, slot, nullValue, err := canonicalize(sample.Result)
		if err != nil {
			witness.Status = "malformed"
			witness.ErrorClass = "canonicalization_failed"
			out.Witnesses = append(out.Witnesses, witness)
			continue
		}
		hash = strings.ToLower(strings.TrimSpace(hash))
		if hash == "" {
			witness.Status = "malformed"
			witness.ErrorClass = "empty_canonical_hash"
			out.Witnesses = append(out.Witnesses, witness)
			continue
		}
		witness.Status = "observed"
		witness.ValueHash = hash
		witness.ContextSlot = slot
		witness.NullValue = nullValue
		out.Available++
		counts[hash]++
		if slot > 0 && (minSlot == 0 || slot < minSlot) {
			minSlot = slot
		}
		if slot > maxSlot {
			maxSlot = slot
		}
		out.Witnesses = append(out.Witnesses, witness)
	}

	sort.Slice(out.Witnesses, func(i, j int) bool {
		if out.Witnesses[i].Provider == out.Witnesses[j].Provider {
			return out.Witnesses[i].Host < out.Witnesses[j].Host
		}
		return out.Witnesses[i].Provider < out.Witnesses[j].Provider
	})
	out.MinSlot = minSlot
	out.MaxSlot = maxSlot
	if maxSlot >= minSlot && minSlot > 0 {
		out.SlotSpread = maxSlot - minSlot
	}

	bestHash := ""
	bestCount := 0
	for hash, count := range counts {
		if count > bestCount || (count == bestCount && (bestHash == "" || hash < bestHash)) {
			bestHash = hash
			bestCount = count
		}
	}
	out.Matching = bestCount
	if out.Available < required {
		out.Status = "insufficient"
		out.Limitations = append(out.Limitations, "Too few providers returned canonical evidence to satisfy the required quorum.")
		return out
	}
	if bestCount >= required {
		out.Status = "verified"
		out.ValueHash = bestHash
		if bestCount < out.Available {
			out.Limitations = append(out.Limitations, "At least one available provider disagreed with the quorum value.")
		}
		return out
	}
	out.Status = "conflict"
	out.Limitations = append(out.Limitations, "Independent providers returned conflicting canonical evidence; no verified value was selected.")
	return out
}

func validateEvidenceCourtCanonicalHash(hash string) error {
	if strings.TrimSpace(hash) == "" {
		return fmt.Errorf("canonical hash is empty")
	}
	return nil
}
