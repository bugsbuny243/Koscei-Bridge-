package web3

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
)

const evidenceCourtSchemaVersion = "koschei-evidence-court-v1"

const evidenceCourtMaxProviders = 4

type EvidenceCourtWitness struct {
	Provider    string `json:"provider"`
	Host        string `json:"host"`
	Status      string `json:"status"`
	ValueHash   string `json:"value_hash,omitempty"`
	ContextSlot uint64 `json:"context_slot,omitempty"`
	NullValue   bool   `json:"null_value,omitempty"`
	ErrorClass  string `json:"error_class,omitempty"`
}

type EvidenceCourtResult struct {
	SchemaVersion string                 `json:"schema_version"`
	Enabled       bool                   `json:"enabled"`
	Method        string                 `json:"method"`
	Status        string                 `json:"status"`
	Required      int                    `json:"required_witnesses"`
	Requested     int                    `json:"requested_witnesses"`
	Available     int                    `json:"available_witnesses"`
	Matching      int                    `json:"matching_witnesses"`
	ValueHash     string                 `json:"agreed_value_hash,omitempty"`
	MinSlot       uint64                 `json:"min_context_slot,omitempty"`
	MaxSlot       uint64                 `json:"max_context_slot,omitempty"`
	SlotSpread    uint64                 `json:"context_slot_spread,omitempty"`
	Witnesses     []EvidenceCourtWitness `json:"witnesses"`
	Limitations   []string               `json:"limitations"`
}

type EvidenceCourtSample struct {
	Provider string
	Host     string
	Result   json.RawMessage
	Err      error
}

type evidenceCourtEndpoint struct {
	Provider string
	Host     string
	URL      string
}

func EvidenceCourtEnabled() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("KOSCHEI_EVIDENCE_COURT_ENABLED")))
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func evidenceCourtRequiredWitnesses() int {
	value := 2
	if raw := strings.TrimSpace(os.Getenv("KOSCHEI_EVIDENCE_COURT_REQUIRED_WITNESSES")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			value = parsed
		}
	}
	if value < 2 {
		return 2
	}
	if value > evidenceCourtMaxProviders {
		return evidenceCourtMaxProviders
	}
	return value
}

func evidenceCourtAllowedMethod(method string) bool {
	switch strings.TrimSpace(method) {
	case "getAccountInfo", "getMultipleAccounts", "getTokenSupply":
		return true
	default:
		return false
	}
}

// EvidenceCourt performs a bounded, read-only multi-provider comparison for
// critical state evidence. It is default-off and intentionally separate from
// normal failover: failover asks one provider after another for availability;
// Evidence Court asks independent provider hosts for corroboration.
func (s *SolanaRPC) EvidenceCourt(ctx context.Context, network, method string, params any) EvidenceCourtResult {
	required := evidenceCourtRequiredWitnesses()
	result := EvidenceCourtResult{
		SchemaVersion: evidenceCourtSchemaVersion,
		Enabled:       EvidenceCourtEnabled(),
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

	endpoints := s.evidenceCourtEndpoints(network)
	result.Requested = len(endpoints)
	if len(endpoints) < required {
		result.Status = "insufficient"
		result.Limitations = append(result.Limitations, "Fewer independent provider hosts are configured than the required witness quorum.")
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

	type witnessResponse struct {
		sample EvidenceCourtSample
	}
	responses := make(chan witnessResponse, len(endpoints))
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
			responses <- witnessResponse{sample: EvidenceCourtSample{
				Provider: endpoint.Provider,
				Host:     endpoint.Host,
				Result:   raw,
				Err:      err,
			}}
		}()
	}

	samples := make([]EvidenceCourtSample, 0, len(endpoints))
	for range endpoints {
		select {
		case response := <-responses:
			samples = append(samples, response.sample)
		case <-ctx.Done():
			samples = append(samples, EvidenceCourtSample{Provider: "context", Host: "context", Err: ctx.Err()})
		}
	}
	return EvaluateEvidenceCourt(method, samples, required)
}

// EvaluateEvidenceCourt is the deterministic quorum core. The same samples
// always produce the same ordered witness set and verdict.
func EvaluateEvidenceCourt(method string, samples []EvidenceCourtSample, required int) EvidenceCourtResult {
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
		hash, slot, nullValue, err := evidenceCourtCanonicalHash(sample.Result)
		if err != nil {
			witness.Status = "malformed"
			witness.ErrorClass = "malformed_result"
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

func evidenceCourtCanonicalHash(raw json.RawMessage) (string, uint64, bool, error) {
	if len(raw) == 0 {
		return "", 0, false, fmt.Errorf("empty result")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return "", 0, false, err
	}
	value := decoded
	contextSlot := uint64(0)
	if object, ok := decoded.(map[string]any); ok {
		if candidate, exists := object["value"]; exists {
			value = candidate
		}
		if contextValue, ok := object["context"].(map[string]any); ok {
			contextSlot = evidenceCourtUint64(contextValue["slot"])
		}
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", 0, false, err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), contextSlot, value == nil, nil
}

func evidenceCourtUint64(value any) uint64 {
	switch typed := value.(type) {
	case json.Number:
		parsed, _ := strconv.ParseUint(typed.String(), 10, 64)
		return parsed
	case float64:
		if typed > 0 {
			return uint64(typed)
		}
	case string:
		parsed, _ := strconv.ParseUint(strings.TrimSpace(typed), 10, 64)
		return parsed
	}
	return 0
}

func evidenceCourtErrorClass(err error) string {
	if err == nil {
		return ""
	}
	if err == context.DeadlineExceeded {
		return "deadline_exceeded"
	}
	if err == context.Canceled {
		return "canceled"
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "status 429"):
		return "rate_limited"
	case strings.Contains(message, "status 5"):
		return "provider_5xx"
	case strings.Contains(message, "rpc error"):
		return "rpc_error"
	default:
		return "unavailable"
	}
}

func evidenceCourtSafeHost(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "unconfigured"
	}
	if strings.Contains(value, "://") {
		return RPCProviderHost(value)
	}
	if strings.ContainsAny(value, "/?#@") {
		return "invalid-host"
	}
	return value
}

func (s *SolanaRPC) evidenceCourtEndpoints(network string) []evidenceCourtEndpoint {
	if s == nil {
		return nil
	}
	candidates := []string{s.URL(network), SolanaRPCFallbackURL(network)}
	if isSolanaMainnet(network) || strings.TrimSpace(network) == "" {
		for _, key := range []string{"ALCHEMY_SOLANA_RPC_URL", "HELIUS_SOLANA_RPC_URL", "QUICKNODE_SOLANA_RPC_URL"} {
			candidates = append(candidates, strings.TrimSpace(os.Getenv(key)))
		}
		if key := strings.TrimSpace(s.AlchemyAPIKey); key != "" {
			candidates = append(candidates, "https://solana-mainnet.g.alchemy.com/v2/"+key)
		}
		candidates = append(candidates, "https://api.mainnet-beta.solana.com")
	}

	seenHosts := map[string]struct{}{}
	out := make([]evidenceCourtEndpoint, 0, evidenceCourtMaxProviders)
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		host := RPCProviderHost(candidate)
		if host == "unconfigured" || host == "invalid-host" {
			continue
		}
		if _, exists := seenHosts[host]; exists {
			continue
		}
		seenHosts[host] = struct{}{}
		out = append(out, evidenceCourtEndpoint{Provider: providerLabel(host), Host: host, URL: candidate})
		if len(out) == evidenceCourtMaxProviders {
			break
		}
	}
	return out
}

func providerLabel(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	switch {
	case strings.Contains(host, "helius"):
		return "helius"
	case strings.Contains(host, "alchemy"):
		return "alchemy"
	case strings.Contains(host, "quiknode"), strings.Contains(host, "quicknode"):
		return "quicknode"
	case host == "api.mainnet-beta.solana.com", host == "api.devnet.solana.com":
		return "solana_public"
	case host == "":
		return "unknown"
	default:
		return host
	}
}
