package services

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	canonicalPumpFunProgramID   = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"
	canonicalSPLTokenProgramID  = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
	canonicalToken2022ProgramID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
)

type ActorCreatedMintCandidate struct {
	Mint                       string    `json:"mint"`
	Signature                  string    `json:"signature"`
	Slot                       int64     `json:"slot"`
	BlockTime                  int64     `json:"block_time,omitempty"`
	ObservedAt                 time.Time `json:"observed_at"`
	Program                    string    `json:"program"`
	InstructionType            string    `json:"instruction_type"`
	ActorSigned                bool      `json:"actor_signed"`
	VerificationStatus         string    `json:"verification_status"`
	Source                     string    `json:"source"`
	CurrentLiquidityUSD        float64   `json:"current_liquidity_usd,omitempty"`
	CurrentPriceUSD            float64   `json:"current_price_usd,omitempty"`
	LiquidityEvidenceAvailable bool      `json:"liquidity_evidence_available"`
	MarketEvidenceStatus       string    `json:"market_evidence_status,omitempty"`
	FateStatus                 string    `json:"fate_status,omitempty"`
	FateReason                 string    `json:"fate_reason,omitempty"`
}

// CreatedMintDiscovery is provider-neutral. Discovery records remain OBSERVED
// until the candidate transaction is independently re-read from canonical
// Solana RPC and the actor signer plus create/initializeMint instruction match.
type CreatedMintDiscovery struct {
	Configured       bool                        `json:"configured"`
	Available        bool                        `json:"available"`
	Status           string                      `json:"status"`
	Provider         string                      `json:"provider"`
	Wallet           string                      `json:"wallet"`
	PagesFetched     int                         `json:"pages_fetched"`
	TransactionsSeen int                         `json:"transactions_seen"`
	Candidates       []ActorCreatedMintCandidate `json:"candidates"`
	NextCursor       string                      `json:"next_cursor,omitempty"`
	ObservedAt       time.Time                   `json:"observed_at"`
	Limitations      []string                    `json:"limitations"`
}

// ExtractActorCreatedMintCandidates accepts jsonParsed transaction objects
// from Helius getTransactionsForAddress or canonical Solana RPC. It requires
// the actor to be a transaction signer and recognizes only explicit Pump create
// or SPL/Token-2022 initializeMint instructions.
func ExtractActorCreatedMintCandidates(transactions []map[string]any, actorWallet, source string) []ActorCreatedMintCandidate {
	actorWallet = strings.TrimSpace(actorWallet)
	if actorWallet == "" {
		return []ActorCreatedMintCandidate{}
	}
	index := map[string]ActorCreatedMintCandidate{}
	for _, tx := range transactions {
		message := createdMintMessage(tx)
		keys, signers := createdMintAccountKeys(message)
		if !signers[actorWallet] {
			continue
		}
		signature := createdMintSignature(tx)
		slot := createdMintInt64(tx["slot"])
		blockTime := createdMintInt64(firstCreatedMintValue(tx, "blockTime", "block_time"))
		observedAt := time.Time{}
		if blockTime > 0 {
			observedAt = time.Unix(blockTime, 0).UTC()
		}
		for _, instruction := range createdMintInstructions(message, createdMintMap(tx["meta"])) {
			programID := strings.TrimSpace(firstCreatedMintString(instruction["programId"], instruction["program_id"]))
			programName := strings.ToLower(strings.TrimSpace(firstCreatedMintString(instruction["program"])))
			parsed := createdMintMap(instruction["parsed"])
			instructionType := strings.ToLower(strings.TrimSpace(firstCreatedMintString(parsed["type"], instruction["type"], instruction["instruction_type"])))
			info := createdMintMap(parsed["info"])
			mint := ""
			switch {
			case programID == canonicalPumpFunProgramID || strings.Contains(programName, "pump"):
				if instructionType != "" && !strings.Contains(instructionType, "create") {
					continue
				}
				mint = firstCreatedMintString(info["mint"], instruction["mint"])
				if mint == "" {
					accounts := createdMintInstructionAccounts(instruction, keys)
					if len(accounts) > 0 {
						mint = accounts[0]
					}
				}
				if instructionType == "" {
					instructionType = "pump_create_candidate"
				}
				if programID == "" {
					programID = canonicalPumpFunProgramID
				}
			case programID == canonicalSPLTokenProgramID || programID == canonicalToken2022ProgramID || strings.Contains(programName, "token"):
				if instructionType != "initializemint" && instructionType != "initializemint2" && instructionType != "initialize_mint" && instructionType != "initialize_mint2" {
					continue
				}
				mint = firstCreatedMintString(info["mint"], instruction["mint"])
			default:
				continue
			}
			mint = strings.TrimSpace(mint)
			if mint == "" || mint == actorWallet {
				continue
			}
			candidate := ActorCreatedMintCandidate{
				Mint: mint, Signature: signature, Slot: slot, BlockTime: blockTime,
				ObservedAt: observedAt, Program: programID, InstructionType: instructionType,
				ActorSigned: true, VerificationStatus: "observed", Source: source,
			}
			key := mint + "|" + signature
			if current, ok := index[key]; !ok || candidate.Slot > current.Slot {
				index[key] = candidate
			}
		}
	}
	out := make([]ActorCreatedMintCandidate, 0, len(index))
	for _, candidate := range index {
		out = append(out, candidate)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Slot != out[j].Slot {
			return out[i].Slot > out[j].Slot
		}
		return out[i].Mint < out[j].Mint
	})
	return out
}

func ActorCreatedMintCandidateEvidence(wallet, network string, candidates []ActorCreatedMintCandidate) []ActorDefenseEvidenceRecord {
	out := []ActorDefenseEvidenceRecord{}
	wallet = strings.TrimSpace(wallet)
	for _, candidate := range candidates {
		if wallet == "" || strings.TrimSpace(candidate.Mint) == "" {
			continue
		}
		status := strings.ToLower(strings.TrimSpace(candidate.VerificationStatus))
		if status != "verified" {
			status = "observed"
		}
		observedAt := candidate.ObservedAt
		if observedAt.IsZero() {
			observedAt = time.Now().UTC()
		}
		source := strings.TrimSpace(candidate.Source)
		if source == "" {
			source = "helius_get_transactions_for_address"
		}
		key := candidate.Signature
		if key == "" {
			key = candidate.Mint
		}
		out = append(out, ActorDefenseEvidenceRecord{
			Network: normalizeRadarNetwork(network), ActorWallet: wallet,
			CounterpartKind: "token", CounterpartID: candidate.Mint,
			Relation: "created_token", VerificationStatus: status,
			EvidenceKey: "created_mint:" + key + ":" + candidate.Mint,
			Source:      source, Signature: candidate.Signature, Slot: candidate.Slot,
			ObservedAt: observedAt, TokenMint: candidate.Mint, OccurrenceCount: 1,
			Metadata: map[string]any{
				"actor_role": "creator_deployer", "source_wallet": wallet,
				"destination_wallet": candidate.Mint, "program": candidate.Program,
				"instruction_type": candidate.InstructionType, "actor_signed": candidate.ActorSigned,
				"external_discovery":           status != "verified",
				"identity_or_wrongdoing_claim": false, "persistent_actor_index": true,
			},
		})
	}
	return out
}

func createdMintMessage(tx map[string]any) map[string]any {
	transaction := createdMintMap(tx["transaction"])
	if len(transaction) == 0 {
		transaction = createdMintMap(tx["tx"])
	}
	return createdMintMap(transaction["message"])
}

func createdMintSignature(tx map[string]any) string {
	if value := firstCreatedMintString(tx["signature"], tx["tx_hash"], tx["txHash"]); value != "" {
		return value
	}
	transaction := createdMintMap(tx["transaction"])
	if signatures, ok := transaction["signatures"].([]any); ok && len(signatures) > 0 {
		return firstCreatedMintString(signatures[0])
	}
	if signatures, ok := tx["signatures"].([]any); ok && len(signatures) > 0 {
		return firstCreatedMintString(signatures[0])
	}
	return ""
}

func createdMintAccountKeys(message map[string]any) ([]string, map[string]bool) {
	keys := []string{}
	signers := map[string]bool{}
	items, _ := message["accountKeys"].([]any)
	if len(items) == 0 {
		items, _ = message["account_keys"].([]any)
	}
	for _, raw := range items {
		key := ""
		signer := false
		switch value := raw.(type) {
		case string:
			key = strings.TrimSpace(value)
		case map[string]any:
			key = firstCreatedMintString(value["pubkey"], value["address"])
			signer = createdMintBool(value["signer"])
		}
		if key == "" {
			continue
		}
		keys = append(keys, key)
		if signer {
			signers[key] = true
		}
	}
	return keys, signers
}

func createdMintInstructions(message, meta map[string]any) []map[string]any {
	out := []map[string]any{}
	appendRows := func(raw any) {
		rows, _ := raw.([]any)
		for _, row := range rows {
			if item, ok := row.(map[string]any); ok {
				out = append(out, item)
			}
		}
	}
	appendRows(message["instructions"])
	inner, _ := meta["innerInstructions"].([]any)
	if len(inner) == 0 {
		inner, _ = meta["inner_instructions"].([]any)
	}
	for _, raw := range inner {
		appendRows(createdMintMap(raw)["instructions"])
	}
	return out
}

func createdMintInstructionAccounts(instruction map[string]any, keys []string) []string {
	out := []string{}
	rows, _ := instruction["accounts"].([]any)
	for _, row := range rows {
		switch value := row.(type) {
		case string:
			value = strings.TrimSpace(value)
			if value != "" {
				out = append(out, value)
			}
		case float64:
			index := int(value)
			if index >= 0 && index < len(keys) {
				out = append(out, keys[index])
			}
		case int:
			if value >= 0 && value < len(keys) {
				out = append(out, keys[value])
			}
		}
	}
	return out
}

func firstCreatedMintValue(values map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := values[key]; ok && value != nil {
			return value
		}
	}
	return nil
}

func firstCreatedMintString(values ...any) string {
	for _, raw := range values {
		if raw == nil {
			continue
		}
		value := strings.TrimSpace(fmt.Sprint(raw))
		if value != "" && value != "<nil>" {
			return value
		}
	}
	return ""
}

func createdMintMap(value any) map[string]any {
	if result, ok := value.(map[string]any); ok {
		return result
	}
	return map[string]any{}
}

func createdMintInt64(value any) int64 {
	switch typed := value.(type) {
	case int64:
		return typed
	case int:
		return int64(typed)
	case float64:
		return int64(typed)
	case json.Number:
		parsed, _ := typed.Int64()
		return parsed
	case string:
		parsed, _ := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		return parsed
	default:
		return 0
	}
}

func createdMintBool(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		parsed, _ := strconv.ParseBool(strings.TrimSpace(typed))
		return parsed
	default:
		return false
	}
}
