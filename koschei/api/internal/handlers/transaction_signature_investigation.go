package handlers

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"koschei/api/internal/services"
)

const transactionInvestigationSchemaVersion = "koschei-transaction-investigation-v1"

type transactionInvestigationBalanceDelta struct {
	Address       string `json:"address"`
	LamportsDelta int64  `json:"lamports_delta"`
}

type transactionInvestigationTokenDelta struct {
	AccountIndex int     `json:"account_index"`
	Address      string  `json:"address,omitempty"`
	Owner        string  `json:"owner,omitempty"`
	Mint         string  `json:"mint"`
	Decimals     int     `json:"decimals"`
	PreAmount    float64 `json:"pre_amount"`
	PostAmount   float64 `json:"post_amount"`
	Delta        float64 `json:"delta"`
}

type transactionInvestigationInstruction struct {
	Index       int            `json:"index"`
	Program     string         `json:"program,omitempty"`
	ProgramID   string         `json:"program_id,omitempty"`
	Type        string         `json:"type,omitempty"`
	ParsedInfo  map[string]any `json:"parsed_info,omitempty"`
	Inner       bool           `json:"inner"`
	EvidenceRef string         `json:"evidence_ref"`
}

type transactionInvestigationReport struct {
	SchemaVersion       string                                  `json:"schema_version"`
	Status              string                                  `json:"status"`
	Network             string                                  `json:"network"`
	Signature           string                                  `json:"signature"`
	Slot                int64                                   `json:"slot,omitempty"`
	BlockTime           time.Time                               `json:"block_time,omitempty"`
	Succeeded           bool                                    `json:"succeeded"`
	ExecutionError      any                                     `json:"execution_error,omitempty"`
	FeeLamports         int64                                   `json:"fee_lamports,omitempty"`
	Signers             []string                                `json:"signers"`
	AccountKeys         []string                                `json:"account_keys"`
	InvokedPrograms     []string                                `json:"invoked_programs"`
	Instructions        []transactionInvestigationInstruction   `json:"instructions"`
	SOLBalanceDeltas    []transactionInvestigationBalanceDelta  `json:"sol_balance_deltas"`
	TokenBalanceDeltas  []transactionInvestigationTokenDelta    `json:"token_balance_deltas"`
	EvidenceRefs        []string                                `json:"evidence_refs"`
	EvidenceLimits      []string                                `json:"evidence_limits"`
	CollectionGaps      []string                                `json:"collection_gaps"`
	IdentityScope       string                                  `json:"identity_scope"`
	AttributionClaimed  bool                                    `json:"attribution_claimed"`
	RawTransactionSaved bool                                    `json:"raw_transaction_saved"`
	Memory              intelligenceMemoryReceipt               `json:"intelligence_memory"`
}

func (h *Handler) investigateTransactionSignature(ctx context.Context, signature, network string) transactionInvestigationReport {
	signature = strings.TrimSpace(signature)
	network = strings.TrimSpace(network)
	if network == "" {
		network = "solana-mainnet"
	}
	out := newTransactionInvestigationReport(signature, network)
	if signature == "" {
		out.Status = "signature_required"
		out.CollectionGaps = append(out.CollectionGaps, "A Solana transaction signature is required before transaction evidence can be collected.")
		return out
	}
	if network != "solana-mainnet" {
		out.Status = "unsupported_network"
		out.CollectionGaps = append(out.CollectionGaps, "Transaction signature investigation currently has a verified collector only for solana-mainnet.")
		return out
	}
	rpcURL := creatorIntelRPCURL()
	if strings.TrimSpace(rpcURL) == "" {
		out.Status = "rpc_unavailable"
		out.CollectionGaps = append(out.CollectionGaps, "Solana RPC is unavailable; transaction details were not collected.")
		return out
	}
	tx, err := services.SolanaGetTransactionJSONParsed(ctx, rpcURL, signature)
	if err != nil {
		out.Status = "collection_failed"
		out.CollectionGaps = append(out.CollectionGaps, "getTransaction failed: "+compactCollectorError(err))
		return out
	}
	if tx == nil {
		out.Status = "transaction_unavailable"
		out.CollectionGaps = append(out.CollectionGaps, "The RPC provider returned no transaction object for this signature; absence is not treated as a safe result.")
		return out
	}
	out = buildTransactionInvestigationReport(signature, network, map[string]any(tx))
	payload := map[string]any{
		"schema_version": transactionInvestigationSchemaVersion,
		"network":        network,
		"signature":      signature,
		"investigation":  out,
		"storage_policy": map[string]any{
			"durable_memory_backend":        "google_drive",
			"neon_intelligence_persistence": false,
			"raw_transaction_saved":         false,
		},
	}
	out.Memory = h.archiveIntelligenceMemory(ctx, "transaction_investigation", network, signature, payload)
	return out
}

func newTransactionInvestigationReport(signature, network string) transactionInvestigationReport {
	return transactionInvestigationReport{
		SchemaVersion:      transactionInvestigationSchemaVersion,
		Status:             "not_started",
		Network:            strings.TrimSpace(network),
		Signature:          strings.TrimSpace(signature),
		Signers:            []string{},
		AccountKeys:        []string{},
		InvokedPrograms:    []string{},
		Instructions:       []transactionInvestigationInstruction{},
		SOLBalanceDeltas:   []transactionInvestigationBalanceDelta{},
		TokenBalanceDeltas: []transactionInvestigationTokenDelta{},
		EvidenceRefs:       []string{},
		EvidenceLimits:     []string{},
		CollectionGaps:     []string{},
		IdentityScope:      "onchain_transaction_only",
	}
}

func buildTransactionInvestigationReport(signature, network string, tx map[string]any) transactionInvestigationReport {
	out := newTransactionInvestigationReport(signature, network)
	meta := creatorIntelMap(tx["meta"])
	transaction := creatorIntelMap(tx["transaction"])
	message := creatorIntelMap(transaction["message"])
	out.Slot = creatorIntelInt64(tx["slot"])
	if blockTime := creatorIntelInt64(tx["blockTime"]); blockTime > 0 {
		out.BlockTime = time.Unix(blockTime, 0).UTC()
	}
	out.ExecutionError = meta["err"]
	out.Succeeded = meta["err"] == nil
	out.FeeLamports = creatorIntelInt64(meta["fee"])
	out.AccountKeys, out.Signers = transactionInvestigationAccountKeys(message, meta)
	out.SOLBalanceDeltas = transactionInvestigationSOLBalanceDeltas(meta, out.AccountKeys)
	out.TokenBalanceDeltas = transactionInvestigationTokenBalanceDeltas(meta, out.AccountKeys)
	out.Instructions = transactionInvestigationInstructions(message, meta)
	out.InvokedPrograms = transactionInvestigationPrograms(out.Instructions)
	out.EvidenceRefs = transactionInvestigationEvidenceRefs(out)
	out.Status = "complete"
	if len(out.Instructions) == 0 {
		out.EvidenceLimits = append(out.EvidenceLimits, "No parsed top-level or inner instructions were exposed by the RPC response; hidden semantics are not inferred.")
	}
	if len(out.InvokedPrograms) == 0 {
		out.EvidenceLimits = append(out.EvidenceLimits, "No invoked program ID could be resolved from parsed instructions; program behavior is therefore not claimed.")
	}
	out.EvidenceLimits = append(out.EvidenceLimits,
		"This historical transaction view describes observed execution evidence; it does not reconstruct pre-signing intent or prove the signer's real-world identity.",
		"Program bytecode semantics are not inferred solely from an invoked program ID.",
	)
	return out
}

func transactionInvestigationAccountKeys(message, meta map[string]any) ([]string, []string) {
	keys, signers := creatorIntelAccountKeys(message)
	loaded := creatorIntelMap(meta["loadedAddresses"])
	keys = append(keys, creatorIntelStringSlice(loaded["writable"])...)
	keys = append(keys, creatorIntelStringSlice(loaded["readonly"])...)
	return uniqueStrings(keys), uniqueStrings(signers)
}

func transactionInvestigationSOLBalanceDeltas(meta map[string]any, keys []string) []transactionInvestigationBalanceDelta {
	deltas := creatorIntelLamportDeltas(meta, keys)
	out := make([]transactionInvestigationBalanceDelta, 0, len(deltas))
	for _, address := range keys {
		delta, exists := deltas[address]
		if !exists || delta == 0 {
			continue
		}
		out = append(out, transactionInvestigationBalanceDelta{Address: address, LamportsDelta: delta})
	}
	return out
}

type transactionTokenState struct {
	Index    int
	Address  string
	Owner    string
	Mint     string
	Decimals int
	Amount   float64
}

func transactionInvestigationTokenBalanceDeltas(meta map[string]any, keys []string) []transactionInvestigationTokenDelta {
	pre := transactionTokenStates(meta["preTokenBalances"], keys)
	post := transactionTokenStates(meta["postTokenBalances"], keys)
	indexes := map[int]bool{}
	for index := range pre {
		indexes[index] = true
	}
	for index := range post {
		indexes[index] = true
	}
	ordered := make([]int, 0, len(indexes))
	for index := range indexes {
		ordered = append(ordered, index)
	}
	sort.Ints(ordered)
	out := make([]transactionInvestigationTokenDelta, 0, len(ordered))
	for _, index := range ordered {
		before := pre[index]
		after := post[index]
		state := after
		if state.Mint == "" {
			state = before
		}
		delta := after.Amount - before.Amount
		if delta == 0 {
			continue
		}
		out = append(out, transactionInvestigationTokenDelta{
			AccountIndex: index,
			Address:      state.Address,
			Owner:        firstNonEmptyString(after.Owner, before.Owner),
			Mint:         firstNonEmptyString(after.Mint, before.Mint),
			Decimals:     maxInt(after.Decimals, before.Decimals),
			PreAmount:    before.Amount,
			PostAmount:   after.Amount,
			Delta:        delta,
		})
	}
	return out
}

func transactionTokenStates(raw any, keys []string) map[int]transactionTokenState {
	out := map[int]transactionTokenState{}
	items, _ := raw.([]any)
	for _, item := range items {
		row := creatorIntelMap(item)
		index := creatorIntelInt(row["accountIndex"])
		ui := creatorIntelMap(row["uiTokenAmount"])
		address := ""
		if index >= 0 && index < len(keys) {
			address = keys[index]
		}
		out[index] = transactionTokenState{
			Index:    index,
			Address:  address,
			Owner:    creatorIntelCleanString(row["owner"]),
			Mint:     creatorIntelCleanString(row["mint"]),
			Decimals: creatorIntelInt(ui["decimals"]),
			Amount:   creatorIntelUIAmount(ui),
		}
	}
	return out
}

func transactionInvestigationInstructions(message, meta map[string]any) []transactionInvestigationInstruction {
	out := []transactionInvestigationInstruction{}
	appendRows := func(raw any, inner bool, prefix string) {
		items, _ := raw.([]any)
		for _, item := range items {
			row := creatorIntelMap(item)
			parsed := creatorIntelMap(row["parsed"])
			instruction := transactionInvestigationInstruction{
				Index:       len(out),
				Program:     creatorIntelCleanString(row["program"]),
				ProgramID:   creatorIntelCleanString(row["programId"]),
				Type:        strings.ToLower(creatorIntelCleanString(parsed["type"])),
				ParsedInfo:  creatorIntelMap(parsed["info"]),
				Inner:       inner,
				EvidenceRef: fmt.Sprintf("rpc:getTransaction.%s[%d]", prefix, len(out)),
			}
			out = append(out, instruction)
		}
	}
	appendRows(message["instructions"], false, "message.instructions")
	innerRows, _ := meta["innerInstructions"].([]any)
	for groupIndex, group := range innerRows {
		groupMap := creatorIntelMap(group)
		appendRows(groupMap["instructions"], true, fmt.Sprintf("meta.innerInstructions[%d].instructions", groupIndex))
	}
	return out
}

func transactionInvestigationPrograms(instructions []transactionInvestigationInstruction) []string {
	programs := []string{}
	for _, instruction := range instructions {
		if strings.TrimSpace(instruction.ProgramID) != "" {
			programs = append(programs, instruction.ProgramID)
		}
	}
	return uniqueStrings(programs)
}

func transactionInvestigationEvidenceRefs(report transactionInvestigationReport) []string {
	refs := []string{"rpc:getTransaction", "rpc:getTransaction.meta", "rpc:getTransaction.transaction.message"}
	if report.Slot > 0 {
		refs = append(refs, "rpc:getTransaction.slot")
	}
	if !report.BlockTime.IsZero() {
		refs = append(refs, "rpc:getTransaction.blockTime")
	}
	if len(report.SOLBalanceDeltas) > 0 {
		refs = append(refs, "rpc:getTransaction.meta.preBalances", "rpc:getTransaction.meta.postBalances")
	}
	if len(report.TokenBalanceDeltas) > 0 {
		refs = append(refs, "rpc:getTransaction.meta.preTokenBalances", "rpc:getTransaction.meta.postTokenBalances")
	}
	for _, instruction := range report.Instructions {
		refs = append(refs, instruction.EvidenceRef)
	}
	return uniqueStrings(refs)
}
