package handlers

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/services"
)

type actorDefenseRequest struct {
	Target       string `json:"target"`
	Address      string `json:"address"`
	Network      string `json:"network"`
	LiveEvidence *bool  `json:"live_evidence,omitempty"`
}

type actorDefenseLiveCoverage struct {
	Status              string   `json:"status"`
	SignaturesSeen      int      `json:"signatures_seen"`
	TransactionsParsed  int      `json:"transactions_parsed"`
	EvidencePersisted   int      `json:"evidence_persisted"`
	RPCFailures         int      `json:"rpc_failures"`
	PersistenceFailures int      `json:"persistence_failures"`
	SignatureLimit      int      `json:"signature_limit"`
	TransactionLimit    int      `json:"transaction_limit"`
	EvidenceLimit       int      `json:"evidence_limit"`
	Limitations         []string `json:"limitations"`
}

type actorDefenseTokenAccountOwner struct {
	Owner string
	Mint  string
}

// OwnerActorDefenseInvestigation is the wallet-first investigation surface for
// Koschei's defense network. It assembles persistent actor memory, Pump trade
// observations and selective live transaction evidence. It does not produce a
// numeric score and it never turns a relation into an identity or wrongdoing
// claim. Letter grades come only from the versioned deterministic ruleset.
func (h *Handler) OwnerActorDefenseInvestigation(w http.ResponseWriter, r *http.Request) {
	var input actorDefenseRequest
	if err := decodeJSON(r, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "Invalid request body")
		return
	}
	target := strings.TrimSpace(firstNonEmptyString(input.Target, input.Address))
	if target == "" {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "target is required")
		return
	}
	network := strings.TrimSpace(input.Network)
	if network == "" {
		network = "solana-mainnet"
	}
	classification := classifyRadarTarget(r.Context(), target)
	wallet := target
	switch classification.Type {
	case radarTargetWallet:
		// Direct wallet investigation.
	case radarTargetTokenAccount:
		wallet = strings.TrimSpace(classification.TokenOwnerWallet)
		if wallet == "" {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"ok": false, "error": "token_account_owner_unresolved",
				"target": target, "target_classification": classification,
				"message": "Token hesabının owner cüzdanı çözümlenemedi; wallet investigation başlatılmadı.",
			})
			return
		}
	default:
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"ok": false, "error": "wallet_target_required",
			"target": target, "target_classification": classification,
			"message": "Bu endpoint wallet-first actor investigation içindir; doğrulanmış bir cüzdan veya token hesabı gerekir.",
		})
		return
	}

	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Actor defense database is unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 170*time.Second)
	defer cancel()
	store := services.NewActorDefenseStore(db)
	initial, err := store.LoadPersistentWalletDossier(ctx, wallet, network, 75)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Actor defense dossier could not be assembled")
		return
	}

	liveEnabled := true
	if input.LiveEvidence != nil {
		liveEnabled = *input.LiveEvidence
	}
	coverage := actorDefenseLiveCoverage{Status: "stored_evidence_only", Limitations: []string{}}
	fundingOrigin := services.ActorFundingOrigin{
		Wallet: wallet, Status: "stored_evidence_only", VerificationStatus: "unverified",
		TrailStatus: "not_investigated", IdentityScope: "onchain_wallet_only", Limitations: []string{},
	}
	fundingPersistence := "not_requested"
	if liveEnabled {
		fundingOrigin, fundingPersistence = h.collectActorFundingOrigin(ctx, store, wallet, network)
		coverage = h.collectActorDefenseLiveEvidence(ctx, store, initial)
		if fundingPersistence == "failed" {
			coverage.PersistenceFailures++
			if coverage.Status == "complete" {
				coverage.Status = "partial_persistence"
			}
			coverage.Limitations = append(coverage.Limitations, "Funding-origin kanıtı kalıcı actor index'e yazılamadı.")
		}
	}
	final, err := store.LoadPersistentWalletDossier(ctx, wallet, network, 100)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Actor defense dossier could not be refreshed")
		return
	}
	ruleVerdict := services.EvaluateActorDefenseRules(final.Track, final.Evidence)
	rulePersistence := "persisted"
	if err := store.PersistRuleVerdict(ctx, final.Track, ruleVerdict); err != nil {
		rulePersistence = "failed"
		coverage.PersistenceFailures++
		if coverage.Status == "complete" {
			coverage.Status = "partial_persistence"
		}
		coverage.Limitations = append(coverage.Limitations, "Deterministik rule verdict threat track üzerine kaydedilemedi.")
	}
	final.Coverage["live_evidence"] = coverage
	final.Coverage["funding_origin"] = fundingOrigin
	final.Coverage["funding_origin_persistence"] = fundingPersistence
	final.Coverage["requested_target"] = target
	final.Coverage["resolved_wallet"] = wallet
	final.Coverage["rule_verdict_persistence"] = rulePersistence
	final.Coverage["numeric_score_disabled"] = true
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                    true,
		"schema_version":        "koschei-actor-defense-v3",
		"ruleset_version":       services.ActorDefenseRulesetVersion,
		"target":                target,
		"wallet":                wallet,
		"network":               network,
		"target_classification": classification,
		"dossier":               final,
		"funding_origin":        fundingOrigin,
		"rule_verdict":          ruleVerdict,
	})
}

func (h *Handler) collectActorFundingOrigin(ctx context.Context, store *services.ActorDefenseStore, wallet, network string) (services.ActorFundingOrigin, string) {
	timeout := time.Duration(actorDefenseEnvInt("ACTOR_FUNDING_TIMEOUT_SECONDS", 75, 20, 140)) * time.Second
	fundingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	origin, err := services.FindActorFundingOrigin(fundingCtx, creatorIntelRPCURL(), wallet, services.ActorFundingOriginOptions{
		PageSize:                  actorDefenseEnvInt("ACTOR_FUNDING_PAGE_SIZE", 250, 50, 1000),
		MaxPages:                  actorDefenseEnvInt("ACTOR_FUNDING_MAX_PAGES", 8, 1, 20),
		OldestTransactionsToParse: actorDefenseEnvInt("ACTOR_FUNDING_TRANSACTION_LIMIT", 60, 10, 250),
	})
	if err != nil {
		return services.ActorFundingOrigin{
			Wallet: wallet, Status: "investigation_failed", VerificationStatus: "unverified",
			TrailStatus: "not_investigated", IdentityScope: "onchain_wallet_only",
			Limitations: []string{"Funding-origin araştırması tamamlanamadı: " + creatorIntelCompactError(err)},
		}, "not_persisted"
	}
	evidence, ok := services.ActorFundingOriginEvidence(origin, network)
	if !ok {
		return origin, "no_persistable_evidence"
	}
	if err := store.UpsertEvidence(ctx, evidence); err != nil {
		return origin, "failed"
	}
	return origin, "persisted"
}

func (h *Handler) collectActorDefenseLiveEvidence(ctx context.Context, store *services.ActorDefenseStore, dossier services.ActorDefenseDossier) actorDefenseLiveCoverage {
	coverage := actorDefenseLiveCoverage{
		Status:           "complete",
		SignatureLimit:   actorDefenseEnvInt("ACTOR_DEFENSE_SIGNATURE_LIMIT", 120, 20, 500),
		TransactionLimit: actorDefenseEnvInt("ACTOR_DEFENSE_TRANSACTION_LIMIT", 40, 5, 120),
		EvidenceLimit:    actorDefenseEnvInt("ACTOR_DEFENSE_EVIDENCE_LIMIT", 100, 10, 300),
		Limitations:      []string{},
	}
	rpcURL := creatorIntelRPCURL()
	if rpcURL == "" {
		coverage.Status = "rpc_unavailable"
		coverage.Limitations = append(coverage.Limitations, "Solana RPC yapılandırılmadığı için yeni transaction kanıtı toplanmadı.")
		return coverage
	}
	signatures, err := services.SolanaGetSignaturesForAddress(ctx, rpcURL, dossier.Wallet, coverage.SignatureLimit)
	if err != nil {
		coverage.Status = "rpc_failed"
		coverage.RPCFailures++
		coverage.Limitations = append(coverage.Limitations, "Wallet işlem imzaları RPC sağlayıcısından alınamadı: "+creatorIntelCompactError(err))
		return coverage
	}
	coverage.SignaturesSeen = len(signatures)
	knownMints := map[string]bool{}
	for _, token := range dossier.Tokens {
		if strings.TrimSpace(token.Mint) != "" {
			knownMints[token.Mint] = true
		}
	}
	relatedActors := map[string]services.ActorDefenseRelatedActor{}
	for _, actor := range dossier.RelatedActors {
		if strings.TrimSpace(actor.Wallet) != "" {
			relatedActors[actor.Wallet] = actor
		}
	}
	persist := func(item services.ActorDefenseEvidenceRecord) {
		if coverage.EvidencePersisted >= coverage.EvidenceLimit {
			return
		}
		if err := store.UpsertEvidence(ctx, item); err != nil {
			coverage.PersistenceFailures++
			return
		}
		coverage.EvidencePersisted++
	}

	for _, signature := range signatures {
		if coverage.TransactionsParsed >= coverage.TransactionLimit || coverage.EvidencePersisted >= coverage.EvidenceLimit || ctx.Err() != nil {
			break
		}
		if signature.Err != nil || strings.TrimSpace(signature.Signature) == "" {
			continue
		}
		tx, txErr := services.SolanaGetTransactionJSONParsed(ctx, rpcURL, signature.Signature)
		if txErr != nil {
			coverage.RPCFailures++
			continue
		}
		txMap := map[string]any(tx)
		meta := creatorIntelMap(txMap["meta"])
		if meta["err"] != nil {
			continue
		}
		coverage.TransactionsParsed++
		message := creatorIntelMap(creatorIntelMap(txMap["transaction"])["message"])
		keys, signers := creatorIntelAccountKeys(message)
		actorSigned := actorDefenseContainsExact(signers, dossier.Wallet)
		observedAt := actorDefenseObservedAt(signature, txMap)
		owners := actorDefenseTokenAccountOwners(meta, keys)
		instructions := actorDefenseInstructions(message, meta)

		for index, instruction := range instructions {
			if coverage.EvidencePersisted >= coverage.EvidenceLimit {
				break
			}
			for _, item := range actorDefenseInstructionEvidence(dossier, signature, observedAt, actorSigned, instruction, owners, knownMints, relatedActors, index) {
				persist(item)
			}
		}

		if actorSigned {
			liquidity := actorDefenseLiquidityEvidence(message, meta)
			if liquidity.Found {
				transactionMints := actorDefenseKnownTransactionMints(meta, knownMints)
				verificationStatus := "observed"
				source := "solana_transaction_logs"
				scope := "parsed instruction or log observation; complete creator-to-pool evidence line not available"
				counterpartKind := "transaction"
				counterpartID := signature.Signature
				if dossier.Track.CreatedTokenCount > 0 && liquidity.Complete() && len(transactionMints) > 0 {
					verificationStatus = "verified"
					source = "solana_jsonparsed_instruction"
					scope = "creator signed parsed liquidity-removal instruction with explicit pool, program and creator-linked token mint"
					counterpartKind = "pool"
					counterpartID = liquidity.PoolWallet
				}
				tokenMint := ""
				if len(transactionMints) > 0 {
					tokenMint = transactionMints[0]
				}
				persist(services.ActorDefenseEvidenceRecord{
					Network: dossier.Network, ActorWallet: dossier.Wallet,
					CounterpartKind: counterpartKind, CounterpartID: counterpartID,
					Relation: "liquidity_remove_activity", VerificationStatus: verificationStatus,
					EvidenceKey: signature.Signature + ":liquidity_remove", Source: source,
					Signature: signature.Signature, Slot: signature.Slot, ObservedAt: observedAt,
					TokenMint: tokenMint,
					Metadata: map[string]any{
						"actor_signed":            true,
						"creator_role_observed":   dossier.Track.CreatedTokenCount > 0,
						"instruction_types":       liquidity.InstructionTypes,
						"known_transaction_mints": transactionMints,
						"source_wallet":           dossier.Wallet,
						"destination_wallet":      liquidity.PoolWallet,
						"pool_account":            liquidity.PoolWallet,
						"program":                 liquidity.Program,
						"classification_scope":    scope,
					},
				})
			}
		}
	}
	if coverage.TransactionsParsed == 0 && coverage.Status == "complete" {
		coverage.Status = "no_parsed_transactions"
	}
	if coverage.PersistenceFailures > 0 && coverage.Status == "complete" {
		coverage.Status = "partial_persistence"
	}
	coverage.Limitations = append(coverage.Limitations,
		fmt.Sprintf("Canlı kanıt taraması en fazla %d imza, %d başarılı transaction ve %d yeni kanıtla sınırlandırıldı.", coverage.SignatureLimit, coverage.TransactionLimit, coverage.EvidenceLimit),
		"Doğrudan transfer yalnız jsonParsed instruction ve token-account owner eşleşmesiyle VERIFIED olur.",
		"Creator liquidity removal yalnız actor-signed parsed removal instruction, explicit pool/program ve creator-linked mint aynı transaction'da doğrulanırsa VERIFIED olur.",
		"Solana adresleri case-sensitive karşılaştırılır.",
		"Log-only veya pool/program alanı eksik likidite kaldırma işareti OBSERVED kalır; tek başına kötü niyet kanıtı değildir.",
	)
	return coverage
}

func actorDefenseInstructionEvidence(
	dossier services.ActorDefenseDossier,
	signature services.SolanaSignatureInfo,
	observedAt time.Time,
	actorSigned bool,
	instruction map[string]any,
	owners map[string]actorDefenseTokenAccountOwner,
	knownMints map[string]bool,
	relatedActors map[string]services.ActorDefenseRelatedActor,
	index int,
) []services.ActorDefenseEvidenceRecord {
	parsed := creatorIntelMap(instruction["parsed"])
	kind := strings.ToLower(creatorIntelCleanString(parsed["type"]))
	info := creatorIntelMap(parsed["info"])
	program := strings.ToLower(creatorIntelCleanString(instruction["program"]))
	evidenceKey := fmt.Sprintf("%s:%d", signature.Signature, index)
	baseMetadata := map[string]any{"instruction_type": kind, "actor_signed": actorSigned}

	if program == "system" && kind == "transfer" {
		source := creatorIntelCleanString(info["source"])
		destination := creatorIntelCleanString(info["destination"])
		lamports := creatorIntelInt64(info["lamports"])
		if source == dossier.Wallet && destination != "" && destination != dossier.Wallet && actorSigned {
			actorDefenseApplyRelatedActorMetadata(baseMetadata, relatedActors, destination)
			return []services.ActorDefenseEvidenceRecord{{
				Network: dossier.Network, ActorWallet: dossier.Wallet,
				CounterpartKind: "wallet", CounterpartID: destination,
				Relation: "direct_sol_transfer_out", VerificationStatus: "verified",
				EvidenceKey: evidenceKey, Source: "solana_jsonparsed_instruction",
				Signature: signature.Signature, Slot: signature.Slot, ObservedAt: observedAt,
				AmountNative: float64(lamports) / 1e9, Metadata: baseMetadata,
			}}
		}
		if destination == dossier.Wallet && source != "" && source != dossier.Wallet {
			actorDefenseApplyRelatedActorMetadata(baseMetadata, relatedActors, source)
			return []services.ActorDefenseEvidenceRecord{{
				Network: dossier.Network, ActorWallet: dossier.Wallet,
				CounterpartKind: "wallet", CounterpartID: source,
				Relation: "direct_sol_transfer_in", VerificationStatus: "verified",
				EvidenceKey: evidenceKey, Source: "solana_jsonparsed_instruction",
				Signature: signature.Signature, Slot: signature.Slot, ObservedAt: observedAt,
				AmountNative: float64(lamports) / 1e9, Metadata: baseMetadata,
			}}
		}
		return nil
	}

	if !strings.Contains(program, "token") || (kind != "transfer" && kind != "transferchecked") {
		return nil
	}
	sourceAccount := creatorIntelCleanString(info["source"])
	destinationAccount := creatorIntelCleanString(info["destination"])
	authority := creatorIntelCleanString(info["authority"])
	sourceOwner := owners[sourceAccount]
	destinationOwner := owners[destinationAccount]
	mint := firstNonEmptyString(sourceOwner.Mint, destinationOwner.Mint, creatorIntelCleanString(info["mint"]))
	amount := actorDefenseTokenAmount(info)
	metadata := map[string]any{
		"actor_signed":              actorSigned,
		"authority":                 authority,
		"source_token_account":      sourceAccount,
		"destination_token_account": destinationAccount,
		"known_token":               knownMints[mint],
		"raw_amount":                creatorIntelCleanString(info["amount"]),
		"amount_scope":              actorDefenseTokenAmountScope(info),
	}
	if sourceOwner.Owner == dossier.Wallet && destinationOwner.Owner != "" && destinationOwner.Owner != dossier.Wallet && authority == dossier.Wallet && actorSigned {
		actorDefenseApplyRelatedActorMetadata(metadata, relatedActors, destinationOwner.Owner)
		return []services.ActorDefenseEvidenceRecord{{
			Network: dossier.Network, ActorWallet: dossier.Wallet,
			CounterpartKind: "wallet", CounterpartID: destinationOwner.Owner,
			Relation: "direct_token_transfer_out", VerificationStatus: "verified",
			EvidenceKey: evidenceKey, Source: "solana_jsonparsed_instruction",
			Signature: signature.Signature, Slot: signature.Slot, ObservedAt: observedAt,
			TokenMint: mint, TokenAmount: amount, Metadata: metadata,
		}}
	}
	if destinationOwner.Owner == dossier.Wallet && sourceOwner.Owner != "" && sourceOwner.Owner != dossier.Wallet {
		actorDefenseApplyRelatedActorMetadata(metadata, relatedActors, sourceOwner.Owner)
		return []services.ActorDefenseEvidenceRecord{{
			Network: dossier.Network, ActorWallet: dossier.Wallet,
			CounterpartKind: "wallet", CounterpartID: sourceOwner.Owner,
			Relation: "direct_token_transfer_in", VerificationStatus: "verified",
			EvidenceKey: evidenceKey, Source: "solana_jsonparsed_instruction",
			Signature: signature.Signature, Slot: signature.Slot, ObservedAt: observedAt,
			TokenMint: mint, TokenAmount: amount, Metadata: metadata,
		}}
	}
	return nil
}

func actorDefenseApplyRelatedActorMetadata(metadata map[string]any, actors map[string]services.ActorDefenseRelatedActor, wallet string) {
	if metadata == nil {
		return
	}
	actor, found := actors[wallet]
	dominant := found && actor.MaxPercentage >= 20
	metadata["related_actor_observed"] = found
	metadata["known_related_actor"] = dominant
	metadata["dominant_holder_relation"] = dominant
	if found {
		metadata["shared_token_count"] = actor.SharedTokenCount
		metadata["max_holder_percentage"] = actor.MaxPercentage
	}
}

func actorDefenseInstructions(message, meta map[string]any) []map[string]any {
	out := []map[string]any{}
	appendRows := func(raw any) {
		items, _ := raw.([]any)
		for _, item := range items {
			row := creatorIntelMap(item)
			if len(row) > 0 {
				out = append(out, row)
			}
		}
	}
	appendRows(message["instructions"])
	inner, _ := meta["innerInstructions"].([]any)
	for _, item := range inner {
		appendRows(creatorIntelMap(item)["instructions"])
	}
	return out
}

func actorDefenseTokenAccountOwners(meta map[string]any, keys []string) map[string]actorDefenseTokenAccountOwner {
	out := map[string]actorDefenseTokenAccountOwner{}
	collect := func(raw any) {
		items, _ := raw.([]any)
		for _, item := range items {
			row := creatorIntelMap(item)
			rawIndex, exists := row["accountIndex"]
			if !exists {
				continue
			}
			index := creatorIntelInt(rawIndex)
			if index < 0 || index >= len(keys) {
				continue
			}
			owner := creatorIntelCleanString(row["owner"])
			mint := creatorIntelCleanString(row["mint"])
			if owner != "" || mint != "" {
				out[keys[index]] = actorDefenseTokenAccountOwner{Owner: owner, Mint: mint}
			}
		}
	}
	collect(meta["preTokenBalances"])
	collect(meta["postTokenBalances"])
	return out
}

func actorDefenseKnownTransactionMints(meta map[string]any, knownMints map[string]bool) []string {
	seen := map[string]bool{}
	collect := func(raw any) {
		items, _ := raw.([]any)
		for _, item := range items {
			mint := creatorIntelCleanString(creatorIntelMap(item)["mint"])
			if mint != "" && knownMints[mint] {
				seen[mint] = true
			}
		}
	}
	collect(meta["preTokenBalances"])
	collect(meta["postTokenBalances"])
	out := make([]string, 0, len(seen))
	for mint := range seen {
		out = append(out, mint)
	}
	sort.Strings(out)
	return out
}

func actorDefenseTokenAmount(info map[string]any) float64 {
	if tokenAmount := creatorIntelMap(info["tokenAmount"]); len(tokenAmount) > 0 {
		return creatorIntelUIAmount(tokenAmount)
	}
	if raw := creatorIntelCleanString(info["uiAmountString"]); raw != "" {
		value, _ := strconv.ParseFloat(raw, 64)
		return value
	}
	// Plain SPL `transfer` exposes raw base units without decimals. Keeping the
	// UI amount at zero prevents Koschei from presenting raw units as tokens;
	// the exact raw amount remains in evidence metadata.
	return 0
}

func actorDefenseTokenAmountScope(info map[string]any) string {
	if tokenAmount := creatorIntelMap(info["tokenAmount"]); len(tokenAmount) > 0 {
		return "ui_amount"
	}
	if creatorIntelCleanString(info["uiAmountString"]) != "" {
		return "ui_amount"
	}
	return "raw_base_units_only"
}

func actorDefenseLiquidityRemoval(message, meta map[string]any) (bool, []string) {
	line := actorDefenseLiquidityEvidence(message, meta)
	return line.Found, line.InstructionTypes
}

func actorDefenseParsedLiquidityRemoval(instructionTypes []string) bool {
	for _, kind := range instructionTypes {
		value := strings.ToLower(strings.TrimSpace(kind))
		if strings.Contains(value, "removeliquidity") || strings.Contains(value, "remove_liquidity") || strings.Contains(value, "withdrawliquidity") || strings.Contains(value, "withdraw_liquidity") {
			return true
		}
	}
	return false
}

func actorDefenseObservedAt(signature services.SolanaSignatureInfo, tx map[string]any) time.Time {
	if blockTime := creatorIntelInt64(tx["blockTime"]); blockTime > 0 {
		return time.Unix(blockTime, 0).UTC()
	}
	if signature.BlockTime != nil && *signature.BlockTime > 0 {
		return time.Unix(*signature.BlockTime, 0).UTC()
	}
	return time.Now().UTC()
}

func actorDefenseContainsExact(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func actorDefenseEnvInt(name string, fallback, minimum, maximum int) int {
	value := fallback
	if raw := strings.TrimSpace(os.Getenv(name)); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			value = parsed
		}
	}
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}
