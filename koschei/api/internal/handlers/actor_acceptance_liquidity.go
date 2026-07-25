package handlers

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"koschei/api/internal/services"
)

type actorAcceptanceLiquidityCoverage struct {
	Status              string   `json:"status"`
	SignaturesSeen      int      `json:"signatures_seen"`
	TransactionsParsed  int      `json:"transactions_parsed"`
	InstructionsMatched int      `json:"instructions_matched"`
	EvidencePersisted   int      `json:"evidence_persisted"`
	RPCFailures         int      `json:"rpc_failures"`
	PersistenceFailures int      `json:"persistence_failures"`
	SignatureLimit      int      `json:"signature_limit"`
	TransactionLimit    int      `json:"transaction_limit"`
	TimeoutSeconds      int      `json:"timeout_seconds"`
	Limitations         []string `json:"limitations"`
}

type actorAcceptanceLiquidityLine struct {
	Action      string
	Program     string
	PoolWallet  string
	Authority   string
	Instruction string
}

// collectActorAcceptanceLiquidity searches only the investigated creator
// wallet's bounded transaction window. It accepts explicit parsed liquidity
// instructions with a pool, program and creator-linked mint. Logs and account
// position alone never become a canonical pool claim.
func (h *Handler) collectActorAcceptanceLiquidity(ctx context.Context, store *services.ActorDefenseStore, dossier services.ActorDefenseDossier) actorAcceptanceLiquidityCoverage {
	coverage := actorAcceptanceLiquidityCoverage{
		Status:           "not_investigated",
		SignatureLimit:   actorDefenseEnvInt("ACTOR_ACCEPTANCE_LIQUIDITY_SIGNATURE_LIMIT", 160, 20, 500),
		TransactionLimit: actorDefenseEnvInt("ACTOR_ACCEPTANCE_LIQUIDITY_TRANSACTION_LIMIT", 80, 10, 200),
		TimeoutSeconds:   actorDefenseEnvInt("ACTOR_ACCEPTANCE_LIQUIDITY_TIMEOUT_SECONDS", 120, 30, 240),
		Limitations:      []string{},
	}
	if store == nil || store.DB == nil {
		coverage.Status = "database_unavailable"
		coverage.Limitations = append(coverage.Limitations, "Actor evidence store is unavailable.")
		return coverage
	}
	rpcURL := creatorIntelRPCURL()
	if strings.TrimSpace(rpcURL) == "" {
		coverage.Status = "rpc_unavailable"
		coverage.Limitations = append(coverage.Limitations, "Solana RPC is not configured; liquidity enrichment was not run.")
		return coverage
	}

	knownMints := map[string]bool{}
	for _, token := range dossier.Tokens {
		mint := strings.TrimSpace(token.Mint)
		if mint != "" && actorAcceptanceTokenHasRole(token, "creator_deployer") {
			knownMints[mint] = true
		}
	}
	if len(knownMints) == 0 {
		coverage.Status = "no_creator_mints"
		coverage.Limitations = append(coverage.Limitations, "No creator_deployer mint was available for liquidity enrichment.")
		return coverage
	}

	workerCtx, cancel := context.WithTimeout(ctx, time.Duration(coverage.TimeoutSeconds)*time.Second)
	defer cancel()
	signatures, err := services.SolanaGetSignaturesForAddress(workerCtx, rpcURL, dossier.Wallet, coverage.SignatureLimit)
	if err != nil {
		coverage.Status = "rpc_failed"
		coverage.RPCFailures++
		coverage.Limitations = append(coverage.Limitations, "Creator wallet signatures could not be fetched: "+creatorIntelCompactError(err))
		return coverage
	}
	coverage.SignaturesSeen = len(signatures)

	for _, signature := range signatures {
		if coverage.TransactionsParsed >= coverage.TransactionLimit || workerCtx.Err() != nil {
			break
		}
		if signature.Err != nil || strings.TrimSpace(signature.Signature) == "" {
			continue
		}
		tx, txErr := services.SolanaGetTransactionJSONParsed(workerCtx, rpcURL, signature.Signature)
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
		_, signers := creatorIntelAccountKeys(message)
		if !actorDefenseContainsExact(signers, dossier.Wallet) {
			continue
		}
		transactionMints := actorDefenseKnownTransactionMints(meta, knownMints)
		if len(transactionMints) == 0 {
			continue
		}
		observedAt := actorDefenseObservedAt(signature, txMap)
		for index, instruction := range actorDefenseInstructions(message, meta) {
			line, ok := actorAcceptanceParsedLiquidityLine(instruction, dossier.Wallet)
			if !ok {
				continue
			}
			coverage.InstructionsMatched++
			verificationStatus := "observed"
			if line.Authority != "" && line.Authority == dossier.Wallet {
				verificationStatus = "verified"
			}
			for _, mint := range transactionMints {
				relation := "liquidity_" + line.Action + "_activity"
				evidenceKey := fmt.Sprintf("%s:liquidity:%s:%d:%s", signature.Signature, line.Action, index, mint)
				item := services.ActorDefenseEvidenceRecord{
					Network: dossier.Network, ActorWallet: dossier.Wallet,
					CounterpartKind: "pool", CounterpartID: line.PoolWallet,
					Relation: relation, VerificationStatus: verificationStatus,
					EvidenceKey: evidenceKey, Source: "solana_jsonparsed_instruction",
					Signature: signature.Signature, Slot: signature.Slot, ObservedAt: observedAt,
					TokenMint: mint,
					Metadata: map[string]any{
						"actor_signed": true,
						"authority": line.Authority,
						"instruction_type": line.Instruction,
						"source_wallet": dossier.Wallet,
						"destination_wallet": line.PoolWallet,
						"pool_account": line.PoolWallet,
						"program": line.Program,
						"creator_linked_mint": mint,
						"classification_scope": "actor-signed explicit parsed liquidity instruction with pool, program and creator-linked mint",
						"acceptance_auto_enrichment": true,
					},
				}
				if err := store.UpsertEvidence(workerCtx, item); err != nil {
					coverage.PersistenceFailures++
					continue
				}
				coverage.EvidencePersisted++
			}
		}
	}

	switch {
	case workerCtx.Err() != nil:
		coverage.Status = "partial_timeout"
		coverage.Limitations = append(coverage.Limitations, "Liquidity worker exhausted its bounded time budget.")
	case coverage.PersistenceFailures > 0:
		coverage.Status = "partial_persistence"
	case coverage.InstructionsMatched > 0 && coverage.EvidencePersisted > 0:
		coverage.Status = "complete_with_evidence"
	case coverage.TransactionsParsed > 0:
		coverage.Status = "complete_no_explicit_liquidity_observed"
	default:
		coverage.Status = "no_parsed_transactions"
	}
	coverage.Limitations = append(coverage.Limitations,
		fmt.Sprintf("Liquidity enrichment was bounded to %d signatures, %d parsed transactions and %d seconds.", coverage.SignatureLimit, coverage.TransactionLimit, coverage.TimeoutSeconds),
		"Only explicit parsed add/increase or remove/decrease instructions with pool and program fields are accepted.",
		"Log-only markers and opaque account-array positions do not become canonical liquidity claims.",
	)
	return coverage
}

func actorAcceptanceParsedLiquidityLine(instruction map[string]any, actorWallet string) (actorAcceptanceLiquidityLine, bool) {
	parsed := creatorIntelMap(instruction["parsed"])
	kind := strings.ToLower(strings.TrimSpace(creatorIntelCleanString(parsed["type"])))
	action := actorAcceptanceLiquidityAction(kind)
	if action == "" {
		return actorAcceptanceLiquidityLine{}, false
	}
	info := creatorIntelMap(parsed["info"])
	program := firstNonEmptyString(
		creatorIntelCleanString(instruction["programId"]),
		creatorIntelCleanString(instruction["program"]),
	)
	pool := firstNonEmptyString(
		creatorIntelCleanString(info["pool"]),
		creatorIntelCleanString(info["poolAccount"]),
		creatorIntelCleanString(info["poolState"]),
		creatorIntelCleanString(info["amm"]),
		creatorIntelCleanString(info["ammId"]),
		creatorIntelCleanString(info["market"]),
	)
	authority := firstNonEmptyString(
		creatorIntelCleanString(info["authority"]),
		creatorIntelCleanString(info["owner"]),
		creatorIntelCleanString(info["user"]),
		creatorIntelCleanString(info["positionOwner"]),
		creatorIntelCleanString(info["liquidityProvider"]),
	)
	if strings.TrimSpace(program) == "" || strings.TrimSpace(pool) == "" {
		return actorAcceptanceLiquidityLine{}, false
	}
	if authority != "" && authority != strings.TrimSpace(actorWallet) {
		return actorAcceptanceLiquidityLine{}, false
	}
	return actorAcceptanceLiquidityLine{Action: action, Program: program, PoolWallet: pool, Authority: authority, Instruction: kind}, true
}

func actorAcceptanceLiquidityAction(kind string) string {
	value := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(kind), "-", "_"))
	compact := strings.ReplaceAll(value, "_", "")
	addMarkers := []string{"addliquidity", "increaseliquidity", "depositalltokentypes", "depositliquidity"}
	removeMarkers := []string{"removeliquidity", "decreaseliquidity", "withdrawliquidity", "withdrawalltokentypes"}
	for _, marker := range addMarkers {
		if strings.Contains(compact, marker) {
			return "add"
		}
	}
	for _, marker := range removeMarkers {
		if strings.Contains(compact, marker) {
			return "remove"
		}
	}
	return ""
}

func actorAcceptanceSortedMints(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for mint := range values {
		out = append(out, mint)
	}
	sort.Strings(out)
	return out
}
