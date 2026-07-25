package handlers

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"koschei/api/internal/services"
)

type actorAcceptanceEnrichmentCoverage struct {
	Status               string   `json:"status"`
	MintsDiscovered      int      `json:"mints_discovered"`
	MintsAttempted       int      `json:"mints_attempted"`
	MintsCompleted       int      `json:"mints_completed"`
	RecipientsResolved   int      `json:"recipients_resolved"`
	HolderComparisons    int      `json:"holder_comparisons"`
	EvidencePersisted    int      `json:"evidence_persisted"`
	PersistenceFailures  int      `json:"persistence_failures"`
	MintLimit            int      `json:"mint_limit"`
	TimeoutSeconds       int      `json:"timeout_seconds"`
	Limitations          []string `json:"limitations"`
}

// collectActorAcceptanceDistribution runs the already-existing mint-specific
// recipient collector as part of the live acceptance route. It never crawls a
// recipient wallet's broad signature history. Top-holder comparison is produced
// by the same bounded mint investigation and persisted on each evidence row.
func (h *Handler) collectActorAcceptanceDistribution(ctx context.Context, store *services.ActorDefenseStore, dossier services.ActorDefenseDossier) actorAcceptanceEnrichmentCoverage {
	coverage := actorAcceptanceEnrichmentCoverage{
		Status:         "not_investigated",
		MintLimit:      actorDefenseEnvInt("ACTOR_ACCEPTANCE_DISTRIBUTION_MINT_LIMIT", 3, 1, 20),
		TimeoutSeconds: actorDefenseEnvInt("ACTOR_ACCEPTANCE_DISTRIBUTION_TIMEOUT_SECONDS", 120, 30, 240),
		Limitations:    []string{},
	}
	if store == nil || store.DB == nil {
		coverage.Status = "database_unavailable"
		coverage.Limitations = append(coverage.Limitations, "Actor evidence store is unavailable.")
		return coverage
	}
	rpcURL := creatorIntelRPCURL()
	if strings.TrimSpace(rpcURL) == "" {
		coverage.Status = "rpc_unavailable"
		coverage.Limitations = append(coverage.Limitations, "Solana RPC is not configured; distribution enrichment was not run.")
		return coverage
	}

	creatorTokens := make([]services.ActorDefenseTokenObservation, 0, len(dossier.Tokens))
	seen := map[string]bool{}
	for _, token := range dossier.Tokens {
		mint := strings.TrimSpace(token.Mint)
		if mint == "" || seen[mint] || !actorAcceptanceTokenHasRole(token, "creator_deployer") {
			continue
		}
		seen[mint] = true
		creatorTokens = append(creatorTokens, token)
	}
	sort.SliceStable(creatorTokens, func(i, j int) bool {
		if !creatorTokens[i].LastObservedAt.Equal(creatorTokens[j].LastObservedAt) {
			return creatorTokens[i].LastObservedAt.After(creatorTokens[j].LastObservedAt)
		}
		return creatorTokens[i].Mint < creatorTokens[j].Mint
	})
	coverage.MintsDiscovered = len(creatorTokens)
	if len(creatorTokens) == 0 {
		coverage.Status = "no_creator_mints"
		coverage.Limitations = append(coverage.Limitations, "No creator_deployer mint was available for bounded distribution enrichment.")
		return coverage
	}
	if len(creatorTokens) > coverage.MintLimit {
		coverage.Limitations = append(coverage.Limitations, fmt.Sprintf("Only the newest %d of %d creator mints were enriched in this request.", coverage.MintLimit, len(creatorTokens)))
		creatorTokens = creatorTokens[:coverage.MintLimit]
	}

	enrichmentCtx, cancel := context.WithTimeout(ctx, time.Duration(coverage.TimeoutSeconds)*time.Second)
	defer cancel()
	for _, token := range creatorTokens {
		if enrichmentCtx.Err() != nil {
			coverage.Limitations = append(coverage.Limitations, "Distribution enrichment time budget was exhausted before every selected mint completed.")
			break
		}
		coverage.MintsAttempted++
		report := services.InvestigateActorInitialRecipients(
			enrichmentCtx,
			rpcURL,
			dossier.Wallet,
			token.Mint,
			token.CreatorSignature,
			services.ActorInitialRecipientOptions{
				MaxRecipients:        actorDefenseEnvInt("ACTOR_RECIPIENT_LIMIT", 20, 1, 20),
				SignaturePageSize:    actorDefenseEnvInt("ACTOR_RECIPIENT_SIGNATURE_PAGE_SIZE", 250, 50, 1000),
				MaxPagesPerTokenATA:  actorDefenseEnvInt("ACTOR_RECIPIENT_MAX_PAGES_PER_ATA", 8, 1, 20),
				MaxTransactionsParse: actorDefenseEnvInt("ACTOR_RECIPIENT_TRANSACTION_LIMIT", 160, 10, 500),
			},
		)
		coverage.RecipientsResolved += len(report.Recipients)
		if actorAcceptanceHolderComparisonAvailable(report.TopHolderStatus) {
			coverage.HolderComparisons += len(report.Recipients)
		}
		if actorAcceptanceDistributionCompleted(report.Status) {
			coverage.MintsCompleted++
		}
		for _, limitation := range report.Limitations {
			limitation = strings.TrimSpace(limitation)
			if limitation != "" {
				coverage.Limitations = append(coverage.Limitations, fmt.Sprintf("%s: %s", token.Mint, limitation))
			}
		}
		for _, evidence := range services.ActorInitialRecipientEvidence(report, dossier.Network) {
			if evidence.Metadata == nil {
				evidence.Metadata = map[string]any{}
			}
			evidence.Metadata["top_holder_status"] = report.TopHolderStatus
			evidence.Metadata["recipient_report_status"] = report.Status
			evidence.Metadata["acceptance_auto_enrichment"] = true
			if err := store.UpsertEvidence(enrichmentCtx, evidence); err != nil {
				coverage.PersistenceFailures++
				continue
			}
			coverage.EvidencePersisted++
		}
	}

	switch {
	case coverage.MintsAttempted == 0:
		coverage.Status = "not_completed"
	case enrichmentCtx.Err() != nil:
		coverage.Status = "partial_timeout"
	case coverage.PersistenceFailures > 0:
		coverage.Status = "partial_persistence"
	case coverage.MintsAttempted < coverage.MintsDiscovered:
		coverage.Status = "partial_mint_limit"
	case coverage.MintsCompleted == coverage.MintsAttempted:
		coverage.Status = "complete"
	default:
		coverage.Status = "partial"
	}
	return coverage
}

func actorAcceptanceTokenHasRole(token services.ActorDefenseTokenObservation, role string) bool {
	for _, candidate := range token.Roles {
		if strings.EqualFold(strings.TrimSpace(candidate), strings.TrimSpace(role)) {
			return true
		}
	}
	return false
}

func actorAcceptanceHolderComparisonAvailable(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "verified_role_resolution", "dominant_holder_role_unresolved":
		return true
	default:
		return false
	}
}

func actorAcceptanceDistributionCompleted(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "initial_recipients_resolved", "recipient_window_resolved", "no_creator_distribution_observed":
		return true
	default:
		return false
	}
}
