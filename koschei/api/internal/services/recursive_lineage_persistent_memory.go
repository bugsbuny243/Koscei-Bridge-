package services

import (
	"context"
	"strings"
	"time"
)

const RecursiveLineageVersion = "koschei-radar-recursive-lineage-v1"

type RecursiveLineageWalletMemory struct {
	Seed      RecursiveLineageSeed              `json:"seed"`
	Available bool                              `json:"available"`
	Status    string                            `json:"status"`
	Tokens    []ActorDefenseTokenObservation   `json:"tokens"`
	Lifecycle RecursiveLineageLifecycleReport  `json:"lifecycle"`
	Coverage  map[string]any                    `json:"coverage"`
}

type RecursiveLineagePersistentMemoryReport struct {
	Version       string                         `json:"version"`
	Status        string                         `json:"status"`
	Complete      bool                           `json:"complete"`
	Network       string                         `json:"network"`
	CurrentMint   string                         `json:"current_mint"`
	SeedPlan      RecursiveLineageSeedPlan       `json:"seed_plan"`
	Wallets       []RecursiveLineageWalletMemory `json:"wallets"`
	TokenLineage  RecursiveLineageTokenMerge     `json:"token_lineage"`
	FailedWallets []string                       `json:"failed_wallets"`
	GeneratedAt   time.Time                      `json:"generated_at"`
	Limitations   []string                       `json:"limitations"`
	Policy        map[string]any                 `json:"policy"`
}

func LoadRecursiveLineagePersistentMemory(ctx context.Context, store *ActorDefenseStore, currentMint, network string, plan RecursiveLineageSeedPlan) RecursiveLineagePersistentMemoryReport {
	currentMint = strings.TrimSpace(currentMint)
	network = normalizeRadarNetwork(network)
	out := RecursiveLineagePersistentMemoryReport{
		Version: RecursiveLineageVersion, Status: "persistent_memory_available", Complete: plan.Complete,
		Network: network, CurrentMint: currentMint, SeedPlan: plan, Wallets: []RecursiveLineageWalletMemory{},
		FailedWallets: []string{}, GeneratedAt: time.Now().UTC(), Limitations: append([]string(nil), plan.Limitations...),
		Policy: map[string]any{
			"real_world_identity_claim":  false,
			"same_operator_claim":        false,
			"wrongdoing_claim":           false,
			"verdict_authority":          false,
			"grade_authority":            false,
			"guard_block_authority":      false,
			"no_evidence_no_claim":       true,
			"bounded_persistent_history": true,
			"synchronous_rpc_fanout":     false,
			"read_path_mutates_store":    false,
		},
	}
	if store == nil || store.DB == nil {
		out.Status = "persistent_memory_unavailable"
		out.Complete = false
		out.Limitations = append(out.Limitations, "Persistent actor database is unavailable; recursive wallet history was not materialized.")
		out.TokenLineage = RecursiveLineageTokenMerge{RelatedTokens: []RecursiveLineageRelatedToken{}, Complete: false, Limitations: []string{"Persistent actor database is unavailable."}}
		return out
	}

	seeds := append([]RecursiveLineageSeed(nil), plan.Seeds...)
	if len(seeds) > MaxRecursiveLineageSynchronousWallets {
		seeds = seeds[:MaxRecursiveLineageSynchronousWallets]
		out.Complete = false
		out.Limitations = append(out.Limitations, "Recursive wallet materialization was capped at 25 seed wallets.")
	}
	mergeInputs := make([]RecursiveLineageWalletDossier, 0, len(seeds))
	for _, seed := range seeds {
		wallet := strings.TrimSpace(seed.Wallet)
		if wallet == "" {
			continue
		}
		history, err := store.LoadBoundedRecursiveTokenHistory(ctx, wallet, network, MaxRecursiveLineageTokensPerSeed)
		if err != nil {
			out.Complete = false
			out.FailedWallets = append(out.FailedWallets, wallet)
			out.Wallets = append(out.Wallets, RecursiveLineageWalletMemory{
				Seed: seed, Available: false, Status: "persistent_history_unavailable", Coverage: map[string]any{}, Tokens: []ActorDefenseTokenObservation{},
				Lifecycle: RecursiveLineageLifecycleReport{Wallet: wallet, Network: network, Complete: false, References: []RecursiveLineageLifecycleReference{}, Limitations: []string{"Persistent token history was unavailable."}},
			})
			continue
		}
		if !history.Complete {
			out.Complete = false
			out.Limitations = append(out.Limitations, history.Limitations...)
		}
		lifecycle := RecursiveLineageLifecycleReport{Wallet: wallet, Network: network, Complete: true, References: []RecursiveLineageLifecycleReference{}, Limitations: []string{}}
		if recursiveLineageHistoryHasCreatorRole(history.Tokens) {
			loadedLifecycle, lifecycleErr := store.LoadBoundedRecursiveLifecycle(ctx, wallet, network, currentMint, MaxRecursiveLineageTokensPerSeed)
			if lifecycleErr != nil {
				out.Complete = false
				lifecycle.Complete = false
				lifecycle.Limitations = append(lifecycle.Limitations, "Creator lifecycle provenance could not be loaded for this seed wallet.")
			} else {
				lifecycle = loadedLifecycle
				if !lifecycle.Complete {
					out.Complete = false
					out.Limitations = append(out.Limitations, lifecycle.Limitations...)
				}
			}
		}
		out.Wallets = append(out.Wallets, RecursiveLineageWalletMemory{
			Seed: seed, Available: true, Status: "bounded_persistent_history_loaded",
			Tokens: append([]ActorDefenseTokenObservation(nil), history.Tokens...), Lifecycle: lifecycle,
			Coverage: map[string]any{
				"complete": history.Complete,
				"evidence_rows_read": history.EvidenceRowsRead,
				"trade_groups_read": history.TradeGroupsRead,
				"token_count": len(history.Tokens),
				"lifecycle_reference_count": len(lifecycle.References),
			},
		})
		mergeInputs = append(mergeInputs, RecursiveLineageWalletDossier{
			Seed: seed, Dossier: ActorDefenseDossier{Wallet: wallet, Network: network, Tokens: history.Tokens},
		})
	}
	out.FailedWallets = uniqueSortedRecursiveLineageStrings(out.FailedWallets)
	if len(out.FailedWallets) > 0 {
		out.Status = "persistent_memory_partial"
		out.Limitations = append(out.Limitations, "One or more seed-wallet persistent histories could not be loaded; no clean/safe claim was inferred from missing history.")
	}
	out.TokenLineage = MergeRecursiveLineageTokenHistory(currentMint, mergeInputs)
	out.TokenLineage = AttachRecursiveLineageLifecycle(out.TokenLineage, out.Wallets)
	if !out.TokenLineage.Complete {
		out.Complete = false
		out.Limitations = append(out.Limitations, out.TokenLineage.Limitations...)
	}
	out.Limitations = uniqueSortedRecursiveLineageStrings(out.Limitations)
	return out
}

func recursiveLineageHistoryHasCreatorRole(tokens []ActorDefenseTokenObservation) bool {
	for _, token := range tokens {
		for _, role := range token.Roles {
			if strings.TrimSpace(role) == "creator_deployer" {
				return true
			}
		}
	}
	return false
}
