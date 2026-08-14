package services

import (
	"context"
	"strings"
	"time"
)

const RecursiveLineageVersion = "koschei-radar-recursive-lineage-v1"

type RecursiveLineageWalletMemory struct {
	Seed      RecursiveLineageSeed            `json:"seed"`
	Available bool                            `json:"available"`
	Status    string                          `json:"status"`
	Track     ActorDefenseTrack               `json:"track"`
	Tokens    []ActorDefenseTokenObservation `json:"tokens"`
	Coverage  map[string]any                  `json:"coverage"`
}

type RecursiveLineagePersistentMemoryReport struct {
	Version       string                         `json:"version"`
	Status        string                         `json:"status"`
	Complete      bool                           `json:"complete"`
	CurrentMint   string                         `json:"current_mint"`
	SeedPlan      RecursiveLineageSeedPlan       `json:"seed_plan"`
	Wallets       []RecursiveLineageWalletMemory `json:"wallets"`
	TokenLineage  RecursiveLineageTokenMerge     `json:"token_lineage"`
	FailedWallets []string                       `json:"failed_wallets"`
	GeneratedAt   time.Time                      `json:"generated_at"`
	Limitations   []string                       `json:"limitations"`
	Policy        map[string]any                 `json:"policy"`
}

func LoadRecursiveLineagePersistentMemory(ctx context.Context, store *ActorDefenseStore, currentMint string, plan RecursiveLineageSeedPlan) RecursiveLineagePersistentMemoryReport {
	currentMint = strings.TrimSpace(currentMint)
	out := RecursiveLineagePersistentMemoryReport{
		Version: RecursiveLineageVersion, Status: "persistent_memory_available", Complete: plan.Complete,
		CurrentMint: currentMint, SeedPlan: plan, Wallets: []RecursiveLineageWalletMemory{},
		FailedWallets: []string{}, GeneratedAt: time.Now().UTC(), Limitations: append([]string(nil), plan.Limitations...),
		Policy: map[string]any{
			"real_world_identity_claim": false,
			"same_operator_claim":       false,
			"wrongdoing_claim":          false,
			"verdict_authority":         false,
			"grade_authority":           false,
			"guard_block_authority":     false,
			"no_evidence_no_claim":      true,
			"bounded_persistent_history": true,
			"synchronous_rpc_fanout":    false,
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
		dossier, err := store.LoadPersistentWalletDossier(ctx, wallet, "solana-mainnet", 200)
		if err != nil {
			out.Complete = false
			out.FailedWallets = append(out.FailedWallets, wallet)
			out.Wallets = append(out.Wallets, RecursiveLineageWalletMemory{
				Seed: seed, Available: false, Status: "persistent_dossier_unavailable", Coverage: map[string]any{}, Tokens: []ActorDefenseTokenObservation{},
			})
			continue
		}
		tokens := append([]ActorDefenseTokenObservation(nil), dossier.Tokens...)
		if len(tokens) > MaxRecursiveLineageTokensPerSeed {
			tokens = tokens[:MaxRecursiveLineageTokensPerSeed]
			out.Complete = false
		}
		out.Wallets = append(out.Wallets, RecursiveLineageWalletMemory{
			Seed: seed, Available: true, Status: "persistent_dossier_loaded",
			Track: dossier.Track, Tokens: tokens, Coverage: dossier.Coverage,
		})
		mergeInputs = append(mergeInputs, RecursiveLineageWalletDossier{Seed: seed, Dossier: dossier})
	}
	out.FailedWallets = uniqueSortedRecursiveLineageStrings(out.FailedWallets)
	if len(out.FailedWallets) > 0 {
		out.Status = "persistent_memory_partial"
		out.Limitations = append(out.Limitations, "One or more seed-wallet persistent dossiers could not be loaded; no clean/safe claim was inferred from missing history.")
	}
	out.TokenLineage = MergeRecursiveLineageTokenHistory(currentMint, mergeInputs)
	if !out.TokenLineage.Complete {
		out.Complete = false
		out.Limitations = append(out.Limitations, out.TokenLineage.Limitations...)
	}
	out.Limitations = uniqueSortedRecursiveLineageStrings(out.Limitations)
	return out
}
