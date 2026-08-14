package services

import (
	"fmt"
	"testing"
	"time"
)

func TestMergeRecursiveLineageTokenHistoryDeduplicatesCurrentMintAndRoles(t *testing.T) {
	now := time.Now().UTC()
	inputs := []RecursiveLineageWalletDossier{
		{
			Seed: RecursiveLineageSeed{Wallet: "wallet-a", Roles: []string{"creator_deployer"}, EvidenceStatus: "observed"},
			Dossier: ActorDefenseDossier{Tokens: []ActorDefenseTokenObservation{
				{Mint: "current", Roles: []string{"creator_deployer"}, LastObservedAt: now},
				{Mint: "token-b", Roles: []string{"creator_deployer"}, CreatorSignature: "sig-b", FirstObservedAt: now.Add(-time.Hour), LastObservedAt: now},
				{Mint: "token-b", Roles: []string{"trader"}, FirstObservedAt: now.Add(-2 * time.Hour), LastObservedAt: now.Add(time.Minute)},
			}},
		},
		{
			Seed: RecursiveLineageSeed{Wallet: "wallet-b", Roles: []string{"primary_funder"}, EvidenceStatus: "verified"},
			Dossier: ActorDefenseDossier{Tokens: []ActorDefenseTokenObservation{
				{Mint: "token-b", Roles: []string{"dominant_holder"}, LastObservedAt: now.Add(-time.Minute)},
			}},
		},
	}
	merged := MergeRecursiveLineageTokenHistory("current", inputs)
	if len(merged.RelatedTokens) != 1 || merged.RelatedTokens[0].Mint != "token-b" {
		t.Fatalf("expected only token-b after current-mint dedupe: %#v", merged.RelatedTokens)
	}
	if len(merged.RelatedTokens[0].WalletRoles) != 2 {
		t.Fatalf("expected two wallet relations for token-b: %#v", merged.RelatedTokens[0].WalletRoles)
	}
	first := merged.RelatedTokens[0].WalletRoles[0]
	if first.Wallet != "wallet-a" {
		t.Fatalf("wallet relations must be deterministic: %#v", merged.RelatedTokens[0].WalletRoles)
	}
	roles := map[string]bool{}
	for _, role := range first.TokenRoles {
		roles[role] = true
	}
	if !roles["creator_deployer"] || !roles["trader"] {
		t.Fatalf("duplicate wallet/token observations should merge token roles: %#v", first.TokenRoles)
	}
	if first.CreatorSignature != "sig-b" {
		t.Fatalf("creator signature provenance should survive merge: %#v", first)
	}
}

func TestMergeRecursiveLineageTokenHistoryEnforcesPerSeedAndGlobalBounds(t *testing.T) {
	inputs := []RecursiveLineageWalletDossier{}
	for walletIndex := 0; walletIndex < 30; walletIndex++ {
		tokens := []ActorDefenseTokenObservation{}
		for tokenIndex := 0; tokenIndex < 25; tokenIndex++ {
			tokens = append(tokens, ActorDefenseTokenObservation{
				Mint: fmt.Sprintf("token-%02d-%02d", walletIndex, tokenIndex),
				Roles: []string{"trader"},
				LastObservedAt: time.Unix(int64(100000-walletIndex*100-tokenIndex), 0).UTC(),
			})
		}
		inputs = append(inputs, RecursiveLineageWalletDossier{
			Seed: RecursiveLineageSeed{Wallet: fmt.Sprintf("wallet-%02d", walletIndex), Roles: []string{"critical_holder"}, EvidenceStatus: "observed"},
			Dossier: ActorDefenseDossier{Tokens: tokens},
		})
	}
	merged := MergeRecursiveLineageTokenHistory("", inputs)
	if merged.Complete {
		t.Fatalf("hitting wallet/token bounds must mark recursive lineage incomplete")
	}
	if merged.WalletsProcessed != MaxRecursiveLineageSynchronousWallets {
		t.Fatalf("expected %d processed wallets, got %d", MaxRecursiveLineageSynchronousWallets, merged.WalletsProcessed)
	}
	if len(merged.RelatedTokens) != MaxRecursiveLineageRelatedTokens {
		t.Fatalf("expected %d related tokens after global cap, got %d", MaxRecursiveLineageRelatedTokens, len(merged.RelatedTokens))
	}
}
