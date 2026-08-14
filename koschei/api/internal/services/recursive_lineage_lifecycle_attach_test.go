package services

import (
	"testing"
	"time"
)

func TestAttachRecursiveLineageLifecycleBindsExactWalletAndMint(t *testing.T) {
	now := time.Now().UTC()
	lineage := RecursiveLineageTokenMerge{
		Complete: true,
		RelatedTokens: []RecursiveLineageRelatedToken{
			{Mint: "mint-a", WalletRoles: []RecursiveLineageTokenWalletRole{
				{Wallet: "wallet-a", EvidenceStatus: "observed", TokenRoles: []string{"creator_deployer"}},
				{Wallet: "wallet-b", EvidenceStatus: "observed", TokenRoles: []string{"dominant_holder"}},
			}},
			{Mint: "mint-b", WalletRoles: []RecursiveLineageTokenWalletRole{
				{Wallet: "wallet-a", EvidenceStatus: "observed", TokenRoles: []string{"trader"}},
			}},
		},
	}
	wallets := []RecursiveLineageWalletMemory{
		{
			Seed: RecursiveLineageSeed{Wallet: "wallet-a"},
			Lifecycle: RecursiveLineageLifecycleReport{References: []RecursiveLineageLifecycleReference{
				{ActorWallet: "wallet-a", Mint: "mint-a", CreationSignature: "sig-a", CreationSlot: 42, FirstObservedAt: now.Add(-time.Hour), LastObservedAt: now, FateStatus: "active", EvidenceStatus: "verified", ReferenceComplete: true},
			}},
		},
		{
			Seed: RecursiveLineageSeed{Wallet: "wallet-b"},
			Lifecycle: RecursiveLineageLifecycleReport{References: []RecursiveLineageLifecycleReference{
				{ActorWallet: "wallet-b", Mint: "mint-b", CreationSignature: "sig-wrong", CreationSlot: 99, FirstObservedAt: now.Add(-time.Hour), LastObservedAt: now, FateStatus: "inactive_or_dead", EvidenceStatus: "verified", ReferenceComplete: true},
			}},
		},
	}

	got := AttachRecursiveLineageLifecycle(lineage, wallets)
	roleA := got.RelatedTokens[0].WalletRoles[0]
	if roleA.Lifecycle == nil || roleA.Lifecycle.CreationSignature != "sig-a" || roleA.Lifecycle.CreationSlot != 42 {
		t.Fatalf("exact wallet+mint lifecycle provenance was not attached: %#v", roleA)
	}
	if roleA.EvidenceStatus != "verified" || roleA.CreatorSignature != "sig-a" {
		t.Fatalf("verified lifecycle should strengthen only that wallet-token row: %#v", roleA)
	}
	roleB := got.RelatedTokens[0].WalletRoles[1]
	if roleB.Lifecycle != nil || roleB.CreatorSignature != "" || roleB.EvidenceStatus != "observed" {
		t.Fatalf("wallet-b mint-b provenance must not leak onto wallet-b mint-a: %#v", roleB)
	}
	mintBWalletA := got.RelatedTokens[1].WalletRoles[0]
	if mintBWalletA.Lifecycle != nil {
		t.Fatalf("wallet-b lifecycle must not leak onto wallet-a for the same mint: %#v", mintBWalletA)
	}
}
