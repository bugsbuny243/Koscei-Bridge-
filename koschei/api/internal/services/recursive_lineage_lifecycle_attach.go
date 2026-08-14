package services

import "strings"

func AttachRecursiveLineageLifecycle(lineage RecursiveLineageTokenMerge, wallets []RecursiveLineageWalletMemory) RecursiveLineageTokenMerge {
	byWalletMint := map[string]RecursiveLineageLifecycleReference{}
	for _, walletMemory := range wallets {
		wallet := strings.TrimSpace(walletMemory.Seed.Wallet)
		if wallet == "" {
			continue
		}
		for _, reference := range walletMemory.Lifecycle.References {
			mint := strings.TrimSpace(reference.Mint)
			if mint == "" {
				continue
			}
			key := recursiveLineageLifecycleKey(wallet, mint)
			existing, ok := byWalletMint[key]
			if !ok || recursiveLineageLifecycleReferenceRank(reference) > recursiveLineageLifecycleReferenceRank(existing) {
				byWalletMint[key] = reference
			}
		}
	}

	for tokenIndex := range lineage.RelatedTokens {
		mint := strings.TrimSpace(lineage.RelatedTokens[tokenIndex].Mint)
		for roleIndex := range lineage.RelatedTokens[tokenIndex].WalletRoles {
			role := &lineage.RelatedTokens[tokenIndex].WalletRoles[roleIndex]
			wallet := strings.TrimSpace(role.Wallet)
			reference, ok := byWalletMint[recursiveLineageLifecycleKey(wallet, mint)]
			if !ok {
				continue
			}
			copyReference := reference
			role.Lifecycle = &copyReference
			if role.CreatorSignature == "" && copyReference.CreationSignature != "" {
				role.CreatorSignature = copyReference.CreationSignature
			}
			if recursiveLineageEvidenceRank(copyReference.EvidenceStatus) > recursiveLineageEvidenceRank(role.EvidenceStatus) {
				role.EvidenceStatus = copyReference.EvidenceStatus
			}
		}
	}
	return lineage
}

func recursiveLineageLifecycleKey(wallet, mint string) string {
	return strings.TrimSpace(wallet) + "\x00" + strings.TrimSpace(mint)
}

func recursiveLineageLifecycleReferenceRank(reference RecursiveLineageLifecycleReference) int {
	rank := recursiveLineageEvidenceRank(reference.EvidenceStatus) * 10
	if reference.ReferenceComplete {
		rank += 2
	}
	if reference.CreationSignature != "" && reference.CreationSlot > 0 {
		rank++
	}
	return rank
}
