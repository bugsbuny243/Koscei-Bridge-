package services

import (
	"sort"
	"strings"
	"time"
)

const (
	MaxRecursiveLineageSynchronousWallets = 25
	MaxRecursiveLineageRelatedTokens      = 100
	MaxRecursiveLineageTokensPerSeed      = 20
)

type RecursiveLineageTokenWalletRole struct {
	Wallet           string   `json:"wallet"`
	SeedRoles        []string `json:"seed_roles"`
	TokenRoles       []string `json:"token_roles"`
	EvidenceStatus   string   `json:"evidence_status"`
	FirstObservedAt  string   `json:"first_observed_at,omitempty"`
	LastObservedAt   string   `json:"last_observed_at,omitempty"`
	CreatorSignature string   `json:"creator_signature,omitempty"`
}

type RecursiveLineageRelatedToken struct {
	Mint        string                            `json:"mint"`
	WalletRoles []RecursiveLineageTokenWalletRole `json:"wallet_roles"`
}

type RecursiveLineageTokenMerge struct {
	RelatedTokens    []RecursiveLineageRelatedToken `json:"related_tokens"`
	WalletsProcessed int                            `json:"wallets_processed"`
	Complete         bool                           `json:"complete"`
	Limitations      []string                       `json:"limitations"`
}

type RecursiveLineageWalletDossier struct {
	Seed    RecursiveLineageSeed
	Dossier ActorDefenseDossier
}

func MergeRecursiveLineageTokenHistory(currentMint string, inputs []RecursiveLineageWalletDossier) RecursiveLineageTokenMerge {
	currentMint = strings.TrimSpace(currentMint)
	out := RecursiveLineageTokenMerge{RelatedTokens: []RecursiveLineageRelatedToken{}, Complete: true, Limitations: []string{}}
	if len(inputs) > MaxRecursiveLineageSynchronousWallets {
		inputs = inputs[:MaxRecursiveLineageSynchronousWallets]
		out.Complete = false
		out.Limitations = append(out.Limitations, "Wallet dossier materialization was capped at 25 seed wallets.")
	}
	byMint := map[string]map[string]RecursiveLineageTokenWalletRole{}
	for _, input := range inputs {
		wallet := strings.TrimSpace(input.Seed.Wallet)
		if wallet == "" {
			continue
		}
		out.WalletsProcessed++
		tokens := append([]ActorDefenseTokenObservation(nil), input.Dossier.Tokens...)
		sort.SliceStable(tokens, func(i, j int) bool {
			if !tokens[i].LastObservedAt.Equal(tokens[j].LastObservedAt) {
				return tokens[i].LastObservedAt.After(tokens[j].LastObservedAt)
			}
			return strings.TrimSpace(tokens[i].Mint) < strings.TrimSpace(tokens[j].Mint)
		})
		if len(tokens) > MaxRecursiveLineageTokensPerSeed {
			tokens = tokens[:MaxRecursiveLineageTokensPerSeed]
			out.Complete = false
		}
		for _, token := range tokens {
			mint := strings.TrimSpace(token.Mint)
			if mint == "" || mint == currentMint {
				continue
			}
			wallets := byMint[mint]
			if wallets == nil {
				wallets = map[string]RecursiveLineageTokenWalletRole{}
				byMint[mint] = wallets
			}
			row := RecursiveLineageTokenWalletRole{
				Wallet: wallet, SeedRoles: append([]string(nil), input.Seed.Roles...),
				TokenRoles: append([]string(nil), token.Roles...), EvidenceStatus: input.Seed.EvidenceStatus,
				CreatorSignature: strings.TrimSpace(token.CreatorSignature),
			}
			if !token.FirstObservedAt.IsZero() {
				row.FirstObservedAt = token.FirstObservedAt.UTC().Format(time.RFC3339)
			}
			if !token.LastObservedAt.IsZero() {
				row.LastObservedAt = token.LastObservedAt.UTC().Format(time.RFC3339)
			}
			if existing, ok := wallets[wallet]; ok {
				row.SeedRoles = uniqueSortedRecursiveLineageStrings(append(existing.SeedRoles, row.SeedRoles...))
				row.TokenRoles = uniqueSortedRecursiveLineageStrings(append(existing.TokenRoles, row.TokenRoles...))
				if recursiveLineageEvidenceRank(existing.EvidenceStatus) > recursiveLineageEvidenceRank(row.EvidenceStatus) {
					row.EvidenceStatus = existing.EvidenceStatus
				}
				if row.CreatorSignature == "" {
					row.CreatorSignature = existing.CreatorSignature
				}
				if row.FirstObservedAt == "" || (existing.FirstObservedAt != "" && existing.FirstObservedAt < row.FirstObservedAt) {
					row.FirstObservedAt = existing.FirstObservedAt
				}
				if existing.LastObservedAt > row.LastObservedAt {
					row.LastObservedAt = existing.LastObservedAt
				}
			}
			wallets[wallet] = row
		}
	}

	mints := make([]string, 0, len(byMint))
	for mint := range byMint {
		mints = append(mints, mint)
	}
	sort.Strings(mints)
	if len(mints) > MaxRecursiveLineageRelatedTokens {
		mints = mints[:MaxRecursiveLineageRelatedTokens]
		out.Complete = false
		out.Limitations = append(out.Limitations, "Related-token lineage was capped at 100 unique mints.")
	}
	for _, mint := range mints {
		walletMap := byMint[mint]
		walletNames := make([]string, 0, len(walletMap))
		for wallet := range walletMap {
			walletNames = append(walletNames, wallet)
		}
		sort.Strings(walletNames)
		item := RecursiveLineageRelatedToken{Mint: mint, WalletRoles: []RecursiveLineageTokenWalletRole{}}
		for _, wallet := range walletNames {
			item.WalletRoles = append(item.WalletRoles, walletMap[wallet])
		}
		out.RelatedTokens = append(out.RelatedTokens, item)
	}
	if !out.Complete {
		out.Limitations = append(out.Limitations, "Recursive lineage is a bounded view; omitted wallet/token history may exist outside configured synchronous budgets.")
	}
	return out
}
