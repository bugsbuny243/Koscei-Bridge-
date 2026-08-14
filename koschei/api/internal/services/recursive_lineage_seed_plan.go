package services

import (
	"sort"
	"strings"
)

const MaxRecursiveLineageHolderSeeds = 20

type RecursiveLineageSeed struct {
	Wallet         string   `json:"wallet"`
	Roles          []string `json:"roles"`
	EvidenceStatus string   `json:"evidence_status"`
	HolderRank     int      `json:"holder_rank,omitempty"`
	Reasons        []string `json:"reasons"`
}

type RecursiveLineageSeedPlan struct {
	Seeds                    []RecursiveLineageSeed `json:"seeds"`
	HolderCandidatesObserved int                    `json:"holder_candidates_observed"`
	HolderSeedsIncluded      int                    `json:"holder_seeds_included"`
	Complete                 bool                   `json:"complete"`
	Limitations              []string               `json:"limitations"`
}

func BuildRecursiveLineageSeedPlan(creator string, funding ActorFundingOrigin, holders HolderIntelligence) RecursiveLineageSeedPlan {
	creator = strings.TrimSpace(creator)
	out := RecursiveLineageSeedPlan{
		Seeds:       []RecursiveLineageSeed{},
		Complete:    true,
		Limitations: []string{},
	}
	indexByWallet := map[string]int{}
	add := func(seed RecursiveLineageSeed) {
		seed.Wallet = strings.TrimSpace(seed.Wallet)
		if seed.Wallet == "" {
			return
		}
		seed.Roles = uniqueSortedRecursiveLineageStrings(seed.Roles)
		seed.Reasons = uniqueSortedRecursiveLineageStrings(seed.Reasons)
		if index, ok := indexByWallet[seed.Wallet]; ok {
			existing := &out.Seeds[index]
			existing.Roles = uniqueSortedRecursiveLineageStrings(append(existing.Roles, seed.Roles...))
			existing.Reasons = uniqueSortedRecursiveLineageStrings(append(existing.Reasons, seed.Reasons...))
			if recursiveLineageEvidenceRank(seed.EvidenceStatus) > recursiveLineageEvidenceRank(existing.EvidenceStatus) {
				existing.EvidenceStatus = seed.EvidenceStatus
			}
			if existing.HolderRank == 0 || (seed.HolderRank > 0 && seed.HolderRank < existing.HolderRank) {
				existing.HolderRank = seed.HolderRank
			}
			return
		}
		indexByWallet[seed.Wallet] = len(out.Seeds)
		out.Seeds = append(out.Seeds, seed)
	}

	if creator != "" {
		add(RecursiveLineageSeed{
			Wallet:         creator,
			Roles:          []string{"creator_deployer"},
			EvidenceStatus: "observed",
			Reasons:        []string{"resolved_creator_wallet"},
		})
	}

	if recursiveLineageFundingVerified(funding) {
		add(RecursiveLineageSeed{
			Wallet:         strings.TrimSpace(funding.SourceWallet),
			Roles:          []string{"primary_funder"},
			EvidenceStatus: "verified",
			Reasons:        []string{"verified_funding_origin"},
		})
	}

	rows := append([]HolderIntelligenceRow(nil), holders.Rows...)
	sort.SliceStable(rows, func(i, j int) bool {
		left, right := rows[i].Rank, rows[j].Rank
		if left <= 0 {
			left = int(^uint(0) >> 1)
		}
		if right <= 0 {
			right = int(^uint(0) >> 1)
		}
		if left != right {
			return left < right
		}
		return strings.TrimSpace(rows[i].OwnerWallet) < strings.TrimSpace(rows[j].OwnerWallet)
	})

	for _, row := range rows {
		if !recursiveLineageHolderEligible(row) {
			continue
		}
		out.HolderCandidatesObserved++
		if out.HolderSeedsIncluded >= MaxRecursiveLineageHolderSeeds {
			out.Complete = false
			continue
		}
		reasons := recursiveLineageHolderReasons(row)
		before := len(out.Seeds)
		add(RecursiveLineageSeed{
			Wallet:         row.OwnerWallet,
			Roles:          []string{"critical_holder"},
			EvidenceStatus: "observed",
			HolderRank:     row.Rank,
			Reasons:        reasons,
		})
		if len(out.Seeds) > before || recursiveLineageSeedHasRole(out.Seeds, strings.TrimSpace(row.OwnerWallet), "critical_holder") {
			out.HolderSeedsIncluded++
		}
	}
	if out.HolderCandidatesObserved > MaxRecursiveLineageHolderSeeds {
		out.Limitations = append(out.Limitations, "Critical-holder seed selection was capped at 20 wallets; additional eligible holders may exist outside this bounded view.")
	}
	return out
}

func recursiveLineageFundingVerified(funding ActorFundingOrigin) bool {
	return strings.TrimSpace(funding.SourceWallet) != "" &&
		strings.EqualFold(strings.TrimSpace(funding.VerificationStatus), "verified") &&
		strings.TrimSpace(funding.Signature) != "" && funding.Slot > 0 && !funding.ObservedAt.IsZero()
}

func recursiveLineageHolderEligible(row HolderIntelligenceRow) bool {
	if !row.OwnerResolved || !row.RiskBearing || row.ExcludedFromHolderRisk || strings.TrimSpace(row.OwnerWallet) == "" {
		return false
	}
	return row.ParsedTransactions > 0 || row.CommonExitObserved || row.RepeatDominantHolder || row.LaunchCreatorLinked || strings.TrimSpace(row.FundingSource) != ""
}

func recursiveLineageHolderReasons(row HolderIntelligenceRow) []string {
	out := []string{}
	if row.ParsedTransactions > 0 {
		out = append(out, "parsed_transaction_evidence")
	}
	if row.CommonExitObserved {
		out = append(out, "common_exit_evidence")
	}
	if row.RepeatDominantHolder {
		out = append(out, "repeat_dominant_holder_history")
	}
	if row.LaunchCreatorLinked {
		out = append(out, "launch_creator_linkage")
	}
	if strings.TrimSpace(row.FundingSource) != "" {
		out = append(out, "funding_source_observed")
	}
	return uniqueSortedRecursiveLineageStrings(out)
}

func recursiveLineageEvidenceRank(status string) int {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "verified":
		return 2
	case "observed":
		return 1
	default:
		return 0
	}
}

func recursiveLineageSeedHasRole(seeds []RecursiveLineageSeed, wallet, role string) bool {
	for _, seed := range seeds {
		if seed.Wallet != wallet {
			continue
		}
		for _, candidate := range seed.Roles {
			if candidate == role {
				return true
			}
		}
	}
	return false
}

func uniqueSortedRecursiveLineageStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
