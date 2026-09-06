package handlers

import (
	"sort"
	"strings"
	"time"

	"koschei/api/internal/services"
)

const creatorTokenObservedPathsSchemaVersion = "koschei-creator-token-observed-paths-v1"

type creatorTokenObservedPath struct {
	Mint string `json:"mint"`

	CreatorWallet string `json:"creator_wallet"`

	Counterparty string `json:"counterparty"`

	CounterpartyKind string `json:"counterparty_kind"`

	CounterpartyRiskFlag string `json:"counterparty_risk_flag,omitempty"`

	Signature string `json:"signature"`

	Slot int64 `json:"slot"`

	ObservedAt time.Time `json:"observed_at"`

	TokenAmount float64 `json:"token_amount,omitempty"`

	LifecycleFate string `json:"lifecycle_fate"`

	LifecycleStatus string `json:"lifecycle_status"`

	CurrentLiquidityUSD float64 `json:"current_liquidity_usd"`

	VerificationStatus string `json:"verification_status"`

	TransferClaim string `json:"transfer_claim"`

	SaleClaimed bool `json:"sale_claimed"`

	RugClaimed bool `json:"rug_claimed"`

	WrongdoingClaimed bool `json:"wrongdoing_claimed"`
}

type creatorTokenObservedPathsReport struct {
	SchemaVersion string `json:"schema_version"`

	Status string `json:"status"`

	CreatorWallet string `json:"creator_wallet"`

	VerifiedCreatorTokenCount int `json:"verified_creator_token_count"`

	ObservedPathCount int `json:"observed_path_count"`

	ClassifiedEndpointCount int `json:"classified_endpoint_count"`

	UnknownEndpointCount int `json:"unknown_endpoint_count"`

	Paths []creatorTokenObservedPath `json:"paths"`

	Limitations []string `json:"limitations"`

	Policy map[string]any `json:"policy"`
}

func newCreatorTokenObservedPathsReport(wallet string) creatorTokenObservedPathsReport {
	out := creatorTokenObservedPathsReport{}
	out.SchemaVersion = creatorTokenObservedPathsSchemaVersion
	out.Status = "no_verified_creator_token_outbound_path"
	out.CreatorWallet = strings.TrimSpace(wallet)
	out.Paths = []creatorTokenObservedPath{}
	out.Limitations = []string{}
	out.Policy = map[string]any{}
	out.Policy["verified_creator_mint_only"] = true
	out.Policy["verified_direct_transfer_only"] = true
	out.Policy["verified_provider_endpoint_taxonomy_only"] = true
	out.Policy["transfer_is_not_sale"] = true
	out.Policy["lifecycle_state_is_not_causation"] = true
	out.Policy["sale_claimed"] = false
	out.Policy["rug_claimed"] = false
	out.Policy["wrongdoing_claimed"] = false
	out.Policy["numeric_probability_disabled"] = true
	out.Policy["neon_persistence"] = false
	return out
}

// buildCreatorTokenObservedPaths joins only already-collected evidence. A path
// exists when the investigated wallet has a verified creator-linked mint and a
// decoded outbound SPL transfer for that same mint. Endpoint classification is
// attached only when provider-verified taxonomy is already available.
func buildCreatorTokenObservedPaths(wallet string, portfolio actorCreatedMintIntegrationRun, flow addressFlowReport, interactions addressInteractionsReport, outcomes creatorOutcomeHistoryReport) creatorTokenObservedPathsReport {
	out := newCreatorTokenObservedPathsReport(wallet)
	verifiedMints := map[string]bool{}
	for _, candidate := range portfolio.VerifiedCandidates {
		mint := strings.TrimSpace(candidate.Mint)
		if mint != "" {
			verifiedMints[mint] = true
		}
	}
	out.VerifiedCreatorTokenCount = len(verifiedMints)
	if len(verifiedMints) == 0 {
		out.Limitations = append(out.Limitations, "No verified creator-linked mint was available, so creator-token movement paths were withheld.")
		return out
	}

	interactionByAddress := map[string]addressInteraction{}
	for _, interaction := range interactions.Interactions {
		interactionByAddress[strings.TrimSpace(interaction.Address)] = interaction
	}
	outcomeByMint := map[string]creatorTokenOutcome{}
	for _, outcome := range outcomes.Outcomes {
		outcomeByMint[strings.TrimSpace(outcome.Mint)] = outcome
	}

	seen := map[string]bool{}
	for _, transfer := range flow.Transfers {
		mint := strings.TrimSpace(transfer.TokenMint)
		counterparty := strings.TrimSpace(transfer.Counterparty)
		signature := strings.TrimSpace(transfer.Signature)
		if transfer.Direction != "outbound" || transfer.AssetType != "SPL_TOKEN" || !verifiedMints[mint] {
			continue
		}
		if counterparty == "" || signature == "" || transfer.Slot <= 0 || transfer.ObservedAt.IsZero() {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(transfer.VerificationStatus), "verified") {
			continue
		}
		key := mint + "\x00" + signature + "\x00" + counterparty
		if seen[key] {
			continue
		}
		seen[key] = true

		path := creatorTokenObservedPath{}
		path.Mint = mint
		path.CreatorWallet = strings.TrimSpace(wallet)
		path.Counterparty = counterparty
		path.CounterpartyKind = services.WalletEntityKindUnknown
		path.Signature = signature
		path.Slot = transfer.Slot
		path.ObservedAt = transfer.ObservedAt
		path.TokenAmount = transfer.TokenAmount
		path.VerificationStatus = "verified_creator_mint_plus_direct_outbound_transfer"
		path.TransferClaim = "creator_wallet_outbound_token_transfer_observed"
		path.SaleClaimed = false
		path.RugClaimed = false
		path.WrongdoingClaimed = false

		if interaction, ok := interactionByAddress[counterparty]; ok && interaction.Verification == "provider_verified_taxonomy_and_direct_onchain_flow" {
			path.CounterpartyKind = strings.TrimSpace(interaction.InteractionKind)
			path.CounterpartyRiskFlag = strings.TrimSpace(interaction.RiskFlag)
			if path.CounterpartyKind == "" {
				path.CounterpartyKind = services.WalletEntityKindUnknown
			}
		}
		if outcome, ok := outcomeByMint[mint]; ok {
			path.LifecycleFate = strings.TrimSpace(outcome.FateStatus)
			path.LifecycleStatus = strings.TrimSpace(outcome.LifecycleStatus)
			path.CurrentLiquidityUSD = outcome.CurrentLiquidityUSD
		}
		out.Paths = append(out.Paths, path)
		if path.CounterpartyKind == services.WalletEntityKindUnknown {
			out.UnknownEndpointCount++
		} else {
			out.ClassifiedEndpointCount++
		}
	}

	sort.SliceStable(out.Paths, func(i, j int) bool {
		if out.Paths[i].ObservedAt.Equal(out.Paths[j].ObservedAt) {
			if out.Paths[i].Mint == out.Paths[j].Mint {
				return out.Paths[i].Signature < out.Paths[j].Signature
			}
			return out.Paths[i].Mint < out.Paths[j].Mint
		}
		return out.Paths[i].ObservedAt.Before(out.Paths[j].ObservedAt)
	})
	out.ObservedPathCount = len(out.Paths)

	switch {
	case out.ObservedPathCount > 0 && out.ClassifiedEndpointCount > 0:
		out.Status = "verified_creator_token_paths_with_classified_endpoints"
	case out.ObservedPathCount > 0:
		out.Status = "verified_creator_token_paths_observed"
	}
	if !flow.FlowComplete {
		out.Limitations = append(out.Limitations, "Direct fund-flow coverage is bounded; additional creator-token transfers may exist outside the decoded window.")
	}
	out.Limitations = append(out.Limitations,
		"An outbound creator-token transfer is not by itself proof of a sale, liquidity removal, exit, rug pull, common control, or wrongdoing.",
		"A token lifecycle state observed after or before a transfer does not prove that the transfer caused that state.",
	)
	return out
}
