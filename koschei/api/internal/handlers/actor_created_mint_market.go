package handlers

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"koschei/api/internal/services"
)

const actorTokenFateMarketDataUnavailable = "market_data_unavailable"

type actorTokenMarketFate struct {
	Status            string
	Reason            string
	EvidenceAvailable bool
	LifecycleEligible bool
}

func applyActorTokenMarketSnapshot(candidate *services.ActorCreatedMintCandidate, market services.TokenMarketSnapshot) actorTokenMarketFate {
	out := actorTokenMarketFate{Status: actorTokenFateMarketDataUnavailable, Reason: "market snapshot was not produced"}
	if candidate == nil {
		return out
	}
	candidate.MarketEvidenceStatus = strings.TrimSpace(market.Status)
	candidate.CurrentLiquidityUSD = market.LiquidityUSD
	candidate.CurrentPriceUSD = market.PriceUSD

	switch market.Status {
	case "verified_market_snapshot":
		candidate.LiquidityEvidenceAvailable = true
		out.EvidenceAvailable = true
		out.LifecycleEligible = true
		if market.LiquidityUSD > 0 {
			out.Status = services.ActorTokenFateActive
			out.Reason = "positive aggregate Solana pair liquidity was returned by the market provider"
		} else {
			out.Status = services.ActorTokenFateInactiveOrDead
			out.Reason = "the verified market snapshot returned Solana pairs with zero aggregate liquidity"
		}
	case "no_solana_pairs":
		candidate.LiquidityEvidenceAvailable = true
		out.EvidenceAvailable = true
		out.LifecycleEligible = true
		out.Status = services.ActorTokenFateInactiveOrDead
		out.Reason = "the market provider returned no Solana pair for this mint; this is not proof that no unindexed venue exists"
	default:
		out.Status = actorTokenFateMarketDataUnavailable
		status := strings.TrimSpace(market.Status)
		if status == "" {
			status = "market_unavailable"
		}
		out.Reason = "market evidence unavailable: " + status
	}
	candidate.FateStatus = out.Status
	candidate.FateReason = out.Reason
	return out
}

type actorTokenMarketSnapshotFetcher func(context.Context, string) services.TokenMarketSnapshot

func (h *Handler) appendObservedCreatorLaunchCandidates(ctx context.Context, out *actorCreatedMintIntegrationRun, wallet, network string) {
	observed, _ := h.creatorIntelObservedLaunches(ctx, "", network, wallet)
	appendObservedCreatorLaunchRows(ctx, out, observed, services.FetchSolanaTokenMarketSnapshot)
}

func appendObservedCreatorLaunchRows(ctx context.Context, out *actorCreatedMintIntegrationRun, observed []map[string]any, fetch actorTokenMarketSnapshotFetcher) {
	if out == nil || len(observed) == 0 {
		return
	}
	if fetch == nil {
		fetch = func(context.Context, string) services.TokenMarketSnapshot {
			return services.TokenMarketSnapshot{Status: "market_fetcher_unavailable"}
		}
	}
	seen := map[string]bool{}
	for _, candidate := range out.Discovery.Candidates {
		if mint := strings.TrimSpace(candidate.Mint); mint != "" {
			seen[mint] = true
		}
	}
	for _, candidate := range out.VerifiedCandidates {
		if mint := strings.TrimSpace(candidate.Mint); mint != "" {
			seen[mint] = true
		}
	}

	for _, item := range observed {
		mint := strings.TrimSpace(fmt.Sprint(item["target"]))
		if mint == "" || mint == "<nil>" || seen[mint] {
			continue
		}
		seen[mint] = true
		candidate := services.ActorCreatedMintCandidate{
			Mint:               mint,
			Signature:          strings.TrimSpace(fmt.Sprint(item["signature"])),
			InstructionType:    "observed_launch",
			VerificationStatus: "koschei_observed",
			Source:             "koschei_observation_store",
		}
		if candidate.Signature == "<nil>" {
			candidate.Signature = ""
		}
		switch value := item["observed_at"].(type) {
		case time.Time:
			candidate.ObservedAt = value.UTC()
		case string:
			if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value)); err == nil {
				candidate.ObservedAt = parsed.UTC()
			}
		}
		market := fetch(ctx, mint)
		fate := applyActorTokenMarketSnapshot(&candidate, market)
		switch fate.Status {
		case services.ActorTokenFateActive:
			out.LiquidCandidates++
		case services.ActorTokenFateInactiveOrDead:
			out.InactiveOrDeadCandidates++
		default:
			out.MarketDataUnavailableCandidates++
			out.Limitations = append(out.Limitations, "Observed creator launch "+mint+" için piyasa sağlayıcısı sonuç üretmedi; token ölü olarak sınıflandırılmadı ("+candidate.MarketEvidenceStatus+").")
		}
		out.Discovery.Candidates = append(out.Discovery.Candidates, candidate)
		out.ObservedStoreCandidatesMerged++
	}
	if out.ObservedStoreCandidatesMerged == 0 {
		return
	}
	sort.SliceStable(out.Discovery.Candidates, func(i, j int) bool {
		left, right := out.Discovery.Candidates[i], out.Discovery.Candidates[j]
		if !left.ObservedAt.Equal(right.ObservedAt) {
			return left.ObservedAt.After(right.ObservedAt)
		}
		return left.Mint < right.Mint
	})
	out.Discovery.Available = true
	if strings.TrimSpace(out.Discovery.Provider) == "" {
		out.Discovery.Provider = "koschei_observation_store"
	} else if !strings.Contains(out.Discovery.Provider, "koschei_observation_store") {
		out.Discovery.Provider += "+koschei_observation_store"
	}
	if out.CandidatesVerified > 0 {
		out.Status = "verified_plus_observed"
	} else if out.CandidatesRequested > 0 {
		out.Status = "observed_plus_verification_failed"
	} else {
		out.Status = "observed_only"
	}
}
