package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"koschei/api/internal/services"
)

type actorCreatedMintIntegrationRun struct {
	Status                          string                                    `json:"status"`
	Discovery                       services.SolscanCreatedMintDiscovery      `json:"discovery"`
	ObservedEvidenceProduced        int                                       `json:"observed_evidence_produced"`
	ObservedEvidencePersisted       int                                       `json:"observed_evidence_persisted"`
	CandidatesRequested             int                                       `json:"candidates_requested"`
	CandidatesVerified              int                                       `json:"candidates_verified"`
	LiquidCandidates                int                                       `json:"liquid_candidates"`
	InactiveOrDeadCandidates        int                                       `json:"inactive_or_dead_candidates"`
	MarketDataUnavailableCandidates int                                       `json:"market_data_unavailable_candidates"`
	ObservedStoreCandidatesMerged   int                                       `json:"observed_store_candidates_merged"`
	LifecycleSummary                services.ActorTokenLifecycleSummary       `json:"lifecycle_summary"`
	LifecycleObservations           []services.ActorTokenLifecycleObservation `json:"lifecycle_observations"`
	LifecycleObservationsPersisted  int                                       `json:"lifecycle_observations_persisted"`
	LifecyclePersistenceFailures    int                                       `json:"lifecycle_persistence_failures"`
	VerificationFailures            int                                       `json:"verification_failures"`
	VerifiedEvidencePersisted       int                                       `json:"verified_evidence_persisted"`
	PersistenceFailures             int                                       `json:"persistence_failures"`
	VerifiedCandidates              []services.ActorCreatedMintCandidate      `json:"verified_candidates"`
	Limitations                     []string                                  `json:"limitations"`
}

func newActorCreatedMintIntegrationRun(wallet string) actorCreatedMintIntegrationRun {
	return actorCreatedMintIntegrationRun{
		Status: "not_requested",
		Discovery: services.SolscanCreatedMintDiscovery{
			Status: "not_requested", Provider: "solscan_enhanced_transactions",
			Wallet: strings.TrimSpace(wallet), Candidates: []services.ActorCreatedMintCandidate{}, Limitations: []string{},
		},
		LifecycleSummary:      services.SummarizeActorTokenLifecycles(nil),
		LifecycleObservations: []services.ActorTokenLifecycleObservation{},
		VerifiedCandidates:    []services.ActorCreatedMintCandidate{},
		Limitations:           []string{},
	}
}

// collectActorCreatedMintPortfolio uses bounded external discovery providers to
// find candidate transactions. Each candidate is re-read from the canonical Solana
// RPC and must independently satisfy the signer + create/initializeMint parser
// before it becomes VERIFIED actor evidence.
func (h *Handler) collectActorCreatedMintPortfolio(ctx context.Context, store *services.ActorDefenseStore, wallet, network string) actorCreatedMintIntegrationRun {
	wallet = strings.TrimSpace(wallet)
	out := newActorCreatedMintIntegrationRun(wallet)
	if wallet == "" {
		out.Status = "wallet_required"
		out.Limitations = append(out.Limitations, "Created-mint portfolio için creator wallet zorunludur.")
		return out
	}

	// Helius birincil keşif kaynağıdır. Solscan Pro key gerektirir ve 401
	// verdiğinde keşfi bozuyordu; Koschei zaten Helius kullanıyor.
	out.Discovery = services.FetchHeliusCreatedMintDiscovery(ctx, strings.TrimSpace(creatorIntelRPCURL()), wallet)
	out.Status = out.Discovery.Status
	out.Limitations = append(out.Limitations, out.Discovery.Limitations...)
	// Observation-store launches are merged before any Helius/RPC early return.
	// They remain OBSERVED and never enter the canonical verification queue.
	h.appendObservedCreatorLaunchCandidates(ctx, &out, wallet, network)
	observedEvidence := services.ActorCreatedMintCandidateEvidence(wallet, network, out.Discovery.Candidates)
	out.ObservedEvidenceProduced = len(observedEvidence)
	if store != nil {
		for _, item := range observedEvidence {
			if err := store.UpsertEvidence(ctx, item); err != nil {
				out.PersistenceFailures++
				continue
			}
			out.ObservedEvidencePersisted++
		}
	} else if len(observedEvidence) > 0 {
		out.Limitations = append(out.Limitations, "Created-mint adayları bulundu ancak actor evidence store kullanılamıyor.")
	}
	if len(out.Discovery.Candidates) == 0 {
		return out
	}

	rpcURL := strings.TrimSpace(creatorIntelRPCURL())
	if rpcURL == "" {
		out.Status = "rpc_verification_unavailable"
		if out.ObservedStoreCandidatesMerged > 0 {
			out.Status = "observed_only_rpc_verification_unavailable"
		}
		out.Limitations = append(out.Limitations, "Created-mint adayları keşif sağlayıcısından bulundu ancak doğrulama RPC'si yapılandırılmamış.")
		return out
	}
	verifyLimit := actorDefenseEnvInt("ACTOR_CREATED_MINT_VERIFY_LIMIT", 40, 1, 200)
	candidates := actorCreatedMintVerificationCandidates(out.Discovery.Candidates)
	if len(candidates) > verifyLimit {
		candidates = candidates[:verifyLimit]
		out.Limitations = append(out.Limitations, "Created-mint doğrulaması bu çalışmada ilk "+creatorIntelCleanString(verifyLimit)+" adayla sınırlandı; kalan adaylar OBSERVED olarak korundu.")
	}
	out.CandidatesRequested = len(candidates)
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			out.Limitations = append(out.Limitations, "Created-mint RPC doğrulaması request context sona erdiği için kısmi kaldı.")
			break
		}
		if strings.TrimSpace(candidate.Signature) == "" {
			out.VerificationFailures++
			continue
		}
		tx, err := services.SolanaGetTransactionJSONParsed(ctx, rpcURL, candidate.Signature)
		if err != nil {
			out.VerificationFailures++
			continue
		}
		verifiedRows := services.ExtractActorCreatedMintCandidates(
			[]map[string]any{map[string]any(tx)},
			wallet,
			"solana_jsonparsed_instruction",
		)
		verified := services.ActorCreatedMintCandidate{}
		for _, row := range verifiedRows {
			if strings.TrimSpace(row.Mint) == strings.TrimSpace(candidate.Mint) {
				verified = row
				break
			}
		}
		if strings.TrimSpace(verified.Mint) == "" {
			out.VerificationFailures++
			continue
		}
		verified.VerificationStatus = "verified"
		verified.Source = "solana_jsonparsed_instruction"

		// DexScreener snapshot gerçek Solana pair likiditesini ve en likit
		// pair'in referans fiyatını sağlar. Jupiter yalnızca fiyat fallback'idir.
		market := services.FetchSolanaTokenMarketSnapshot(ctx, verified.Mint)
		fate := applyActorTokenMarketSnapshot(&verified, market)
		if verified.CurrentPriceUSD <= 0 {
			mkt := collectJupiterMarketContext(ctx, nil, &http.Client{Timeout: 8 * time.Second}, network, verified.Mint, services.HolderIntelligence{}, market)
			if mkt.PriceAvailable {
				verified.CurrentPriceUSD = mkt.PriceUSD
			}
		}
		switch fate.Status {
		case services.ActorTokenFateActive:
			out.LiquidCandidates++
		case services.ActorTokenFateInactiveOrDead:
			out.InactiveOrDeadCandidates++
		default:
			out.MarketDataUnavailableCandidates++
			out.Limitations = append(out.Limitations, "Verified mint "+verified.Mint+" için piyasa sağlayıcısı sonuç üretmedi; token ölü olarak sınıflandırılmadı ("+verified.MarketEvidenceStatus+").")
		}

		if fate.LifecycleEligible {
			createdOnChainAt := verified.ObservedAt
			if createdOnChainAt.IsZero() && verified.BlockTime > 0 {
				createdOnChainAt = time.Unix(verified.BlockTime, 0).UTC()
			}
			observedAt := market.ObservedAt
			if observedAt.IsZero() {
				observedAt = time.Now().UTC()
			}
			lifecycleInput := services.ActorTokenLifecycleInput{
				Network:             network,
				ActorWallet:         wallet,
				Mint:                verified.Mint,
				CreationSignature:   verified.Signature,
				CreationSlot:        verified.Slot,
				CreatedOnChainAt:    createdOnChainAt,
				ObservedAt:          observedAt,
				CurrentLiquidityUSD: verified.CurrentLiquidityUSD,
				CurrentPriceUSD:     verified.CurrentPriceUSD,
			}
			lifecycle := services.BuildActorTokenLifecycleSnapshot(lifecycleInput)
			if store != nil {
				persisted, persistErr := store.UpsertTokenLifecycleObservation(ctx, lifecycleInput)
				if persistErr != nil {
					out.LifecyclePersistenceFailures++
				} else {
					lifecycle = persisted
					out.LifecycleObservationsPersisted++
				}
			}
			out.LifecycleObservations = append(out.LifecycleObservations, lifecycle)
		}

		out.CandidatesVerified++
		out.VerifiedCandidates = append(out.VerifiedCandidates, verified)
		for _, evidence := range services.ActorCreatedMintCandidateEvidence(wallet, network, []services.ActorCreatedMintCandidate{verified}) {
			if store == nil {
				out.PersistenceFailures++
				continue
			}
			if err := store.UpsertEvidence(ctx, evidence); err != nil {
				out.PersistenceFailures++
				continue
			}
			out.VerifiedEvidencePersisted++
		}
	}

	out.LifecycleSummary = services.SummarizeActorTokenLifecycles(out.LifecycleObservations)
	if out.LifecyclePersistenceFailures > 0 {
		out.Limitations = append(out.Limitations, "Güncel token akıbeti hesaplandı ancak bazı lifecycle gözlemleri kalıcı geçmişe yazılamadı; ortalama ömür yalnız eldeki kanıtlanmış geçiş örneklerini kullanır.")
	}

	switch {
	case out.CandidatesVerified == out.CandidatesRequested && out.CandidatesRequested > 0 && out.PersistenceFailures == 0:
		if out.ObservedStoreCandidatesMerged > 0 {
			out.Status = "verified_plus_observed"
		} else {
			out.Status = "verified"
		}
	case out.CandidatesVerified > 0:
		if out.ObservedStoreCandidatesMerged > 0 {
			out.Status = "partially_verified_plus_observed"
		} else {
			out.Status = "partially_verified"
		}
	case out.CandidatesRequested > 0:
		if out.ObservedStoreCandidatesMerged > 0 {
			out.Status = "observed_plus_verification_failed"
		} else {
			out.Status = "verification_failed"
		}
	}

	return out
}
