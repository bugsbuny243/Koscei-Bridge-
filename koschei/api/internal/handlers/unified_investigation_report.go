package handlers

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"koschei/api/internal/services"
)

const unifiedInvestigationSchemaVersion = "koschei-unified-investigation-v1"

type unifiedInvestigationAssembly struct {
	Report           map[string]any
	Core             holderIntelligenceCoreResult
	DB               *sql.DB
	Store            *services.ActorDefenseStore
	Creator          string
	ActorDossier     services.ActorDefenseDossier
	ActorTrack       services.ActorDefenseTrack
	ActorVerdict     services.ActorDefenseRuleVerdict
	Behavior         services.UnifiedRadarBehaviorReport
	UnifiedVerdict   services.UnifiedRadarVerdict
	Threat           services.ThreatAnticipationReport
	CombinedEvidence []services.ActorDefenseEvidenceRecord
	Modules          []map[string]any
	Structural       map[string]any
	Graph            any
	TradeLedger      map[string]any
	ActorStoreStatus string
}

type unifiedActorInvestigationRun struct {
	Status                   string                      `json:"status"`
	TriggeredBy              string                      `json:"triggered_by"`
	LiveRequested            bool                        `json:"live_requested"`
	FundingOrigin            services.ActorFundingOrigin `json:"funding_origin"`
	FundingOriginPersistence string                      `json:"funding_origin_persistence"`
	LiveEvidence             actorDefenseLiveCoverage    `json:"live_evidence"`
	RuleVerdictPersistence   string                      `json:"rule_verdict_persistence"`
	Limitations              []string                    `json:"limitations"`
}

// buildUnifiedInvestigationReport runs the shared evidence engine used by public,
// authenticated, owner and API callers. Caller type is intentionally absent from
// the technical result. Operational metadata is added outside Report.
func (h *Handler) buildUnifiedInvestigationReport(ctx context.Context, target, network, mode string) unifiedInvestigationAssembly {
	core := h.runHolderIntelligenceCore(ctx, target, network, mode)
	return h.assembleUnifiedInvestigationReportMode(ctx, core, mode)
}

// assembleUnifiedInvestigationReport preserves the mode embedded by the shared
// holder core. Tests with an empty mode remain stored-only and never call RPC.
func (h *Handler) assembleUnifiedInvestigationReport(ctx context.Context, core holderIntelligenceCoreResult) unifiedInvestigationAssembly {
	mode := strings.TrimSpace(core.Request.Mode)
	if mode == "" {
		mode = "stored_only_projection"
	}
	return h.assembleUnifiedInvestigationReportMode(ctx, core, mode)
}

func (h *Handler) assembleUnifiedInvestigationReportMode(ctx context.Context, core holderIntelligenceCoreResult, mode string) unifiedInvestigationAssembly {
	target := strings.TrimSpace(core.Request.Target)
	network := strings.TrimSpace(core.Request.Network)
	if network == "" {
		network = "solana-mainnet"
	}
	now := time.Now().UTC()
	creator := strings.TrimSpace(creatorIntelCleanString(core.SourceContext["creator_wallet"]))
	liveRequested := unifiedLiveEvidenceAllowed(mode)

	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	actorDossier := services.ActorDefenseDossier{
		Wallet: creator, Network: network,
		Tokens: []services.ActorDefenseTokenObservation{}, RelatedActors: []services.ActorDefenseRelatedActor{},
		Evidence: []services.ActorDefenseEvidenceRecord{}, Coverage: map[string]any{}, Policy: map[string]any{}, GeneratedAt: now,
	}
	actorTrack := services.ActorDefenseTrack{Network: network, TargetKind: "wallet", TargetID: creator, Dossier: map[string]any{}}
	actorStoreStatus := "creator_unavailable"
	creatorRelation := newActorCreatorRelationRun(creator, target)
	distributionRun := newActorDistributionIntegrationRun(creator, target)
	var store *services.ActorDefenseStore
	if db != nil && creator != "" {
		store = services.NewActorDefenseStore(db)
		if liveRequested {
			creatorRelation = h.persistCanonicalCreatorMintRelation(ctx, store, core, creator, network)
		}
		if loaded, err := store.LoadPersistentWalletDossier(ctx, creator, network, 150); err == nil {
			actorDossier, actorTrack, actorStoreStatus = loaded, loaded.Track, "loaded"
		} else {
			actorStoreStatus = "load_failed"
		}
	}

	actorRun := unifiedActorInvestigationRun{
		Status:        "not_requested",
		TriggeredBy:   "creator_discovery",
		LiveRequested: liveRequested,
		FundingOrigin: services.ActorFundingOrigin{
			Wallet: creator, Status: "not_requested", VerificationStatus: "unverified",
			TrailStatus: "not_investigated", IdentityScope: "onchain_wallet_only", Limitations: []string{},
		},
		FundingOriginPersistence: "not_requested",
		LiveEvidence:             actorDefenseLiveCoverage{Status: "not_requested", Limitations: []string{}},
		RuleVerdictPersistence:   "not_requested",
		Limitations:              []string{},
	}
	externalDiscovery := newActorExternalDiscoveryRun(creator)

	// A token scan must not stop after discovering the creator address. Full/live
	// modes invoke creator relation persistence, Solscan discovery, funding origin,
	// wallet evidence and the existing mint-specific distribution investigator.
	// Safe Check and stored-only projections remain network-call free.
	if liveRequested && creator != "" {
		externalDiscovery = h.collectActorExternalDiscovery(ctx, store, creator, network)
		actorRun.Limitations = append(actorRun.Limitations, externalDiscovery.Limitations...)
		actorRun.Limitations = append(actorRun.Limitations, creatorRelation.Limitations...)
	}
	if liveRequested {
		switch {
		case creator == "":
			actorRun.Status = "creator_unavailable"
			actorRun.Limitations = append(actorRun.Limitations, "Token taramasında doğrulanmış creator/deployer cüzdanı çözümlenemedi; actor investigation başlatılmadı.")
		case store == nil:
			actorRun.Status = "database_unavailable"
			actorRun.Limitations = append(actorRun.Limitations, "Actor evidence store kullanılamadığı için creator soruşturması kalıcı olarak çalıştırılamadı.")
		default:
			actorRun.Status = "collecting"
			actorRun.FundingOrigin, actorRun.FundingOriginPersistence = h.collectActorFundingOrigin(ctx, store, creator, network)

			// Solscan observations, current creator relation and funding evidence can
			// enrich the dossier before transaction parsing starts.
			if loaded, err := store.LoadPersistentWalletDossier(ctx, creator, network, 200); err == nil {
				actorDossier, actorTrack = loaded, loaded.Track
				actorStoreStatus = "discovery_funding_refreshed"
			} else {
				actorRun.Limitations = append(actorRun.Limitations, "Discovery ve funding-origin toplandıktan sonra actor dossier yenilenemedi.")
			}

			actorRun.LiveEvidence = h.collectActorDefenseLiveEvidence(ctx, store, actorDossier)
			distributionRun = h.collectCanonicalActorDistribution(ctx, store, creatorRelation, network)
			actorRun.Limitations = append(actorRun.Limitations, distributionRun.Limitations...)
			if loaded, err := store.LoadPersistentWalletDossier(ctx, creator, network, 200); err == nil {
				actorDossier, actorTrack = loaded, loaded.Track
				actorStoreStatus = "live_distribution_refreshed"
			} else {
				actorStoreStatus = "live_refresh_failed"
				actorRun.Limitations = append(actorRun.Limitations, "Canlı actor ve dağıtım kanıtı toplandıktan sonra kalıcı dossier yenilenemedi.")
			}

			switch actorRun.LiveEvidence.Status {
			case "complete":
				actorRun.Status = "complete"
			case "not_requested", "stored_evidence_only":
				actorRun.Status = actorRun.LiveEvidence.Status
			default:
				actorRun.Status = "partial"
			}
			if distributionRun.Status == "partial_persistence" || distributionRun.Status == "creator_mint_relation_unresolved" {
				actorRun.Status = "partial"
			}
		}
	} else if creator != "" && store != nil {
		actorRun.Status = "stored_evidence_only"
		actorRun.FundingOrigin.Status = "stored_evidence_only"
		actorRun.LiveEvidence.Status = "stored_evidence_only"
	}

	// Token-scoped live evidence remains a separate collector. Its rows enrich the
	// report but do not silently mutate deterministic rules that require explicit
	// verified actor evidence.
	tradeLedger := h.unifiedTradeLedgerAggregates(ctx, target)
	transactionEvidence := h.loadUnifiedTransactionEvidence(ctx, target, 50)
	liveEvidence := unifiedLiveInvestigationReport{
		Status: "not_requested", Mint: target, WalletCoverage: []unifiedLiveWalletCoverage{},
		Transactions: []unifiedLiveTransactionRow{}, GeneratedAt: now, Limitations: []string{},
		LaunchSigner: unifiedLaunchSignerObservation{Status: "not_requested", InstructionTypes: []string{}, Limitations: []string{}},
	}
	if liveRequested {
		liveEvidence = h.collectUnifiedTokenLiveEvidence(ctx, core)
		transactionEvidence = mergeUnifiedTransactionEvidence(transactionEvidence, unifiedLiveRowsToEvidence(liveEvidence.Transactions))
		if len(transactionEvidence) > 0 {
			tradeLedger = summarizeUnifiedTransactionEvidence(transactionEvidence)
		}
	}

	sales := services.LoadCreatorSellAcceleration(ctx, db, target, creator, now)
	storedVerification := services.CreatorSellVerification{
		CandidateSignatures: append([]string{}, sales.Signatures...), VerifiedSignatures: []string{},
		Limitations: []string{"Acceleration thresholds use the stored trade ledger; live full-scan transaction rows are reported separately and do not rewrite the rule."},
	}
	behavior := services.EvaluateUnifiedRadarBehavior(target, creator, core.Market, core.Intelligence, core.Cluster, sales, now)
	behavior = services.HardenUnifiedRadarBehavior(behavior, storedVerification, core.Cluster)
	behavior = services.ApplyOwnerConcentrationRuleV110(behavior, core.Intelligence, now)
	threat := services.BuildThreatAnticipation(services.ThreatAnticipationInput{
		Target: target, Market: core.Market, Holder: core.Intelligence, Cluster: core.Cluster,
		Arms: core.Arms, Behavior: behavior,
	})
	combinedEvidence := append([]services.ActorDefenseEvidenceRecord{}, actorDossier.Evidence...)
	combinedEvidence = append(combinedEvidence, behavior.Evidence...)
	actorVerdict := services.EvaluateActorDefenseRules(actorTrack, combinedEvidence)
	if store != nil && strings.TrimSpace(actorTrack.TargetID) != "" {
		actorRun.RuleVerdictPersistence = "persisted"
		if err := store.PersistRuleVerdict(ctx, actorTrack, actorVerdict); err != nil {
			actorRun.RuleVerdictPersistence = "failed"
			actorRun.Limitations = append(actorRun.Limitations, "Deterministik actor rule verdict kalıcı actor index'e yazılamadı.")
		}
	}
	unifiedVerdict := services.EvaluateUnifiedRadarVerdictV110(target, actorVerdict, behavior)
	if h.DB != nil {
		_ = services.CaptureHolderConcentrationObservation(ctx, h.DB, network, target, core.Intelligence, now)
	}
	holderConcentrationContext := services.LoadHolderConcentrationContext(ctx, db, core.Intelligence)
	modules := radarDetailModules(core.Arms)
	coverage := services.BuildArvisInvestigationCoverage(core.Arms)
	structural := h.radarDetailStructuralContext(ctx, target, network)
	graph := h.radarDetailGraph(ctx, target)
	evidenceReferences := buildUnifiedEvidenceReferences(core, creator, transactionEvidence, behavior, unifiedVerdict)
	evidenceReferences = applyUnifiedLiveEvidenceReferences(evidenceReferences, liveEvidence)
	evidenceReferences = applyLPControlEvidenceReferences(evidenceReferences, core.LPControl)
	evidenceReferences = applyMarketProgramEvidenceReferences(evidenceReferences, core)

	report := map[string]any{
		"ok": true, "schema_version": unifiedInvestigationSchemaVersion,
		"target": target, "network": network, "generated_at": now.Format(time.RFC3339),
		"analysis_scope": "token_plus_actor_plus_market_behavior",
		"final_verdict":  unifiedVerdict, "threat_anticipation": threat,
		"investigation_coverage": coverage, "holder_distribution": core.Distribution,
		"holder_intelligence": core.Intelligence, "holder_cluster": core.Cluster,
		"holder_concentration_context": holderConcentrationContext,
		"launch_forensics":             core.LaunchForensics, "market": core.Market,
		"lp_control": core.LPControl, "jupiter_market_context": core.JupiterContext,
		"exit_liquidity": core.ExitLiquidity, "program_security": unifiedProgramSecuritySurface(core.SourceContext),
		"source_context": core.SourceContext, "structural_memory": structural,
		"modules": modules, "evidence_arms": modules, "evidence": radarDetailEvidence(core.Arms),
		"behavior_signals": behavior, "trade_ledger_aggregates": tradeLedger,
		"transaction_evidence": transactionEvidence, "evidence_references": evidenceReferences,
		"full_scan_live_evidence": liveEvidence,
		"actor_investigation": map[string]any{
			"wallet": creator, "dossier": actorDossier, "rule_verdict": actorVerdict,
			"store_status": actorStoreStatus, "integration_run": actorRun,
			"current_creator_relation":   creatorRelation,
			"external_discovery":         externalDiscovery,
			"funding_origin":             actorRun.FundingOrigin,
			"funding_origin_persistence": actorRun.FundingOriginPersistence,
			"actor_live_evidence":        actorRun.LiveEvidence,
			"current_token_distribution": distributionRun,
			// Backward-compatible token live-wallet coverage retained for existing UI clients.
			"live_wallet_evidence":     liveEvidence.WalletCoverage,
			"rule_verdict_persistence": actorRun.RuleVerdictPersistence,
		},
		"graph":                       graph,
		"investigation_output_policy": services.SharedInvestigationOutputPolicy(),
		"evidence_policy": map[string]any{
			"numeric_final_score_disabled": true, "numeric_rug_probability_disabled": true,
			"threat_capacity_is_not_intent": true, "no_evidence_no_claim": true,
			"identity_scope": "onchain_wallet_only", "caller_type_changes_evidence": false,
			"external_attribution_is_observed_only": true,
			"recipient_full_wallet_history":         false,
			"recipient_investigation_scope":         "mint_specific_token_accounts",
			"jupiter_context_can_change_verdict":    false, "lp_control_arm_can_change_grade": false,
			"exit_liquidity_quote_only": true, "program_authority_is_capability_not_intent": true,
			"corpus_percentile_can_change_verdict":       false,
			"live_transaction_rows_can_change_grade":     false,
			"verified_actor_evidence_can_change_verdict": true,
		},
	}
	_ = h.persistDossierSourceSnapshot(ctx, report)
	return unifiedInvestigationAssembly{
		Report: report, Core: core, DB: db, Store: store, Creator: creator,
		ActorDossier: actorDossier, ActorTrack: actorTrack, ActorVerdict: actorVerdict,
		Behavior: behavior, UnifiedVerdict: unifiedVerdict, Threat: threat,
		CombinedEvidence: combinedEvidence, Modules: modules, Structural: structural,
		Graph: graph, TradeLedger: tradeLedger, ActorStoreStatus: actorStoreStatus,
	}
}

func (h *Handler) unifiedTradeLedgerAggregates(ctx context.Context, mint string) map[string]any {
	out := map[string]any{
		"available": false, "status": "monitoring_window_active", "trade_count": int64(0),
		"buy_count": int64(0), "sell_count": int64(0), "unique_trader_count": int64(0),
		"round_trip_wallet_count": int64(0), "wash_classification": "not_proven",
	}
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil || strings.TrimSpace(mint) == "" {
		out["status"] = "trade_ledger_unavailable"
		return out
	}
	var tradeCount, buyCount, sellCount, uniqueTraders, roundTrip int64
	var firstSeen, lastSeen sql.NullTime
	err := db.QueryRowContext(ctx, `
		WITH per_trader AS (
			SELECT trader, bool_or(side='buy') AS bought, bool_or(side='sell') AS sold
			FROM token_trade_events WHERE mint=$1 GROUP BY trader
		)
		SELECT
			(SELECT count(*) FROM token_trade_events WHERE mint=$1),
			(SELECT count(*) FROM token_trade_events WHERE mint=$1 AND side='buy'),
			(SELECT count(*) FROM token_trade_events WHERE mint=$1 AND side='sell'),
			(SELECT count(*) FROM per_trader),
			(SELECT count(*) FROM per_trader WHERE bought AND sold),
			(SELECT min(COALESCE(block_time,created_at)) FROM token_trade_events WHERE mint=$1),
			(SELECT max(COALESCE(block_time,created_at)) FROM token_trade_events WHERE mint=$1)`, mint).Scan(
		&tradeCount, &buyCount, &sellCount, &uniqueTraders, &roundTrip, &firstSeen, &lastSeen,
	)
	if err != nil {
		out["status"] = "trade_ledger_query_failed"
		return out
	}
	out["available"], out["status"] = tradeCount > 0, "observed_trade_ledger_aggregates"
	out["trade_count"], out["buy_count"], out["sell_count"] = tradeCount, buyCount, sellCount
	out["unique_trader_count"], out["round_trip_wallet_count"] = uniqueTraders, roundTrip
	out["wash_classification"] = "not_proven"
	out["interpretation"] = "Round-trip wallets are an investigation context signal; they are not, by themselves, proof of wash trading."
	if firstSeen.Valid {
		out["first_observed_at"] = firstSeen.Time.UTC().Format(time.RFC3339)
	}
	if lastSeen.Valid {
		out["last_observed_at"] = lastSeen.Time.UTC().Format(time.RFC3339)
	}
	return out
}
