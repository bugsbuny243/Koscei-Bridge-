package services

import "strings"

func HardenUnifiedRadarBehavior(report UnifiedRadarBehaviorReport, verification CreatorSellVerification, cluster HolderClusterAnalysis) UnifiedRadarBehaviorReport {
	report.Evidence = []ActorDefenseEvidenceRecord{}
	report.TriggeredRuleCount = 0
	report.WatchFlagCount = 0
	for index := range report.Signals {
		signal := &report.Signals[index]
		switch signal.RuleID {
		case UnifiedRuleCreatorSellAcceleration:
			if signal.EvidenceStatus != "unverified" {
				signal.EvidenceStatus = "observed"
			}
			signal.Signatures = append([]string{}, verification.VerifiedSignatures...)
			if signal.Metrics == nil {
				signal.Metrics = map[string]any{}
			}
			signal.Metrics["ledger_candidate_signature_count"] = len(verification.CandidateSignatures)
			signal.Metrics["verified_sell_signature_count"] = len(verification.VerifiedSignatures)
			signal.Metrics["transactions_parsed"] = verification.TransactionsParsed
			signal.Limitations = append(signal.Limitations, verification.Limitations...)
			signal.Summary = strings.ReplaceAll(signal.Summary, "verified sells", "ledger-observed sells")
		case UnifiedRuleDominantHolderFirstExit:
			hardenUnifiedDominantHolderExit(signal, cluster)
		}
		if signal.Triggered {
			report.TriggeredRuleCount++
		}
		if signal.EvidenceStatus == "inferred" {
			report.WatchFlagCount++
		}
		if evidence, ok := canonicalUnifiedSignalEvidence(report.Mint, *signal); ok {
			report.Evidence = append(report.Evidence, evidence)
		}
	}
	return report
}

func hardenUnifiedDominantHolderExit(signal *UnifiedRadarSignal, cluster HolderClusterAnalysis) {
	if signal == nil || !signal.Triggered || len(signal.Signatures) == 0 {
		return
	}
	signature := strings.TrimSpace(signal.Signatures[0])
	for _, wallet := range cluster.Wallets {
		if wallet.Rank != 1 || strings.TrimSpace(wallet.Wallet) == "" {
			continue
		}
		for _, observation := range wallet.FlowObservations {
			if strings.TrimSpace(observation.Signature) != signature {
				continue
			}
			direction := strings.ToLower(strings.TrimSpace(observation.Direction))
			source := strings.TrimSpace(observation.SourceWallet)
			destination := strings.TrimSpace(observation.Destination)
			if direction != "outbound" || !strings.EqualFold(source, strings.TrimSpace(wallet.Wallet)) || destination == "" || observation.Amount <= 0 {
				invalidateUnifiedDominantHolderExit(signal, observation, "The matched transaction is not a verified outbound transfer from the rank-one holder; inbound or direction-ambiguous observations cannot trigger URD-C004.")
				return
			}
			program := firstUnifiedProgram(observation.ProgramIDs)
			if signal.Metrics == nil {
				signal.Metrics = map[string]any{}
			}
			signal.Metrics["source_wallet"] = source
			signal.Metrics["destination_wallet"] = destination
			signal.Metrics["direction"] = direction
			signal.Metrics["program"] = program
			signal.Metrics["program_ids"] = append([]string{}, observation.ProgramIDs...)
			signal.Metrics["slot"] = observation.Slot
			signal.Metrics["amount"] = observation.Amount
			if program == "" || observation.Slot <= 0 {
				signal.EvidenceStatus = "observed"
				signal.Limitations = append(signal.Limitations, "Outbound holder transfer signature was observed, but program or slot evidence is incomplete; VERIFIED is withheld.")
			} else {
				signal.EvidenceStatus = "verified"
			}
			return
		}
	}
	invalidateUnifiedDominantHolderExit(signal, HolderClusterFlowObservation{}, "The candidate exit signature could not be rematched to an outbound rank-one holder flow observation; URD-C004 was withdrawn.")
}

func invalidateUnifiedDominantHolderExit(signal *UnifiedRadarSignal, observation HolderClusterFlowObservation, reason string) {
	if signal == nil {
		return
	}
	signal.Triggered = false
	signal.GradeEffect = "none"
	signal.EvidenceStatus = "observed"
	signal.EvidenceKeys = []string{}
	signal.Signatures = []string{}
	if signal.Metrics == nil {
		signal.Metrics = map[string]any{}
	}
	if source := strings.TrimSpace(observation.SourceWallet); source != "" {
		signal.Metrics["source_wallet"] = source
	}
	if destination := strings.TrimSpace(observation.Destination); destination != "" {
		signal.Metrics["destination_wallet"] = destination
	}
	if direction := strings.ToLower(strings.TrimSpace(observation.Direction)); direction != "" {
		signal.Metrics["direction"] = direction
	}
	if observation.Slot > 0 {
		signal.Metrics["slot"] = observation.Slot
	}
	if observation.Amount > 0 {
		signal.Metrics["amount"] = observation.Amount
	}
	signal.Summary = "Rank-one holder history was inspected, but no transaction-backed outbound holder exit satisfied URD-C004."
	signal.Limitations = append(signal.Limitations, reason)
}

func canonicalUnifiedSignalEvidence(mint string, signal UnifiedRadarSignal) (ActorDefenseEvidenceRecord, bool) {
	if signal.RuleID != UnifiedRuleDominantHolderFirstExit || !signal.Triggered || signal.EvidenceStatus != "verified" || len(signal.Signatures) == 0 {
		return ActorDefenseEvidenceRecord{}, false
	}
	source := unifiedMetricString(signal.Metrics, "source_wallet")
	destination := unifiedMetricString(signal.Metrics, "destination_wallet")
	direction := strings.ToLower(unifiedMetricString(signal.Metrics, "direction"))
	program := unifiedMetricString(signal.Metrics, "program")
	slot, slotOK := unifiedInt64(signal.Metrics["slot"])
	amount := unifiedMetricFloat(signal.Metrics, "amount")
	if source == "" || destination == "" || direction != "outbound" || program == "" || !slotOK || slot <= 0 || amount <= 0 || signal.ObservedAt.IsZero() {
		return ActorDefenseEvidenceRecord{}, false
	}
	item := ActorDefenseEvidenceRecord{
		Network: "solana-mainnet", ActorWallet: source, CounterpartKind: "wallet", CounterpartID: destination,
		Relation: "dominant_holder_first_exit", VerificationStatus: "verified",
		EvidenceKey: signal.EvidenceKeys[0], Source: "unified_manual_radar_transaction",
		Signature: strings.TrimSpace(signal.Signatures[0]), Slot: slot, ObservedAt: signal.ObservedAt.UTC(),
		TokenMint: strings.TrimSpace(mint), TokenAmount: amount,
		Metadata: map[string]any{
			"actor_role": "dominant_holder", "source_wallet": source, "destination_wallet": destination,
			"direction": direction, "program": program, "unified_rule_id": signal.RuleID, "scope": signal.Scope,
			"summary": signal.Summary, "manual_only": true, "metrics": signal.Metrics,
		},
	}
	if !BuildActorDefenseEvidenceLine(item).EvidenceLineComplete {
		return ActorDefenseEvidenceRecord{}, false
	}
	return item, true
}

func firstUnifiedProgram(values []string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func unifiedMetricString(metrics map[string]any, key string) string {
	if metrics == nil {
		return ""
	}
	return strings.TrimSpace(actorFundingString(metrics[key]))
}

func unifiedMetricFloat(metrics map[string]any, key string) float64 {
	if metrics == nil {
		return 0
	}
	switch value := metrics[key].(type) {
	case float64:
		return value
	case float32:
		return float64(value)
	case int:
		return float64(value)
	case int64:
		return float64(value)
	default:
		return 0
	}
}
