package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	ActorExitEventLiquidityRemoval          = "liquidity_removal"
	ActorExitEventDominantHolderExit        = "dominant_holder_exit"
	ActorExitEventAuthorityChangePostLaunch = "authority_change_post_launch"
	ActorExitEventSupplyGrowthPostLaunch    = "supply_growth_post_launch"
	ActorExitEventCreatorSell               = "creator_sell"
)

type ActorExitEvent struct {
	ActorWallet   string         `json:"actor_wallet"`
	Network       string         `json:"network"`
	Target        string         `json:"target"`
	EventKind     string         `json:"event_kind"`
	EvidenceState string         `json:"evidence_state"`
	Signature     string         `json:"signature"`
	Slot          int64          `json:"slot"`
	ObservedAt    time.Time      `json:"observed_at"`
	SourceRuleID  string         `json:"source_rule_id"`
	Detail        map[string]any `json:"detail"`
}

type ActorExitEventReference struct {
	Target        string    `json:"target"`
	EventKind     string    `json:"event_kind"`
	EvidenceState string    `json:"evidence_state"`
	Signature     string    `json:"signature"`
	Slot          int64     `json:"slot"`
	ObservedAt    time.Time `json:"observed_at"`
	SourceRuleID  string    `json:"source_rule_id"`
}

type ActorExitRecurrence struct {
	Available                 bool                      `json:"available"`
	Status                    string                    `json:"status"`
	EvidenceStatus            string                    `json:"evidence_status"`
	ActorWallet               string                    `json:"actor_wallet"`
	Network                   string                    `json:"network"`
	CurrentTarget             string                    `json:"current_target"`
	DistinctTargetsWithEvents int                       `json:"distinct_targets_with_events"`
	OtherTargets              []string                  `json:"other_targets"`
	Signatures                []string                  `json:"signatures"`
	Slots                     []int64                   `json:"slots"`
	EventKinds                []string                  `json:"event_kinds"`
	ReferencesComplete        bool                      `json:"references_complete"`
	Events                    []ActorExitEventReference `json:"events"`
	Limitations               []string                  `json:"limitations"`
}

// actorExitEventFromEvidence projects only transaction-referenced rule evidence
// into the event corpus. It never invents a target, signer, signature or slot.
func strictActorExitEvidenceState(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "verified":
		return "verified", true
	case "observed":
		return "observed", true
	default:
		return "", false
	}
}

func actorExitEventFromEvidence(item ActorDefenseEvidenceRecord) (ActorExitEvent, bool) {
	state, ok := strictActorExitEvidenceState(item.VerificationStatus)
	if !ok {
		return ActorExitEvent{}, false
	}
	signature := strings.TrimSpace(item.Signature)
	target := strings.TrimSpace(item.TokenMint)
	if signature == "" || item.Slot <= 0 || target == "" {
		return ActorExitEvent{}, false
	}

	event := ActorExitEvent{
		Network: normalizeRadarNetwork(item.Network), Target: target,
		EvidenceState: state, Signature: signature, Slot: item.Slot,
		ObservedAt: item.ObservedAt.UTC(), Detail: actorExitEventDetail(item),
	}
	if event.ObservedAt.IsZero() {
		return ActorExitEvent{}, false
	}

	switch strings.TrimSpace(item.Relation) {
	case "liquidity_remove_activity":
		// ARD-H001 requires a verified creator/deployer relation and an actor-signed
		// parsed liquidity-removal instruction. Observed-only ARD-C005 rows do not
		// get relabeled as the hard-rule event.
		if state != "verified" || !actorExitMetadataBool(item.Metadata, "actor_signed") || !actorExitMetadataBool(item.Metadata, "creator_role_observed") {
			return ActorExitEvent{}, false
		}
		event.ActorWallet = strings.TrimSpace(item.ActorWallet)
		event.EventKind = ActorExitEventLiquidityRemoval
		event.SourceRuleID = ActorRuleHardCreatorLiquidityRemoval
	case "dominant_holder_first_exit":
		if !strings.EqualFold(actorExitMetadataString(item.Metadata, "unified_rule_id"), UnifiedRuleDominantHolderFirstExit) {
			return ActorExitEvent{}, false
		}
		metrics := actorExitMetadataMap(item.Metadata, "metrics")
		event.ActorWallet = strings.TrimSpace(actorExitAnyString(metrics["holder_wallet"]))
		event.EventKind = ActorExitEventDominantHolderExit
		event.SourceRuleID = UnifiedRuleDominantHolderFirstExit
	case "creator_sell_acceleration":
		// The current aggregate does not preserve a signature+slot pair per parsed
		// trade event. The schema reserves creator_sell, but no row is written until
		// that transaction-level evidence exists.
		return ActorExitEvent{}, false
	default:
		return ActorExitEvent{}, false
	}

	if strings.TrimSpace(event.ActorWallet) == "" || strings.TrimSpace(event.SourceRuleID) == "" {
		return ActorExitEvent{}, false
	}
	return event, true
}

func actorExitEventDetail(item ActorDefenseEvidenceRecord) map[string]any {
	out := map[string]any{
		"evidence_key": strings.TrimSpace(item.EvidenceKey),
		"source":       strings.TrimSpace(item.Source),
		"relation":     strings.TrimSpace(item.Relation),
	}
	for _, key := range []string{"pool_account", "program", "instruction_types"} {
		if value, ok := item.Metadata[key]; ok {
			out[key] = value
		}
	}
	if metrics := actorExitMetadataMap(item.Metadata, "metrics"); len(metrics) > 0 {
		out["metrics"] = metrics
	}
	return out
}

func actorExitMetadataBool(metadata map[string]any, key string) bool {
	value, _ := metadata[key].(bool)
	return value
}

func actorExitMetadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	return strings.TrimSpace(actorExitAnyString(metadata[key]))
}

func actorExitMetadataMap(metadata map[string]any, key string) map[string]any {
	if metadata == nil {
		return map[string]any{}
	}
	value, _ := metadata[key].(map[string]any)
	if value == nil {
		return map[string]any{}
	}
	return value
}

func actorExitAnyString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return ""
	}
}

func upsertActorExitEventTx(ctx context.Context, tx *sql.Tx, event ActorExitEvent) error {
	if tx == nil {
		return fmt.Errorf("actor exit event transaction is unavailable")
	}
	if strings.TrimSpace(event.ActorWallet) == "" || strings.TrimSpace(event.Target) == "" || strings.TrimSpace(event.Signature) == "" || event.Slot <= 0 || event.ObservedAt.IsZero() {
		return nil
	}
	if event.EvidenceState != "verified" && event.EvidenceState != "observed" {
		return nil
	}
	detail, err := json.Marshal(nonNilMap(event.Detail))
	if err != nil {
		return fmt.Errorf("encode actor exit event detail: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO security_actor_exit_events (
			actor_wallet,network,target,event_kind,evidence_state,signature,slot,observed_at,source_rule_id,detail
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)
		ON CONFLICT (actor_wallet,network,target,event_kind,signature) DO UPDATE SET
			evidence_state=CASE
				WHEN security_actor_exit_events.evidence_state='verified' OR EXCLUDED.evidence_state='verified' THEN 'verified'
				ELSE 'observed'
			END,
			slot=EXCLUDED.slot,
			observed_at=GREATEST(security_actor_exit_events.observed_at,EXCLUDED.observed_at),
			source_rule_id=EXCLUDED.source_rule_id,
			detail=security_actor_exit_events.detail || EXCLUDED.detail`,
		event.ActorWallet, event.Network, event.Target, event.EventKind, event.EvidenceState,
		event.Signature, event.Slot, event.ObservedAt.UTC(), event.SourceRuleID, string(detail))
	if err != nil {
		return fmt.Errorf("upsert actor exit event: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO security_actor_exit_profiles (
			actor_wallet,network,distinct_targets_with_events,event_kind_counts,
			verified_event_count,observed_event_count,first_event_at,last_event_at
		)
		SELECT
			$1,$2,
			count(DISTINCT e.target)::integer,
			COALESCE((
				SELECT jsonb_object_agg(kind_rows.event_kind,kind_rows.event_count)
				FROM (
					SELECT event_kind,count(*)::integer AS event_count
					FROM security_actor_exit_events
					WHERE actor_wallet=$1 AND network=$2
					GROUP BY event_kind
				) AS kind_rows
			),'{}'::jsonb),
			count(*) FILTER (WHERE e.evidence_state='verified')::integer,
			count(*) FILTER (WHERE e.evidence_state='observed')::integer,
			min(e.observed_at),max(e.observed_at)
		FROM security_actor_exit_events e
		WHERE e.actor_wallet=$1 AND e.network=$2
		GROUP BY e.actor_wallet,e.network
		ON CONFLICT (actor_wallet,network) DO UPDATE SET
			distinct_targets_with_events=EXCLUDED.distinct_targets_with_events,
			event_kind_counts=EXCLUDED.event_kind_counts,
			verified_event_count=EXCLUDED.verified_event_count,
			observed_event_count=EXCLUDED.observed_event_count,
			first_event_at=EXCLUDED.first_event_at,
			last_event_at=EXCLUDED.last_event_at`, event.ActorWallet, event.Network)
	if err != nil {
		return fmt.Errorf("recompute actor exit profile: %w", err)
	}
	return nil
}

// LoadActorExitRecurrence reads the persisted event corpus only. It does not
// start a collector, worker, timer or connection of its own.
func (s *ActorDefenseStore) LoadActorExitRecurrence(ctx context.Context, actorWallet, network, currentTarget string) (ActorExitRecurrence, error) {
	actorWallet = strings.TrimSpace(actorWallet)
	network = normalizeRadarNetwork(network)
	currentTarget = strings.TrimSpace(currentTarget)
	out := ActorExitRecurrence{
		Status: "not_investigated", EvidenceStatus: "not_investigated",
		ActorWallet: actorWallet, Network: network, CurrentTarget: currentTarget,
		OtherTargets: []string{}, Signatures: []string{}, Slots: []int64{}, EventKinds: []string{}, Events: []ActorExitEventReference{}, Limitations: []string{},
	}
	if s == nil || s.DB == nil || actorWallet == "" {
		out.Status = "unavailable"
		out.EvidenceStatus = "unavailable"
		out.Limitations = append(out.Limitations, "Actor wallet or exit-event corpus database is unavailable.")
		return out, nil
	}

	err := s.DB.QueryRowContext(ctx, `
		SELECT distinct_targets_with_events
		FROM security_actor_exit_profiles
		WHERE actor_wallet=$1 AND network=$2`, actorWallet, network).Scan(&out.DistinctTargetsWithEvents)
	if err == sql.ErrNoRows {
		out.Available = true
		out.Status = "no_events"
		out.EvidenceStatus = "observed"
		return out, nil
	}
	if err != nil {
		out.Status = "unavailable"
		out.EvidenceStatus = "unavailable"
		out.Limitations = append(out.Limitations, "Exit-event profile query failed.")
		return out, err
	}

	rows, err := s.DB.QueryContext(ctx, `
		SELECT target,event_kind,evidence_state,signature,slot,observed_at,source_rule_id
		FROM security_actor_exit_events
		WHERE actor_wallet=$1 AND network=$2
		ORDER BY observed_at ASC,target ASC,signature ASC`, actorWallet, network)
	if err != nil {
		out.Status = "unavailable"
		out.EvidenceStatus = "unavailable"
		out.Limitations = append(out.Limitations, "Exit-event source-row query failed.")
		return out, err
	}
	defer rows.Close()

	allVerified := true
	allRefs := true
	for rows.Next() {
		var item ActorExitEventReference
		if err := rows.Scan(&item.Target, &item.EventKind, &item.EvidenceState, &item.Signature, &item.Slot, &item.ObservedAt, &item.SourceRuleID); err != nil {
			return out, err
		}
		item.Target = strings.TrimSpace(item.Target)
		item.Signature = strings.TrimSpace(item.Signature)
		item.SourceRuleID = strings.TrimSpace(item.SourceRuleID)
		if item.Target == "" || item.Signature == "" || item.Slot <= 0 || item.ObservedAt.IsZero() {
			allRefs = false
			continue
		}
		if item.EvidenceState != "verified" {
			allVerified = false
		}
		out.Events = append(out.Events, item)
		out.Signatures = append(out.Signatures, item.Signature)
		out.Slots = append(out.Slots, item.Slot)
		out.EventKinds = append(out.EventKinds, item.EventKind)
		if item.Target != currentTarget {
			out.OtherTargets = append(out.OtherTargets, item.Target)
		}
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	out.Available = true
	out.OtherTargets = uniqueFundingStrings(out.OtherTargets)
	out.Signatures = uniqueFundingStrings(out.Signatures)
	out.EventKinds = uniqueFundingStrings(out.EventKinds)
	out.Slots = uniquePositiveLifecycleSlots(out.Slots)
	out.ReferencesComplete = out.DistinctTargetsWithEvents >= 2 && len(out.OtherTargets) > 0 && len(out.Signatures) > 0 && len(out.Slots) > 0 && allRefs

	switch {
	case out.DistinctTargetsWithEvents < 2:
		out.Status = "single_target_only"
		out.EvidenceStatus = "observed"
	case !out.ReferencesComplete:
		out.Status = "reference_gap"
		out.EvidenceStatus = "unavailable"
		out.Limitations = append(out.Limitations, "Cross-token event count exists, but wallet, target, signature and slot references are not complete; recurrence is withheld.")
	case allVerified:
		out.Status = "verified_recurrence"
		out.EvidenceStatus = "verified"
	default:
		out.Status = "observed_recurrence"
		out.EvidenceStatus = "observed"
	}
	return out, nil
}

// ApplyActorExitRecurrenceToAnalysis enriches the existing Repeat Actor Scan arm
// instead of creating a second registry source for the same actor lineage.
func ApplyActorExitRecurrenceToAnalysis(analysis ArvisAnalysis, recurrence ActorExitRecurrence) ArvisAnalysis {
	arms := ArvisArmsFromBundle(analysis.Bundle)
	if len(arms) == 0 {
		arms = append([]SecurityRadarVerdict{}, analysis.Arms...)
	}
	for index := range arms {
		if arms[index].ModuleID != ModuleRepeatActorScan {
			continue
		}
		if arms[index].Signals == nil {
			arms[index].Signals = map[string]any{}
		}
		arms[index].Signals["exit_event_status"] = recurrence.Status
		arms[index].Signals["exit_event_actor_wallet"] = recurrence.ActorWallet
		arms[index].Signals["exit_event_distinct_targets"] = recurrence.DistinctTargetsWithEvents
		arms[index].Signals["exit_event_other_mints"] = append([]string{}, recurrence.OtherTargets...)
		arms[index].Signals["exit_event_signatures"] = append([]string{}, recurrence.Signatures...)
		arms[index].Signals["exit_event_slots"] = append([]int64{}, recurrence.Slots...)
		arms[index].Signals["exit_event_kinds"] = append([]string{}, recurrence.EventKinds...)
		arms[index].Signals["exit_event_references_complete"] = recurrence.ReferencesComplete
		arms[index].Signals["persistent_exit_event_index"] = true
		if recurrence.DistinctTargetsWithEvents >= 2 && recurrence.ReferencesComplete {
			arms[index].Signals["finding_observed"] = true
			arms[index].Signals["cross_token_exit_event_recurrence"] = true
			current := normalizeActorEvidenceStatus(actorExitAnyString(arms[index].Signals["evidence_status"]))
			if recurrence.EvidenceStatus == "verified" || current != "verified" {
				arms[index].Signals["evidence_status"] = recurrence.EvidenceStatus
			}
			arms[index].Evidence = append(arms[index].Evidence, fmt.Sprintf("Persistent event memory references %s across %d token target(s); cited transaction signatures and slots are attached.", recurrence.ActorWallet, recurrence.DistinctTargetsWithEvents))
			arms[index].Verdict = "Persistent on-chain event memory shows transaction-referenced recurrence across multiple token targets."
			arms[index].Recommendation = "Review the cited target mints, transaction signatures and slots as technical on-chain observations."
		} else if recurrence.Available {
			arms[index].Evidence = append(arms[index].Evidence, "Persistent event memory was queried; fewer than two referenced token targets do not constitute cross-token recurrence.")
		}
		break
	}
	analysis.Arms = arms
	if analysis.Bundle.Metadata == nil {
		analysis.Bundle.Metadata = map[string]any{}
	}
	analysis.Bundle.Metadata["arvis_arms"] = arms
	analysis.Bundle.Metadata["actor_exit_event_recurrence"] = recurrence
	analysis.Bundle.Metadata["verified_arm_count"] = verifiedArvisEvidenceCount(arms)
	analysis.Bundle.Metadata["runtime_arm_count"] = verifiedArvisEvidenceCount(arms)
	return ApplyArvisInvestigationCoverage(analysis)
}
