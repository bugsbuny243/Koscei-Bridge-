package services

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// ActorTokenLifecycleRecurrence is a creator-level read-back of migration 086.
// The lifecycle table distinguishes active from inactive/dead; it does not by
// itself prove a rug, so RuggedStatus is deliberately not a fabricated count.
type ActorTokenLifecycleRecurrence struct {
	Available            bool     `json:"available"`
	Status               string   `json:"status"`
	EvidenceStatus       string   `json:"evidence_status"`
	ActorWallet          string   `json:"actor_wallet"`
	Network              string   `json:"network"`
	CurrentMint          string   `json:"current_mint"`
	TotalTokens          int      `json:"total_tokens"`
	ActiveTokens         int      `json:"active_tokens"`
	InactiveOrDeadTokens int      `json:"inactive_or_dead_tokens"`
	OtherMints           []string `json:"other_mints"`
	CreationSignatures   []string `json:"creation_signatures"`
	CreationSlots        []int64  `json:"creation_slots"`
	ReferencesComplete   bool     `json:"references_complete"`
	RuggedStatus         string   `json:"rugged_status"`
	Limitations          []string `json:"limitations"`
}

// LoadTokenLifecycleRecurrence is the first read path for
// security_actor_token_lifecycle. It reads only the already-collected lifecycle
// corpus and starts no collector or background connection.
func (s *ActorDefenseStore) LoadTokenLifecycleRecurrence(ctx context.Context, actorWallet, network, currentMint string) (ActorTokenLifecycleRecurrence, error) {
	actorWallet = strings.TrimSpace(actorWallet)
	network = normalizeRadarNetwork(network)
	currentMint = strings.TrimSpace(currentMint)
	out := ActorTokenLifecycleRecurrence{
		Status: "not_investigated", EvidenceStatus: "not_investigated",
		ActorWallet: actorWallet, Network: network, CurrentMint: currentMint,
		OtherMints: []string{}, CreationSignatures: []string{}, CreationSlots: []int64{},
		RuggedStatus: "not_classified_by_lifecycle_table", Limitations: []string{},
	}
	if s == nil || s.DB == nil || actorWallet == "" {
		out.Status = "unavailable"
		out.EvidenceStatus = "unavailable"
		out.Limitations = append(out.Limitations, "Creator wallet or actor lifecycle database is unavailable.")
		return out, nil
	}

	rows, err := s.DB.QueryContext(ctx, `
		SELECT mint,creation_signature,creation_slot,first_observed_at,last_observed_at,fate_status
		FROM security_actor_token_lifecycle
		WHERE network=$1 AND actor_wallet=$2
		ORDER BY first_observed_at ASC,mint ASC`, network, actorWallet)
	if err != nil {
		out.Status = "unavailable"
		out.EvidenceStatus = "unavailable"
		out.Limitations = append(out.Limitations, "Actor lifecycle corpus query failed.")
		return out, err
	}
	defer rows.Close()

	allReferencesComplete := true
	for rows.Next() {
		var mint, creationSignature, fateStatus string
		var creationSlot sql.NullInt64
		var firstObservedAt, lastObservedAt time.Time
		if err := rows.Scan(&mint, &creationSignature, &creationSlot, &firstObservedAt, &lastObservedAt, &fateStatus); err != nil {
			return out, err
		}
		mint = strings.TrimSpace(mint)
		creationSignature = strings.TrimSpace(creationSignature)
		fateStatus = strings.TrimSpace(fateStatus)
		if mint == "" {
			continue
		}
		out.TotalTokens++
		switch fateStatus {
		case ActorTokenFateActive:
			out.ActiveTokens++
		case ActorTokenFateInactiveOrDead:
			out.InactiveOrDeadTokens++
		}
		if mint == currentMint {
			continue
		}
		out.OtherMints = append(out.OtherMints, mint)
		if creationSignature != "" {
			out.CreationSignatures = append(out.CreationSignatures, creationSignature)
		}
		if creationSlot.Valid && creationSlot.Int64 > 0 {
			out.CreationSlots = append(out.CreationSlots, creationSlot.Int64)
		}
		if firstObservedAt.IsZero() || lastObservedAt.IsZero() || (creationSignature == "" && (!creationSlot.Valid || creationSlot.Int64 <= 0)) {
			allReferencesComplete = false
		}
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	out.Available = true
	out.OtherMints = uniqueFundingStrings(out.OtherMints)
	out.CreationSignatures = uniqueFundingStrings(out.CreationSignatures)
	out.CreationSlots = uniquePositiveLifecycleSlots(out.CreationSlots)
	out.ReferencesComplete = len(out.OtherMints) > 0 && allReferencesComplete

	switch {
	case out.TotalTokens == 0:
		out.Status = "not_investigated"
		out.EvidenceStatus = "not_investigated"
	case out.TotalTokens == 1 || len(out.OtherMints) == 0:
		out.Status = "single_token_only"
		out.EvidenceStatus = "observed"
	case out.ReferencesComplete:
		out.Status = "verified_recurrence"
		out.EvidenceStatus = "verified"
	default:
		out.Status = "observed_recurrence"
		out.EvidenceStatus = "observed"
		out.Limitations = append(out.Limitations, "Creator appears on multiple lifecycle rows, but at least one other token lacks a creation signature/slot or observation timestamp; VERIFIED was not used.")
	}
	out.Limitations = append(out.Limitations, "Lifecycle fate records active vs inactive/dead observations; this table alone does not classify a token as rugged.")
	return out, nil
}

// ApplyActorTokenLifecycleRecurrenceToAnalysis enriches the existing Repeat
// Actor Scan arm. A single lifecycle row never becomes a recurrence claim.
func ApplyActorTokenLifecycleRecurrenceToAnalysis(analysis ArvisAnalysis, recurrence ActorTokenLifecycleRecurrence) ArvisAnalysis {
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
		arms[index].Signals["actor_lifecycle_status"] = recurrence.Status
		arms[index].Signals["creator_wallet"] = recurrence.ActorWallet
		arms[index].Signals["creator_total_tokens"] = recurrence.TotalTokens
		arms[index].Signals["creator_active_tokens"] = recurrence.ActiveTokens
		arms[index].Signals["creator_inactive_or_dead_tokens"] = recurrence.InactiveOrDeadTokens
		arms[index].Signals["creator_other_mints"] = append([]string{}, recurrence.OtherMints...)
		arms[index].Signals["creator_creation_signatures"] = append([]string{}, recurrence.CreationSignatures...)
		arms[index].Signals["creator_creation_slots"] = append([]int64{}, recurrence.CreationSlots...)
		arms[index].Signals["lifecycle_references_complete"] = recurrence.ReferencesComplete
		arms[index].Signals["lifecycle_rugged_status"] = recurrence.RuggedStatus
		arms[index].Signals["persistent_actor_lifecycle_index"] = true
		if recurrence.TotalTokens >= 2 && len(recurrence.OtherMints) > 0 {
			arms[index].Signals["finding_observed"] = true
			arms[index].Signals["creator_token_recurrence"] = true
			arms[index].Signals["evidence_status"] = recurrence.EvidenceStatus
			arms[index].Evidence = append(arms[index].Evidence, fmt.Sprintf("Creator lifecycle memory: %s appears on %d token(s); %d are currently inactive/dead observations. Other target mints: %s.", recurrence.ActorWallet, recurrence.TotalTokens, recurrence.InactiveOrDeadTokens, strings.Join(recurrence.OtherMints, ", ")))
			arms[index].Verdict = "Persistent creator lifecycle memory shows the same on-chain creator across multiple token mints."
			arms[index].Recommendation = "Review the referenced creator-linked token lifecycle rows; inactive/dead is not automatically a rug classification."
		} else if recurrence.Available {
			arms[index].Evidence = append(arms[index].Evidence, "Creator lifecycle memory was queried; a single observed token does not constitute repeat-actor recurrence.")
		}
		break
	}
	analysis.Arms = arms
	if analysis.Bundle.Metadata == nil {
		analysis.Bundle.Metadata = map[string]any{}
	}
	analysis.Bundle.Metadata["arvis_arms"] = arms
	analysis.Bundle.Metadata["actor_token_lifecycle_recurrence"] = recurrence
	analysis.Bundle.Metadata["verified_arm_count"] = verifiedArvisEvidenceCount(arms)
	analysis.Bundle.Metadata["runtime_arm_count"] = verifiedArvisEvidenceCount(arms)
	return ApplyArvisInvestigationCoverage(analysis)
}

func uniquePositiveLifecycleSlots(values []int64) []int64 {
	seen := map[int64]bool{}
	out := []int64{}
	for _, value := range values {
		if value <= 0 || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
