package services

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const (
	PersistentRepeatActorMaxOwners  = 5
	PersistentRepeatActorMaxMatches = 64
	PersistentRepeatActorWindow     = "all-time persistent Koschei actor memory"
)

// PersistentRepeatDominantHolders answers ACTOR_INVESTIGATION_ENGINE questions
// 6 and 9 from security_actor_evidence, the retention-independent actor index.
// It intentionally performs no Solana RPC calls and never infers common identity
// or intent from repeated holder observations.
func (s *SecurityRadarStore) PersistentRepeatDominantHolders(ctx context.Context, holder HolderIntelligence, currentMint, network string) ([]RepeatDominantHolderEvidence, error) {
	if s == nil || s.DB == nil || !holder.Available {
		return []RepeatDominantHolderEvidence{}, nil
	}
	currentMint = strings.TrimSpace(currentMint)
	network = normalizeRadarNetwork(network)
	out := []RepeatDominantHolderEvidence{}
	checked := 0
	for _, row := range holder.Rows {
		owner := strings.TrimSpace(row.OwnerWallet)
		if owner == "" || !row.OwnerResolved || !row.RiskBearing || row.ExcludedFromHolderRisk {
			continue
		}
		checked++
		if checked > PersistentRepeatActorMaxOwners {
			break
		}

		currentPercentage := row.CirculatingPercentage
		if currentPercentage <= 0 {
			currentPercentage = row.RawPercentage
		}
		if currentPercentage < 20 {
			continue
		}

		matches, err := s.persistentRepeatDominantHolderMatches(ctx, owner, network)
		if err != nil {
			return nil, err
		}
		matches = ensureCurrentPersistentDominantMatch(matches, currentMint, currentPercentage, row.Rank)
		if len(matches) < 2 {
			continue
		}

		evidence := RepeatDominantHolderEvidence{
			OwnerWallet:       owner,
			CurrentMint:       currentMint,
			CurrentPercentage: currentPercentage,
			TokenCount:        len(matches),
			ObservationDays:   0,
			ObservationWindow: PersistentRepeatActorWindow,
			// Compatibility-only diagnostic. Unified Radar rules own grade changes.
			RiskWeight: RepeatDominantRiskWeight(currentPercentage, len(matches)),
			Matches:    matches,
		}
		evidence.EvidenceLine = PersistentRepeatDominantEvidenceLine(owner, matches)
		out = append(out, evidence)
	}
	return out, nil
}

func (s *SecurityRadarStore) persistentRepeatDominantHolderMatches(ctx context.Context, owner, network string) ([]RepeatDominantHolderMatch, error) {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return nil, fmt.Errorf("owner wallet is required")
	}
	rows, err := s.DB.QueryContext(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (token_mint)
				token_mint,
				CASE
					WHEN COALESCE(metadata->>'max_holder_percentage',metadata->>'holder_percentage','') ~ '^[0-9]+([.][0-9]+)?$'
					THEN COALESCE(metadata->>'max_holder_percentage',metadata->>'holder_percentage')::double precision
					ELSE 0
				END AS percentage,
				CASE
					WHEN COALESCE(metadata->>'best_holder_rank',metadata->>'holder_rank','') ~ '^[0-9]+$'
					THEN COALESCE(metadata->>'best_holder_rank',metadata->>'holder_rank')::integer
					ELSE 0
				END AS holder_rank,
				last_observed_at
			FROM security_actor_evidence
			WHERE network=$1
			  AND actor_wallet=$2
			  AND actor_role='dominant_holder'
			  AND relation='dominant_holder_of'
			  AND verification_status IN ('verified','observed')
			  AND token_mint IS NOT NULL
			  AND btrim(token_mint)<>''
			ORDER BY token_mint,last_observed_at DESC,id DESC
		)
		SELECT token_mint,percentage,holder_rank,last_observed_at
		FROM latest
		WHERE percentage>=20
		ORDER BY percentage DESC,last_observed_at DESC
		LIMIT $3`, network, owner, PersistentRepeatActorMaxMatches)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RepeatDominantHolderMatch{}
	for rows.Next() {
		var item RepeatDominantHolderMatch
		var observedAt time.Time
		if err := rows.Scan(&item.Mint, &item.Percentage, &item.Rank, &observedAt); err != nil {
			return nil, err
		}
		item.ScannedAt = observedAt.UTC().Format(time.RFC3339)
		out = append(out, item)
	}
	return out, rows.Err()
}

func ensureCurrentPersistentDominantMatch(matches []RepeatDominantHolderMatch, currentMint string, percentage float64, rank int) []RepeatDominantHolderMatch {
	currentMint = strings.TrimSpace(currentMint)
	if currentMint == "" || percentage < 20 {
		return matches
	}
	for _, match := range matches {
		if strings.TrimSpace(match.Mint) == currentMint {
			return matches
		}
	}
	return append(matches, RepeatDominantHolderMatch{
		Mint: currentMint, Percentage: percentage, Rank: rank,
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

func PersistentRepeatDominantEvidenceLine(owner string, matches []RepeatDominantHolderMatch) string {
	items := make([]string, 0, len(matches))
	for _, match := range matches {
		date := strings.TrimSpace(match.ScannedAt)
		if parsed, err := time.Parse(time.RFC3339, date); err == nil {
			date = parsed.UTC().Format("2006-01-02")
		}
		items = append(items, fmt.Sprintf("%s %.2f%% (%s)", repeatDominantShortMint(match.Mint), match.Percentage, date))
	}
	return fmt.Sprintf("REPEAT DOMINANT HOLDER: %s cüzdanı Koschei'nin kalıcı actor index'inde %d farklı token'da >=20%% owner-resolved dominant holder olarak gözlendi: %s. Hafıza ham-event retention süresinden bağımsızdır; bu gözlem ortak kimlik veya niyet iddiası değildir.", strings.TrimSpace(owner), len(matches), strings.Join(items, ", "))
}

// ApplyPersistentRepeatDominantHolderEvidenceToAnalysis keeps the existing
// Repeat Actor arm contract but replaces the legacy bounded-window semantics
// with the retention-independent actor index.
func ApplyPersistentRepeatDominantHolderEvidenceToAnalysis(analysis ArvisAnalysis, req SecurityRadarRequest, evidence []RepeatDominantHolderEvidence) ArvisAnalysis {
	analysis = ApplyRepeatDominantHolderEvidenceToAnalysis(analysis, req, evidence)
	arms := ArvisArmsFromBundle(analysis.Bundle)
	if len(arms) == 0 {
		arms = append([]SecurityRadarVerdict{}, analysis.Arms...)
	}
	findingObserved := len(evidence) > 0
	for i := range arms {
		if arms[i].ModuleID != ModuleRepeatActorScan {
			continue
		}
		if arms[i].Signals == nil {
			arms[i].Signals = map[string]any{}
		}
		arms[i].Signals["persistent_actor_index"] = true
		arms[i].Signals["memory_scope"] = "persistent_actor_index_all_time"
		arms[i].Signals["raw_event_retention_independent"] = true
		arms[i].Signals["bounded_window"] = false
		arms[i].Signals["observation_window"] = "all_time"
		arms[i].Signals["repeat_dominant_observation_days"] = 0
		if findingObserved {
			arms[i].Verdict = "Aynı owner-resolved holder cüzdanı, Koschei'nin kalıcı actor index'inde birden fazla token'da baskın holder olarak gözlendi."
			arms[i].Recommendation = "Combine persistent repeat-holder evidence with creator, funding and liquidity evidence in the unified deterministic rules engine."
		} else {
			arms[i].Evidence = []string{"Koschei persistent actor index was queried across retained actor history; no repeat-dominant holder match was observed. This negative finding is not proof that the actor never appeared outside Koschei's collected evidence."}
			arms[i].Verdict = "Persistent all-time actor-memory query completed; no repeat-dominant holder match was observed in Koschei's retained actor evidence."
			arms[i].Recommendation = "Continue evidence collection; absence from Koschei memory is not a safety claim."
			arms[i].Signals["evidence_status"] = "observed_no_repeat_match"
		}
	}
	analysis.Arms = arms
	if analysis.Bundle.Metadata == nil {
		analysis.Bundle.Metadata = map[string]any{}
	}
	analysis.Bundle.Metadata["arvis_arms"] = arms
	analysis.Bundle.Metadata["repeat_actor_memory_scope"] = "persistent_actor_index_all_time"
	analysis.Bundle.Metadata["repeat_actor_retention_independent"] = true
	analysis.Bundle.Metadata["repeat_dominant_holders"] = evidence
	analysis.Bundle.Metadata["repeat_dominant_holder_count"] = len(evidence)
	analysis.Bundle.Metadata["verified_arm_count"] = verifiedArvisEvidenceCount(arms)
	analysis.Bundle.Metadata["runtime_arm_count"] = verifiedArvisEvidenceCount(arms)
	if findingObserved {
		analysis.Bundle.CustomerSummary = fmt.Sprintf("ARVIS connected %d repeat-dominant holder observation(s) from all-time persistent Koschei actor memory.", len(evidence))
	} else {
		analysis.Bundle.CustomerSummary = "ARVIS completed the all-time persistent actor-memory query without a repeat-dominant holder match."
	}
	return ApplyArvisInvestigationCoverage(analysis)
}
