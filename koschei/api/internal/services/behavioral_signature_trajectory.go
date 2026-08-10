package services

import (
	"context"
	"database/sql"
	"sort"
	"strings"
)

const (
	BehavioralSignatureTrajectoryVersion = "koschei-behavioral-signatures-v1.1"
	BehavioralSignatureTrajectoryID      = "KOSCH-BEH-006"
)

// BuildBehavioralSignatureReportWithTrajectory extends the existing behavior
// families with one wallet/funder-first trajectory recurrence signal. The new
// signal remains watch-only even when every underlying edge is VERIFIED because
// correlation across different wallet addresses is not identity or control proof.
func BuildBehavioralSignatureReportWithTrajectory(
	currentTarget string,
	actorHistory SecurityIncidentCorpusView,
	funding FundingClusterOutcomeMemory,
	genome ActorCampaignGenome,
	operational ActorOperationalMemoryReport,
	genomeMatches CampaignGenomeMatchReport,
	trajectory PersistentFundingTrajectoryGraph,
) BehavioralSignatureReport {
	out := BuildBehavioralSignatureReportWithGenomeMatches(
		currentTarget,
		actorHistory,
		funding,
		genome,
		operational,
		genomeMatches,
	)
	out.Version = BehavioralSignatureTrajectoryVersion
	if out.Policy == nil {
		out.Policy = map[string]any{}
	}
	out.Policy["funding_trajectory_recurrence_is_watch_only"] = true
	out.Policy["trajectory_requires_verified_funding_edge"] = true
	out.Policy["trajectory_requires_distinct_actor_addresses"] = true
	out.Policy["trajectory_requires_distinct_token_targets"] = true
	out.Policy["trajectory_inactive_lifecycle_is_not_rug_claim"] = true

	match := behaviorSignatureFundingTrajectoryRecurrence(trajectory)
	out.Matches = append(out.Matches, match)
	if match.Triggered {
		out.TriggeredCount++
		if match.Status == "verified_supported" {
			out.VerifiedSupportedCount++
		}
		if match.Status == "observed_watch" {
			out.WatchCount++
		}
		out.Status = "behavior_families_observed"
	}
	if !trajectory.Complete && strings.TrimSpace(trajectory.Status) != "" {
		out.Complete = false
		out.Limitations = append(out.Limitations, "Persistent funding trajectory evidence is incomplete; absence of KOSCH-BEH-006 is not conclusive.")
	}
	out.Limitations = append(out.Limitations,
		"KOSCH-BEH-006 requires recurrence across distinct actor addresses under a verified shared funding path and remains investigation context only.",
	)
	return out
}

// LoadPersistentFundingTrajectoryGraphForBehavior keeps handler wiring small and
// preserves fail-soft investigation behavior. Query failure withholds the signal;
// it never becomes a safety or risk assertion.
func LoadPersistentFundingTrajectoryGraphForBehavior(ctx context.Context, db *sql.DB, actorWallet, network string) PersistentFundingTrajectoryGraph {
	graph, err := LoadPersistentFundingTrajectoryGraph(ctx, db, strings.TrimSpace(actorWallet), network, 500)
	if err == nil {
		return graph
	}
	return NewPersistentFundingTrajectoryUnavailableGraph(
		actorWallet,
		network,
		"query_failed",
		"Persistent funding trajectory could not be loaded for behavior-family evaluation; KOSCH-BEH-006 was withheld.",
	)
}

type trajectoryRecurrenceBucket struct {
	fundingSource string
	family        string
	actors        map[string]bool
	targets       map[string]bool
	refs          map[string]bool
}

func behaviorSignatureFundingTrajectoryRecurrence(graph PersistentFundingTrajectoryGraph) BehavioralSignatureMatch {
	match := newBehaviorSignature(BehavioralSignatureTrajectoryID, "Verified funded-trajectory event family across distinct actor addresses")

	// Only VERIFIED funding edges are eligible for cross-wallet grouping. This is
	// intentionally stricter than graph visibility, where OBSERVED funding edges
	// remain useful investigation evidence.
	fundersByActor := map[string]map[string]bool{}
	fundingRefs := map[string]map[string]map[string]bool{}
	creatorTokenLinks := map[string]bool{}
	creatorTokenRefs := map[string]map[string]bool{}
	for _, edge := range graph.Edges {
		source := strings.TrimSpace(edge.SourceID)
		target := strings.TrimSpace(edge.TargetID)
		if source == "" || target == "" {
			continue
		}
		switch strings.TrimSpace(edge.EvidenceKind) {
		case "funding":
			if edge.EvidenceState != "verified" || edge.SourceKind != "wallet" || edge.TargetKind != "wallet" {
				continue
			}
			if fundersByActor[target] == nil {
				fundersByActor[target] = map[string]bool{}
			}
			fundersByActor[target][source] = true
			if fundingRefs[target] == nil {
				fundingRefs[target] = map[string]map[string]bool{}
			}
			if fundingRefs[target][source] == nil {
				fundingRefs[target][source] = map[string]bool{}
			}
			if ref := strings.TrimSpace(edge.Signature); ref != "" {
				fundingRefs[target][source][ref] = true
			}
		case "creation":
			if edge.SourceKind != "wallet" || edge.TargetKind != "token" {
				continue
			}
			if edge.EvidenceState != "verified" && edge.EvidenceState != "observed" {
				continue
			}
			key := trajectoryActorTokenKey(source, target)
			creatorTokenLinks[key] = true
			if creatorTokenRefs[key] == nil {
				creatorTokenRefs[key] = map[string]bool{}
			}
			if ref := strings.TrimSpace(edge.Signature); ref != "" {
				creatorTokenRefs[key][ref] = true
			}
		}
	}

	buckets := map[string]*trajectoryRecurrenceBucket{}
	for _, edge := range graph.Edges {
		if edge.EvidenceState != "verified" {
			continue
		}
		actor := strings.TrimSpace(edge.SourceID)
		target := strings.TrimSpace(edge.TargetID)
		if actor == "" || target == "" || edge.SourceKind != "wallet" || edge.TargetKind != "token" {
			continue
		}
		if !creatorTokenLinks[trajectoryActorTokenKey(actor, target)] {
			continue
		}

		family := ""
		switch strings.TrimSpace(edge.EvidenceKind) {
		case "exit_event":
			relation := strings.TrimSpace(edge.Relation)
			if relation != "" {
				family = "exit_event:" + relation
			}
		case "lifecycle":
			if strings.TrimSpace(edge.Relation) == "lifecycle_inactive_or_dead" {
				family = "lifecycle:inactive_or_dead"
			}
		}
		if family == "" {
			continue
		}

		for funder := range fundersByActor[actor] {
			key := funder + "\x00" + family
			bucket := buckets[key]
			if bucket == nil {
				bucket = &trajectoryRecurrenceBucket{
					fundingSource: funder,
					family:        family,
					actors:        map[string]bool{},
					targets:       map[string]bool{},
					refs:          map[string]bool{},
				}
				buckets[key] = bucket
			}
			bucket.actors[actor] = true
			bucket.targets[target] = true
			for ref := range fundingRefs[actor][funder] {
				bucket.refs[ref] = true
			}
			for ref := range creatorTokenRefs[trajectoryActorTokenKey(actor, target)] {
				bucket.refs[ref] = true
			}
			// Exit-event signatures are direct transaction evidence. Lifecycle
			// edges may carry a creation signature, so the graph hash is the
			// canonical lifecycle evidence reference instead of relabeling it.
			if edge.EvidenceKind == "exit_event" {
				if ref := strings.TrimSpace(edge.Signature); ref != "" {
					bucket.refs[ref] = true
				}
			}
		}
	}

	keys := make([]string, 0, len(buckets))
	for key := range buckets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	qualifyingFamilies := []string{}
	actors := map[string]bool{}
	targets := map[string]bool{}
	funders := map[string]bool{}
	refs := map[string]bool{}
	for _, key := range keys {
		bucket := buckets[key]
		if len(bucket.actors) < 2 || len(bucket.targets) < 2 {
			continue
		}
		qualifyingFamilies = append(qualifyingFamilies, bucket.family)
		funders[bucket.fundingSource] = true
		for actor := range bucket.actors {
			actors[actor] = true
		}
		for target := range bucket.targets {
			targets[target] = true
		}
		for ref := range bucket.refs {
			refs[ref] = true
		}
	}
	if len(qualifyingFamilies) == 0 {
		return match
	}
	if hash := strings.TrimSpace(graph.EvidenceHashSHA256); hash != "" {
		refs[hash] = true
	}

	match.Triggered = true
	match.Status = "observed_watch"
	match.EvidenceStatus = "observed"
	match.ActorWallets = sortedBehaviorKeys(actors)
	match.Targets = sortedBehaviorKeys(targets)
	match.FundingSources = sortedBehaviorKeys(funders)
	match.EvidenceRefs = sortedBehaviorKeys(refs)
	match.Explanation = "A verified shared funding path spans distinct actor addresses whose creator-linked tokens repeat the verified technical trajectory family: " + strings.Join(appendFundingOutcomeUnique(nil, qualifyingFamilies...), ", ") + "."
	match.Limitations = append(match.Limitations,
		"Cross-wallet trajectory recurrence is a technical correlation only; it never proves common control, a shared real-world operator, intent or wrongdoing.",
		"A repeated lifecycle:inactive_or_dead family is not a rug classification. It only means Koschei retained verified positive-liquidity-to-inactive lifecycle transitions on distinct creator-linked tokens.",
	)
	return match
}

func trajectoryActorTokenKey(actor, target string) string {
	return strings.TrimSpace(actor) + "\x00" + strings.TrimSpace(target)
}
