package services

import (
	"sort"
	"strings"
)

const CampaignEvidenceDependencyLedgerVersion = "koschei-campaign-evidence-dependency-ledger-v1"

type CampaignEvidenceDependencyAnchor struct {
	AnchorID              string   `json:"anchor_id"`
	Label                 string   `json:"label"`
	Triggered             bool     `json:"triggered"`
	EvidenceStatus        string   `json:"evidence_status"`
	DependencyGroup       string   `json:"dependency_group"`
	ProvenanceRoots       []string `json:"provenance_roots"`
	EvidenceRefs          []string `json:"evidence_refs"`
	ActorWallets          []string `json:"actor_wallets"`
	Targets               []string `json:"targets"`
	FundingSources        []string `json:"funding_sources"`
	IndependenceStatus    string   `json:"independence_status"`
	IndependenceReason    string   `json:"independence_reason"`
	VerdictAuthority      bool     `json:"verdict_authority"`
	GradeAuthority        bool     `json:"grade_authority"`
}

type CampaignEvidenceDependencyOverlap struct {
	AnchorA     string   `json:"anchor_a"`
	AnchorB     string   `json:"anchor_b"`
	SharedRoots []string `json:"shared_roots"`
	SameGroup   bool     `json:"same_dependency_group"`
	Reason      string   `json:"reason"`
}

type CampaignEvidenceDependencyLedger struct {
	Version                    string                              `json:"version"`
	Status                     string                              `json:"status"`
	Complete                   bool                                `json:"complete"`
	TriggeredAnchorCount       int                                 `json:"triggered_anchor_count"`
	DistinctDependencyGroups   int                                 `json:"distinct_dependency_group_count"`
	DistinctProvenanceRoots    int                                 `json:"distinct_provenance_root_count"`
	IndependenceProvenAnchors  int                                 `json:"independence_proven_anchor_count"`
	IndependenceUnprovenAnchors int                                `json:"independence_unproven_anchor_count"`
	Anchors                    []CampaignEvidenceDependencyAnchor  `json:"anchors"`
	Overlaps                   []CampaignEvidenceDependencyOverlap `json:"overlaps"`
	VerdictAuthority           bool                                `json:"verdict_authority"`
	GradeAuthority             bool                                `json:"grade_authority"`
	SameOperatorClaim          bool                                `json:"same_operator_claim"`
	RealWorldIdentityClaim     bool                                `json:"real_world_identity_claim"`
	WrongdoingClaim            bool                                `json:"wrongdoing_claim"`
	Policy                     map[string]any                      `json:"policy"`
	Limitations                []string                            `json:"limitations"`
}

// BuildCampaignEvidenceDependencyLedger makes evidence ancestry explicit so
// correlated behavior families are not accidentally counted as independent
// confirmations. It is descriptive only: it does not score, grade or issue a
// verdict.
func BuildCampaignEvidenceDependencyLedger(report BehavioralSignatureReport) CampaignEvidenceDependencyLedger {
	out := CampaignEvidenceDependencyLedger{
		Version: CampaignEvidenceDependencyLedgerVersion,
		Status: "no_triggered_anchor",
		Complete: report.Complete,
		Anchors: []CampaignEvidenceDependencyAnchor{},
		Overlaps: []CampaignEvidenceDependencyOverlap{},
		Policy: map[string]any{
			"same_dependency_group_is_not_independent_confirmation": true,
			"shared_provenance_root_is_not_independent_confirmation": true,
			"campaign_genome_independence_requires_orthogonality_proof": true,
			"derived_behavior_family_never_increases_grade": true,
			"ledger_has_no_verdict_authority": true,
		},
		Limitations: []string{
			"Dependency groups prevent obvious double-counting; they do not prove statistical independence between different groups.",
			"Campaign-genome descriptors may include funding-derived relations, so BEH-005 is never treated as independence-proven by this v1 ledger.",
			"BEH-006 and BEH-007 both derive from the persistent funding trajectory and therefore belong to the same dependency group.",
		},
	}

	for _, match := range report.Matches {
		if !match.Triggered {
			continue
		}
		anchor := campaignEvidenceDependencyAnchor(match)
		out.Anchors = append(out.Anchors, anchor)
		out.TriggeredAnchorCount++
		if anchor.IndependenceStatus == "proven_distinct_source_contract" {
			out.IndependenceProvenAnchors++
		} else {
			out.IndependenceUnprovenAnchors++
		}
	}

	sort.SliceStable(out.Anchors, func(i, j int) bool { return out.Anchors[i].AnchorID < out.Anchors[j].AnchorID })
	groups := map[string]bool{}
	roots := map[string]bool{}
	for _, anchor := range out.Anchors {
		if anchor.DependencyGroup != "" {
			groups[anchor.DependencyGroup] = true
		}
		for _, root := range anchor.ProvenanceRoots {
			roots[root] = true
		}
	}
	out.DistinctDependencyGroups = len(groups)
	out.DistinctProvenanceRoots = len(roots)

	for i := 0; i < len(out.Anchors); i++ {
		for j := i + 1; j < len(out.Anchors); j++ {
			a, b := out.Anchors[i], out.Anchors[j]
			shared := intersectCampaignDependencyStrings(a.ProvenanceRoots, b.ProvenanceRoots)
			sameGroup := a.DependencyGroup != "" && a.DependencyGroup == b.DependencyGroup
			if len(shared) == 0 && !sameGroup {
				continue
			}
			reason := "anchors share retained evidence provenance"
			if sameGroup {
				reason = "anchors are derived from the same dependency group and must not be counted as independent confirmations"
			}
			out.Overlaps = append(out.Overlaps, CampaignEvidenceDependencyOverlap{
				AnchorA: a.AnchorID, AnchorB: b.AnchorID, SharedRoots: shared, SameGroup: sameGroup, Reason: reason,
			})
		}
	}
	if out.TriggeredAnchorCount > 0 {
		out.Status = "dependency_ledger_available"
	}
	return out
}

func campaignEvidenceDependencyAnchor(match BehavioralSignatureMatch) CampaignEvidenceDependencyAnchor {
	anchor := CampaignEvidenceDependencyAnchor{
		AnchorID: strings.TrimSpace(match.SignatureID), Label: strings.TrimSpace(match.Label), Triggered: match.Triggered,
		EvidenceStatus: strings.TrimSpace(match.EvidenceStatus), EvidenceRefs: uniqueSortedFundingOutcomeStrings(match.EvidenceRefs),
		ActorWallets: uniqueSortedFundingOutcomeStrings(match.ActorWallets), Targets: uniqueSortedFundingOutcomeStrings(match.Targets),
		FundingSources: uniqueSortedFundingOutcomeStrings(match.FundingSources),
		IndependenceStatus: "not_independence_proven",
	}
	switch anchor.AnchorID {
	case "KOSCH-BEH-001", "KOSCH-BEH-002":
		anchor.DependencyGroup = "exact_actor_incident_corpus"
		anchor.ProvenanceRoots = []string{"immutable_incident_corpus", "event_transaction_reference", "signed_verdict_artifact"}
		anchor.IndependenceReason = "BEH-001 and BEH-002 are alternate summaries of the same exact-address incident corpus."
	case "KOSCH-BEH-003":
		anchor.DependencyGroup = "funding_outcome_history"
		anchor.ProvenanceRoots = []string{"funding_relation_memory", "signed_verdict_history"}
		anchor.IndependenceReason = "Funding-source recurrence and signed token outcomes form one composite derived anchor."
	case "KOSCH-BEH-004":
		anchor.DependencyGroup = "operational_overlap_memory"
		anchor.ProvenanceRoots = []string{"persistent_actor_operational_memory"}
		anchor.IndependenceReason = "Operational overlap may share underlying actor evidence with other families; v1 does not assert independence."
	case "KOSCH-BEH-005":
		anchor.DependencyGroup = "technical_campaign_genome"
		anchor.ProvenanceRoots = []string{"actor_evidence_descriptors", "campaign_genome_index"}
		anchor.IndependenceReason = "Genome descriptors can include funding-derived relations, so orthogonality to funding anchors is not proven."
	case "KOSCH-BEH-006":
		anchor.DependencyGroup = "persistent_funding_trajectory"
		anchor.ProvenanceRoots = []string{"verified_funding_path", "creator_token_relation", "verified_exit_or_lifecycle", "funding_trajectory_graph"}
		anchor.IndependenceReason = "BEH-006 is derived directly from the persistent funding trajectory."
	case "KOSCH-BEH-007":
		anchor.DependencyGroup = "persistent_funding_trajectory"
		anchor.ProvenanceRoots = []string{"verified_funding_path", "creator_token_relation", "positive_liquidity_timestamp", "verified_exit_or_lifecycle", "funding_trajectory_graph"}
		anchor.IndependenceReason = "BEH-007 re-expresses the same funding trajectory through timing buckets and is not independent of BEH-006."
	default:
		anchor.DependencyGroup = "unknown_behavior_family"
		anchor.ProvenanceRoots = []string{"unknown_provenance"}
		anchor.IndependenceReason = "No explicit dependency contract exists for this behavior family; independence is withheld."
	}
	return anchor
}

func intersectCampaignDependencyStrings(a, b []string) []string {
	set := map[string]bool{}
	for _, value := range a {
		if value = strings.TrimSpace(value); value != "" {
			set[value] = true
		}
	}
	shared := []string{}
	seen := map[string]bool{}
	for _, value := range b {
		value = strings.TrimSpace(value)
		if value != "" && set[value] && !seen[value] {
			seen[value] = true
			shared = append(shared, value)
		}
	}
	sort.Strings(shared)
	return shared
}
