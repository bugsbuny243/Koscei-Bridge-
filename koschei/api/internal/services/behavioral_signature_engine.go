package services

import (
	"sort"
	"strings"
)

const BehavioralSignatureEngineVersion = "koschei-behavioral-signatures-v1"

type BehavioralSignatureMatch struct {
	SignatureID      string   `json:"signature_id"`
	Label            string   `json:"label"`
	Triggered        bool     `json:"triggered"`
	Status           string   `json:"status"`
	EvidenceStatus   string   `json:"evidence_status"`
	GradeEligible    bool     `json:"grade_eligible"`
	VerdictAuthority bool     `json:"verdict_authority"`
	ActorWallets     []string `json:"actor_wallets"`
	Targets          []string `json:"targets"`
	FundingSources   []string `json:"funding_sources"`
	IncidentKeys     []string `json:"incident_keys"`
	EvidenceRefs     []string `json:"evidence_refs"`
	Explanation      string   `json:"explanation"`
	Limitations      []string `json:"limitations"`
}

type BehavioralSignatureReport struct {
	Version                string                     `json:"version"`
	Network                string                     `json:"network"`
	CurrentTarget          string                     `json:"current_target"`
	ActorWallet            string                     `json:"actor_wallet,omitempty"`
	Status                 string                     `json:"status"`
	Complete               bool                       `json:"complete"`
	TriggeredCount         int                        `json:"triggered_count"`
	VerifiedSupportedCount int                        `json:"verified_supported_count"`
	WatchCount             int                        `json:"watch_count"`
	CampaignGenomeID       string                     `json:"campaign_genome_id,omitempty"`
	CampaignPatternHash    string                     `json:"campaign_pattern_hash_sha256,omitempty"`
	Matches                []BehavioralSignatureMatch `json:"matches"`
	Policy                 map[string]any             `json:"policy"`
	Limitations            []string                   `json:"limitations"`
}

func BuildBehavioralSignatureReport(currentTarget string, actorHistory SecurityIncidentCorpusView, funding FundingClusterOutcomeMemory, genome ActorCampaignGenome, operational ActorOperationalMemoryReport) BehavioralSignatureReport {
	return BuildBehavioralSignatureReportWithGenomeMatches(currentTarget, actorHistory, funding, genome, operational, CampaignGenomeMatchReport{})
}

// BuildBehavioralSignatureReportWithGenomeMatches turns already-persisted
// Koschei memory into named, versioned behavior families. v1 is context-only:
// no signature changes a token grade or Guard decision. Exact-address recurrence
// may be VERIFIED when immutable corpus references exist; indirect operational
// or cross-wallet genome overlap remains watch-only.
func BuildBehavioralSignatureReportWithGenomeMatches(currentTarget string, actorHistory SecurityIncidentCorpusView, funding FundingClusterOutcomeMemory, genome ActorCampaignGenome, operational ActorOperationalMemoryReport, genomeMatches CampaignGenomeMatchReport) BehavioralSignatureReport {
	network := normalizeRadarNetwork(actorHistory.Network)
	if strings.TrimSpace(network) == "" {
		network = normalizeRadarNetwork(funding.Network)
	}
	actor := strings.TrimSpace(actorHistory.ActorWallet)
	if actor == "" {
		actor = strings.TrimSpace(genome.ActorWallet)
	}
	out := BehavioralSignatureReport{
		Version: BehavioralSignatureEngineVersion, Network: network, CurrentTarget: strings.TrimSpace(currentTarget),
		ActorWallet: actor, Status: "no_behavior_family_triggered", Complete: true,
		Matches: []BehavioralSignatureMatch{}, Limitations: []string{},
		CampaignGenomeID: strings.TrimSpace(genome.GenomeID), CampaignPatternHash: strings.TrimSpace(genome.PatternHashSHA256),
		Policy: map[string]any{
			"verdict_authority":                        false,
			"grade_authority":                          false,
			"guard_block_authority":                    false,
			"real_world_identity_claim":                false,
			"same_operator_claim":                      false,
			"wrongdoing_claim":                         false,
			"exact_actor_recurrence_is_onchain_only":   true,
			"operational_overlap_is_watch_only":        true,
			"campaign_genome_is_technical_anchor_only": true,
			"cross_wallet_genome_match_is_watch_only":  true,
		},
	}

	out.Matches = append(out.Matches,
		behaviorSignatureExactActorMultiIncident(actorHistory),
		behaviorSignatureRepeatedEventFamily(actorHistory),
		behaviorSignatureFundingOutcomeReuse(funding),
		behaviorSignatureOperationalRotationWatch(operational),
		behaviorSignatureCrossWalletGenomeMatch(genomeMatches),
	)
	for _, match := range out.Matches {
		if !match.Triggered {
			continue
		}
		out.TriggeredCount++
		switch match.Status {
		case "verified_supported":
			out.VerifiedSupportedCount++
		case "observed_watch":
			out.WatchCount++
		}
	}
	if out.TriggeredCount > 0 {
		out.Status = "behavior_families_observed"
	}
	if !actorHistory.Complete || !funding.Complete {
		out.Complete = false
		out.Limitations = append(out.Limitations, "One or more persistent memory inputs are incomplete; absence of a behavior family is not conclusive.")
	}
	if !genome.Complete {
		out.Limitations = append(out.Limitations, "A verified-supported campaign genome anchor is not available for the current actor; cross-address genome matching is not attempted.")
	} else if !genomeMatches.Complete && genomeMatches.Status != "" && genomeMatches.Status != "no_pattern_match" {
		out.Complete = false
		out.Limitations = append(out.Limitations, "Campaign genome index matching is incomplete; cross-wallet technical-pattern absence is not conclusive.")
	}
	out.Limitations = append(out.Limitations,
		"Behavior signatures summarize retained evidence patterns; they do not identify a real-world person or prove common control across different wallets.",
		"v1 signatures are investigation context only and cannot change a customer grade, Guard action or signed final verdict.",
	)
	return out
}

func behaviorSignatureExactActorMultiIncident(history SecurityIncidentCorpusView) BehavioralSignatureMatch {
	match := newBehaviorSignature("KOSCH-BEH-001", "Exact actor across multiple verified incident targets")
	actors := map[string]bool{}
	targets := map[string]bool{}
	keys := map[string]bool{}
	refs := map[string]bool{}
	for _, record := range history.Records {
		actor := strings.TrimSpace(record.ActorWallet)
		target := strings.TrimSpace(record.Target)
		if actor == "" || target == "" || strings.TrimSpace(record.EventSignature) == "" || record.EventSlot <= 0 || strings.TrimSpace(record.VerdictSignature) == "" {
			continue
		}
		actors[actor], targets[target] = true, true
		if record.IncidentKey != "" {
			keys[record.IncidentKey] = true
		}
		refs[record.EventSignature] = true
		refs[record.VerdictSignature] = true
	}
	match.ActorWallets = sortedBehaviorKeys(actors)
	match.Targets = sortedBehaviorKeys(targets)
	match.IncidentKeys = sortedBehaviorKeys(keys)
	match.EvidenceRefs = sortedBehaviorKeys(refs)
	if len(match.ActorWallets) == 1 && len(match.Targets) >= 2 && len(match.IncidentKeys) >= 2 {
		match.Triggered = true
		match.Status = "verified_supported"
		match.EvidenceStatus = "verified"
		match.Explanation = "The same exact on-chain actor address appears in immutable verified incident records for multiple token targets."
		match.Limitations = append(match.Limitations, "Exact-address recurrence proves address reuse only; it does not prove who controls the wallet or that the actor caused each token verdict.")
	}
	return match
}

func behaviorSignatureRepeatedEventFamily(history SecurityIncidentCorpusView) BehavioralSignatureMatch {
	match := newBehaviorSignature("KOSCH-BEH-002", "Repeated verified incident event family")
	type family struct {
		actors  map[string]bool
		targets map[string]bool
		keys    map[string]bool
		refs    map[string]bool
	}
	families := map[string]*family{}
	for _, record := range history.Records {
		kind := strings.TrimSpace(record.EventKind)
		actor := strings.TrimSpace(record.ActorWallet)
		target := strings.TrimSpace(record.Target)
		if kind == "" || actor == "" || target == "" || record.EventSlot <= 0 || record.EventSignature == "" || record.VerdictSignature == "" {
			continue
		}
		item := families[kind]
		if item == nil {
			item = &family{actors: map[string]bool{}, targets: map[string]bool{}, keys: map[string]bool{}, refs: map[string]bool{}}
			families[kind] = item
		}
		item.actors[actor], item.targets[target] = true, true
		if record.IncidentKey != "" {
			item.keys[record.IncidentKey] = true
		}
		item.refs[record.EventSignature], item.refs[record.VerdictSignature] = true, true
	}
	kinds := make([]string, 0, len(families))
	for kind := range families {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		item := families[kind]
		if len(item.actors) != 1 || len(item.targets) < 2 || len(item.keys) < 2 {
			continue
		}
		match.Triggered = true
		match.Status = "verified_supported"
		match.EvidenceStatus = "verified"
		match.ActorWallets = sortedBehaviorKeys(item.actors)
		match.Targets = sortedBehaviorKeys(item.targets)
		match.IncidentKeys = sortedBehaviorKeys(item.keys)
		match.EvidenceRefs = sortedBehaviorKeys(item.refs)
		match.Explanation = "The same exact actor address repeats the verified incident event family '" + kind + "' across multiple token targets."
		match.Limitations = append(match.Limitations, "Repeated event-family evidence is a technical recurrence signal, not proof of real-world identity or malicious intent.")
		break
	}
	return match
}

func behaviorSignatureFundingOutcomeReuse(funding FundingClusterOutcomeMemory) BehavioralSignatureMatch {
	match := newBehaviorSignature("KOSCH-BEH-003", "Funding source reused across material signed token outcomes")
	sources := map[string]bool{}
	targets := map[string]bool{}
	for _, source := range funding.Sources {
		if source.MaterialRiskTargetCount < 2 {
			continue
		}
		funder := strings.TrimSpace(source.FundingSource)
		if funder == "" {
			continue
		}
		sources[funder] = true
		for _, target := range source.Targets {
			if !target.MaterialRiskHistory || target.SignedVerdictCount == 0 {
				continue
			}
			if value := strings.TrimSpace(target.Target); value != "" {
				targets[value] = true
			}
		}
	}
	match.FundingSources = sortedBehaviorKeys(sources)
	match.Targets = sortedBehaviorKeys(targets)
	if len(match.FundingSources) > 0 && len(match.Targets) >= 2 {
		match.Triggered = true
		match.Status = "observed_watch"
		match.EvidenceStatus = "observed"
		match.Explanation = "A recurrent on-chain funding source is linked to multiple targets that later received signed material Koschei verdicts."
		match.Limitations = append(match.Limitations, "Funding relation plus historical token outcome does not prove the funder controlled or caused those outcomes; this signature remains watch-only.")
	}
	return match
}

func behaviorSignatureOperationalRotationWatch(operational ActorOperationalMemoryReport) BehavioralSignatureMatch {
	match := newBehaviorSignature("KOSCH-BEH-004", "Cross-wallet operational overlap candidate")
	actors := map[string]bool{}
	refs := map[string]bool{}
	for _, item := range operational.Matches {
		switch strings.TrimSpace(item.Classification) {
		case "repeated_operational_overlap", "repeated_funding_overlap":
		default:
			continue
		}
		if wallet := strings.TrimSpace(item.Wallet); wallet != "" {
			actors[wallet] = true
		}
		for _, rule := range item.Rules {
			if rule = strings.TrimSpace(rule); rule != "" {
				refs[rule] = true
			}
		}
	}
	match.ActorWallets = sortedBehaviorKeys(actors)
	match.EvidenceRefs = sortedBehaviorKeys(refs)
	if len(match.ActorWallets) > 0 {
		match.Triggered = true
		match.Status = "observed_watch"
		match.EvidenceStatus = "observed"
		match.Explanation = "Persistent actor memory contains repeated operational overlap with other on-chain wallet addresses."
		match.Limitations = append(match.Limitations, "Different wallet addresses are not merged into one actor. This is an address-rotation investigation candidate only and never an identity claim.")
	}
	return match
}

func behaviorSignatureCrossWalletGenomeMatch(genomeMatches CampaignGenomeMatchReport) BehavioralSignatureMatch {
	match := newBehaviorSignature("KOSCH-BEH-005", "Same technical campaign genome across different wallet addresses")
	actors := map[string]bool{}
	refs := map[string]bool{}
	for _, item := range genomeMatches.Matches {
		if actor := strings.TrimSpace(item.ActorWallet); actor != "" {
			actors[actor] = true
		}
		if key := strings.TrimSpace(item.SnapshotKey); key != "" {
			refs[key] = true
		}
		if hash := strings.TrimSpace(item.RecordHash); hash != "" {
			refs[hash] = true
		}
	}
	match.ActorWallets = sortedBehaviorKeys(actors)
	match.EvidenceRefs = sortedBehaviorKeys(refs)
	if genomeMatches.Available && genomeMatches.MatchCount > 0 && len(match.ActorWallets) > 0 {
		match.Triggered = true
		match.Status = "observed_watch"
		match.EvidenceStatus = "observed"
		match.Explanation = "The current verified-supported technical campaign genome has the same normalized pattern hash as snapshots from other wallet addresses."
		match.Limitations = append(match.Limitations,
			"The genome pattern excludes counterpart addresses and token mints, so this is useful against address rotation; however, the match proves technical-pattern similarity only and never common control or identity.",
		)
	}
	return match
}

func newBehaviorSignature(id, label string) BehavioralSignatureMatch {
	return BehavioralSignatureMatch{
		SignatureID: id, Label: label, Status: "not_triggered", EvidenceStatus: "not_observed",
		GradeEligible: false, VerdictAuthority: false,
		ActorWallets: []string{}, Targets: []string{}, FundingSources: []string{}, IncidentKeys: []string{}, EvidenceRefs: []string{}, Limitations: []string{},
	}
}

func sortedBehaviorKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
