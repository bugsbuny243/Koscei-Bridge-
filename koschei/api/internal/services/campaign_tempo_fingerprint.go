package services

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

const (
	CampaignTempoFingerprintVersion  = "koschei-campaign-tempo-fingerprint-v1"
	BehavioralSignatureTempoVersion  = "koschei-behavioral-signatures-v1.2"
	BehavioralSignatureTempoID       = "KOSCH-BEH-007"
)

type CampaignTempoPath struct {
	FundingSourceWallet              string   `json:"funding_source_wallet"`
	ActorWallet                      string   `json:"actor_wallet"`
	TokenMint                        string   `json:"token_mint"`
	TerminalFamily                   string   `json:"terminal_family"`
	FundingObservedAt                string   `json:"funding_observed_at"`
	CreationObservedAt               string   `json:"creation_observed_at"`
	FirstLiquidityObservedAt         string   `json:"first_liquidity_observed_at"`
	TerminalObservedAt               string   `json:"terminal_observed_at"`
	FundingToCreationSeconds         int64    `json:"funding_to_creation_seconds"`
	CreationToFirstLiquiditySeconds  int64    `json:"creation_to_first_liquidity_seconds"`
	FirstLiquidityToTerminalSeconds  int64    `json:"first_liquidity_to_terminal_seconds"`
	FundingToCreationBin             string   `json:"funding_to_creation_bin"`
	CreationToFirstLiquidityBin      string   `json:"creation_to_first_liquidity_bin"`
	FirstLiquidityToTerminalBin      string   `json:"first_liquidity_to_terminal_bin"`
	TempoProfile                     string   `json:"tempo_profile"`
	EvidenceRefs                     []string `json:"evidence_refs"`
}

type CampaignTempoFingerprintReport struct {
	Version                string              `json:"version"`
	Network                string              `json:"network"`
	SubjectWallet          string              `json:"subject_wallet"`
	Available              bool                `json:"available"`
	Complete               bool                `json:"complete"`
	Status                 string              `json:"status"`
	PathCount              int                 `json:"path_count"`
	DistinctActorCount     int                 `json:"distinct_actor_count"`
	DistinctTokenCount     int                 `json:"distinct_token_count"`
	DistinctFundingSources int                 `json:"distinct_funding_source_count"`
	Paths                  []CampaignTempoPath `json:"paths"`
	FingerprintSHA256      string              `json:"fingerprint_sha256"`
	VerdictAuthority       bool                `json:"verdict_authority"`
	SameOperatorClaim      bool                `json:"same_operator_claim"`
	RealWorldIdentityClaim bool                `json:"real_world_identity_claim"`
	RugClaim               bool                `json:"rug_claim"`
	WrongdoingClaim        bool                `json:"wrongdoing_claim"`
	Limitations            []string            `json:"limitations"`
}

type campaignTempoFundingEvent struct {
	funder string
	actor  string
	at     time.Time
	ref    string
}

type campaignTempoCreationEvent struct {
	actor string
	token string
	at    time.Time
	ref   string
}

type campaignTempoTerminalEvent struct {
	actor  string
	token  string
	family string
	at     time.Time
	ref    string
}

// BuildCampaignTempoFingerprint derives a deterministic timing profile from the
// already-retained trajectory graph. It does not infer missing timestamps. A
// path is eligible only when Koschei has a VERIFIED funding edge, a VERIFIED
// creator/token edge, a retained first-positive-liquidity timestamp, and a
// VERIFIED terminal exit/lifecycle edge in chronological order.
func BuildCampaignTempoFingerprint(graph PersistentFundingTrajectoryGraph) CampaignTempoFingerprintReport {
	out := CampaignTempoFingerprintReport{
		Version:       CampaignTempoFingerprintVersion,
		Network:       normalizeRadarNetwork(graph.Network),
		SubjectWallet: strings.TrimSpace(graph.SubjectWallet),
		Complete:      graph.Complete,
		Status:        "no_complete_verified_tempo_path",
		Paths:         []CampaignTempoPath{},
		Limitations: []string{
			"Tempo bins are deterministic operational buckets, not statistical proof of common control, identity, intent or wrongdoing.",
			"Only complete chronological paths with verified funding, verified creation, observed positive liquidity and a verified terminal event are fingerprinted.",
			"A repeated inactive lifecycle tempo is not a rug classification.",
			"Missing timing evidence withholds a path; it is not interpreted as safety or as a different tempo.",
		},
	}

	fundingByActor := map[string][]campaignTempoFundingEvent{}
	creationByActorToken := map[string]campaignTempoCreationEvent{}
	firstLiquidityByActorToken := map[string]time.Time{}
	terminalByActorTokenFamily := map[string]campaignTempoTerminalEvent{}

	for _, edge := range graph.Edges {
		source := strings.TrimSpace(edge.SourceID)
		target := strings.TrimSpace(edge.TargetID)
		if source == "" || target == "" {
			continue
		}
		edgeAt, edgeTimeOK := parseCampaignTempoTime(edge.ObservedAt)
		switch strings.TrimSpace(edge.EvidenceKind) {
		case "funding":
			if !edgeTimeOK || edge.EvidenceState != "verified" || edge.SourceKind != "wallet" || edge.TargetKind != "wallet" {
				continue
			}
			fundingByActor[target] = append(fundingByActor[target], campaignTempoFundingEvent{
				funder: source, actor: target, at: edgeAt, ref: strings.TrimSpace(edge.Signature),
			})
		case "creation":
			if !edgeTimeOK || edge.EvidenceState != "verified" || edge.SourceKind != "wallet" || edge.TargetKind != "token" {
				continue
			}
			key := trajectoryActorTokenKey(source, target)
			current, exists := creationByActorToken[key]
			if !exists || edgeAt.Before(current.at) {
				creationByActorToken[key] = campaignTempoCreationEvent{
					actor: source, token: target, at: edgeAt, ref: strings.TrimSpace(edge.Signature),
				}
			}
		case "lifecycle":
			if edge.SourceKind != "wallet" || edge.TargetKind != "token" {
				continue
			}
			key := trajectoryActorTokenKey(source, target)
			if liquidAt, ok := campaignTempoMetadataTime(edge.Metadata, "first_liquid_observed_at"); ok {
				current, exists := firstLiquidityByActorToken[key]
				if !exists || liquidAt.Before(current) {
					firstLiquidityByActorToken[key] = liquidAt
				}
			}
			if edge.EvidenceState != "verified" || strings.TrimSpace(edge.Relation) != "lifecycle_inactive_or_dead" {
				continue
			}
			terminalAt, ok := campaignTempoMetadataTime(edge.Metadata, "current_inactive_since")
			if !ok {
				continue
			}
			family := "lifecycle:inactive_or_dead"
			terminalKey := key + "\x00" + family
			current, exists := terminalByActorTokenFamily[terminalKey]
			if !exists || terminalAt.Before(current.at) {
				terminalByActorTokenFamily[terminalKey] = campaignTempoTerminalEvent{
					actor: source, token: target, family: family, at: terminalAt,
				}
			}
		case "exit_event":
			if !edgeTimeOK || edge.EvidenceState != "verified" || edge.SourceKind != "wallet" || edge.TargetKind != "token" {
				continue
			}
			relation := strings.TrimSpace(edge.Relation)
			if relation == "" {
				continue
			}
			key := trajectoryActorTokenKey(source, target)
			family := "exit_event:" + relation
			terminalKey := key + "\x00" + family
			current, exists := terminalByActorTokenFamily[terminalKey]
			if !exists || edgeAt.Before(current.at) {
				terminalByActorTokenFamily[terminalKey] = campaignTempoTerminalEvent{
					actor: source, token: target, family: family, at: edgeAt, ref: strings.TrimSpace(edge.Signature),
				}
			}
		}
	}

	for actor := range fundingByActor {
		sort.SliceStable(fundingByActor[actor], func(i, j int) bool {
			if !fundingByActor[actor][i].at.Equal(fundingByActor[actor][j].at) {
				return fundingByActor[actor][i].at.Before(fundingByActor[actor][j].at)
			}
			return fundingByActor[actor][i].funder < fundingByActor[actor][j].funder
		})
	}

	keys := make([]string, 0, len(terminalByActorTokenFamily))
	for key := range terminalByActorTokenFamily {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, terminalKey := range keys {
		terminal := terminalByActorTokenFamily[terminalKey]
		actorTokenKey := trajectoryActorTokenKey(terminal.actor, terminal.token)
		creation, creationOK := creationByActorToken[actorTokenKey]
		liquidAt, liquidityOK := firstLiquidityByActorToken[actorTokenKey]
		if !creationOK || !liquidityOK || liquidAt.Before(creation.at) || terminal.at.Before(liquidAt) {
			continue
		}
		funding := latestCampaignTempoFundingBefore(fundingByActor[terminal.actor], creation.at)
		if funding == nil || creation.at.Before(funding.at) {
			continue
		}

		fundingToCreation := int64(creation.at.Sub(funding.at) / time.Second)
		creationToLiquidity := int64(liquidAt.Sub(creation.at) / time.Second)
		liquidityToTerminal := int64(terminal.at.Sub(liquidAt) / time.Second)
		if fundingToCreation < 0 || creationToLiquidity < 0 || liquidityToTerminal < 0 {
			continue
		}
		fundingBin := campaignTempoDurationBin(fundingToCreation)
		liquidityBin := campaignTempoDurationBin(creationToLiquidity)
		terminalBin := campaignTempoDurationBin(liquidityToTerminal)
		profile := terminal.family + "|f2c=" + fundingBin + "|c2l=" + liquidityBin + "|l2t=" + terminalBin
		refs := []string{}
		if funding.ref != "" {
			refs = append(refs, funding.ref)
		}
		if creation.ref != "" {
			refs = append(refs, creation.ref)
		}
		if terminal.ref != "" {
			refs = append(refs, terminal.ref)
		}
		if graph.EvidenceHashSHA256 != "" {
			refs = append(refs, graph.EvidenceHashSHA256)
		}
		out.Paths = append(out.Paths, CampaignTempoPath{
			FundingSourceWallet:             funding.funder,
			ActorWallet:                     terminal.actor,
			TokenMint:                       terminal.token,
			TerminalFamily:                  terminal.family,
			FundingObservedAt:               funding.at.UTC().Format(time.RFC3339Nano),
			CreationObservedAt:              creation.at.UTC().Format(time.RFC3339Nano),
			FirstLiquidityObservedAt:        liquidAt.UTC().Format(time.RFC3339Nano),
			TerminalObservedAt:              terminal.at.UTC().Format(time.RFC3339Nano),
			FundingToCreationSeconds:        fundingToCreation,
			CreationToFirstLiquiditySeconds: creationToLiquidity,
			FirstLiquidityToTerminalSeconds: liquidityToTerminal,
			FundingToCreationBin:            fundingBin,
			CreationToFirstLiquidityBin:     liquidityBin,
			FirstLiquidityToTerminalBin:     terminalBin,
			TempoProfile:                    profile,
			EvidenceRefs:                    uniqueSortedFundingOutcomeStrings(refs),
		})
	}

	sort.SliceStable(out.Paths, func(i, j int) bool {
		if out.Paths[i].FundingSourceWallet != out.Paths[j].FundingSourceWallet {
			return out.Paths[i].FundingSourceWallet < out.Paths[j].FundingSourceWallet
		}
		if out.Paths[i].TempoProfile != out.Paths[j].TempoProfile {
			return out.Paths[i].TempoProfile < out.Paths[j].TempoProfile
		}
		if out.Paths[i].ActorWallet != out.Paths[j].ActorWallet {
			return out.Paths[i].ActorWallet < out.Paths[j].ActorWallet
		}
		return out.Paths[i].TokenMint < out.Paths[j].TokenMint
	})
	actors := map[string]bool{}
	tokens := map[string]bool{}
	funders := map[string]bool{}
	for _, path := range out.Paths {
		actors[path.ActorWallet] = true
		tokens[path.TokenMint] = true
		funders[path.FundingSourceWallet] = true
	}
	out.PathCount = len(out.Paths)
	out.DistinctActorCount = len(actors)
	out.DistinctTokenCount = len(tokens)
	out.DistinctFundingSources = len(funders)
	out.Available = out.PathCount > 0
	if out.Available {
		out.Status = "verified_campaign_tempo_paths_observed"
	}
	out.FingerprintSHA256 = hashCampaignTempoFingerprint(out)
	return out
}

func BuildBehavioralSignatureReportWithTempo(
	currentTarget string,
	actorHistory SecurityIncidentCorpusView,
	funding FundingClusterOutcomeMemory,
	genome ActorCampaignGenome,
	operational ActorOperationalMemoryReport,
	genomeMatches CampaignGenomeMatchReport,
	trajectory PersistentFundingTrajectoryGraph,
	tempo CampaignTempoFingerprintReport,
) BehavioralSignatureReport {
	out := BuildBehavioralSignatureReportWithTrajectory(
		currentTarget,
		actorHistory,
		funding,
		genome,
		operational,
		genomeMatches,
		trajectory,
	)
	out.Version = BehavioralSignatureTempoVersion
	if out.Policy == nil {
		out.Policy = map[string]any{}
	}
	out.Policy["campaign_tempo_recurrence_is_watch_only"] = true
	out.Policy["campaign_tempo_requires_verified_funding_creation_terminal"] = true
	out.Policy["campaign_tempo_requires_positive_liquidity_timestamp"] = true
	out.Policy["tempo_bins_are_operational_not_identity_evidence"] = true

	match := behaviorSignatureCampaignTempoRecurrence(tempo)
	out.Matches = append(out.Matches, match)
	if match.Triggered {
		out.TriggeredCount++
		out.WatchCount++
		out.Status = "behavior_families_observed"
	}
	if !tempo.Complete {
		out.Complete = false
		out.Limitations = append(out.Limitations, "Campaign tempo evidence is incomplete; absence of KOSCH-BEH-007 is not conclusive.")
	}
	out.Limitations = append(out.Limitations,
		"KOSCH-BEH-007 is a timing-pattern correlation across distinct on-chain addresses and cannot identify a real-world operator or prove common control.",
	)
	return out
}

func behaviorSignatureCampaignTempoRecurrence(tempo CampaignTempoFingerprintReport) BehavioralSignatureMatch {
	match := newBehaviorSignature(BehavioralSignatureTempoID, "Recurring verified campaign tempo across distinct funded actors")
	type bucket struct {
		funder  string
		profile string
		actors  map[string]bool
		tokens  map[string]bool
		refs    map[string]bool
	}
	buckets := map[string]*bucket{}
	for _, path := range tempo.Paths {
		funder := strings.TrimSpace(path.FundingSourceWallet)
		profile := strings.TrimSpace(path.TempoProfile)
		actor := strings.TrimSpace(path.ActorWallet)
		token := strings.TrimSpace(path.TokenMint)
		if funder == "" || profile == "" || actor == "" || token == "" {
			continue
		}
		key := funder + "\x00" + profile
		item := buckets[key]
		if item == nil {
			item = &bucket{funder: funder, profile: profile, actors: map[string]bool{}, tokens: map[string]bool{}, refs: map[string]bool{}}
			buckets[key] = item
		}
		item.actors[actor] = true
		item.tokens[token] = true
		for _, ref := range path.EvidenceRefs {
			if strings.TrimSpace(ref) != "" {
				item.refs[strings.TrimSpace(ref)] = true
			}
		}
	}

	keys := make([]string, 0, len(buckets))
	for key := range buckets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	profiles := []string{}
	actors := map[string]bool{}
	tokens := map[string]bool{}
	funders := map[string]bool{}
	refs := map[string]bool{}
	for _, key := range keys {
		item := buckets[key]
		if len(item.actors) < 2 || len(item.tokens) < 2 {
			continue
		}
		profiles = append(profiles, item.profile)
		funders[item.funder] = true
		for actor := range item.actors {
			actors[actor] = true
		}
		for token := range item.tokens {
			tokens[token] = true
		}
		for ref := range item.refs {
			refs[ref] = true
		}
	}
	if len(profiles) == 0 {
		return match
	}
	if tempo.FingerprintSHA256 != "" {
		refs[tempo.FingerprintSHA256] = true
	}

	match.Triggered = true
	match.Status = "observed_watch"
	match.EvidenceStatus = "observed"
	match.ActorWallets = sortedBehaviorKeys(actors)
	match.Targets = sortedBehaviorKeys(tokens)
	match.FundingSources = sortedBehaviorKeys(funders)
	match.EvidenceRefs = sortedBehaviorKeys(refs)
	match.Explanation = "Distinct funded actor addresses repeat the same complete verified campaign-tempo profile: " + strings.Join(uniqueSortedFundingOutcomeStrings(profiles), ", ") + "."
	match.Limitations = append(match.Limitations,
		"Matching deterministic time buckets are investigation context only; timing similarity can occur coincidentally and does not prove shared control, identity, intent or wrongdoing.",
		"The time-bucket boundaries are a versioned engineering convention, not a learned or population-calibrated probability model.",
	)
	return match
}

func latestCampaignTempoFundingBefore(events []campaignTempoFundingEvent, before time.Time) *campaignTempoFundingEvent {
	var selected *campaignTempoFundingEvent
	for i := range events {
		if events[i].at.After(before) {
			continue
		}
		if selected == nil || events[i].at.After(selected.at) || (events[i].at.Equal(selected.at) && events[i].funder < selected.funder) {
			copy := events[i]
			selected = &copy
		}
	}
	return selected
}

func campaignTempoDurationBin(seconds int64) string {
	switch {
	case seconds < 300:
		return "lt_5m"
	case seconds < 1800:
		return "5m_30m"
	case seconds < 7200:
		return "30m_2h"
	case seconds < 43200:
		return "2h_12h"
	case seconds < 172800:
		return "12h_48h"
	case seconds < 604800:
		return "2d_7d"
	default:
		return "gte_7d"
	}
}

func parseCampaignTempoTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

func campaignTempoMetadataTime(metadata map[string]any, key string) (time.Time, bool) {
	if metadata == nil {
		return time.Time{}, false
	}
	value, ok := metadata[key]
	if !ok || value == nil {
		return time.Time{}, false
	}
	switch typed := value.(type) {
	case string:
		return parseCampaignTempoTime(typed)
	case time.Time:
		return typed.UTC(), true
	default:
		return parseCampaignTempoTime(strings.TrimSpace(toString(typed)))
	}
}

func hashCampaignTempoFingerprint(report CampaignTempoFingerprintReport) string {
	copy := report
	copy.FingerprintSHA256 = ""
	payload, err := json.Marshal(copy)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}
