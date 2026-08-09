package services

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

const ActorCampaignGenomeVersion = "koschei-technical-campaign-genome-v1"

type ActorCampaignGenomeDescriptor struct {
	Kind               string   `json:"kind"`
	Value              string   `json:"value"`
	EvidenceStatus     string   `json:"evidence_status"`
	EvidenceKeys       []string `json:"evidence_keys,omitempty"`
	Signatures         []string `json:"signatures,omitempty"`
	SignatureBacked    bool     `json:"signature_backed"`
	GradeEligible      bool     `json:"grade_eligible"`
	VerificationWeight string   `json:"verification_weight"`
}

type ActorCampaignGenome struct {
	Version                    string                          `json:"version"`
	ActorWallet                string                          `json:"actor_wallet"`
	Network                    string                          `json:"network"`
	Status                     string                          `json:"status"`
	Complete                   bool                            `json:"complete"`
	GenomeID                   string                          `json:"genome_id,omitempty"`
	PatternHashSHA256          string                          `json:"pattern_hash_sha256,omitempty"`
	EvidenceHashSHA256         string                          `json:"evidence_hash_sha256"`
	DescriptorCount            int                             `json:"descriptor_count"`
	VerifiedDescriptorCount    int                             `json:"verified_descriptor_count"`
	ObservedDescriptorCount    int                             `json:"observed_descriptor_count"`
	VerifiedSignatureBacked    int                             `json:"verified_signature_backed_descriptor_count"`
	WatchDescriptorCount       int                             `json:"watch_descriptor_count"`
	ExcludedUnverifiedEvidence int                             `json:"excluded_unverified_evidence_count"`
	Descriptors                []ActorCampaignGenomeDescriptor `json:"descriptors"`
	WatchDescriptors           []ActorCampaignGenomeDescriptor `json:"watch_descriptors"`
	Limitations                []string                        `json:"limitations"`
	Policy                     map[string]any                  `json:"policy"`
}

type actorCampaignDescriptorBuilder struct {
	kind            string
	value           string
	strongestStatus string
	evidenceKeys    map[string]struct{}
	signatures      map[string]struct{}
	gradeEligible   bool
	signatureBacked bool
}

// BuildActorCampaignGenome creates a technical behavior fingerprint from
// persisted actor evidence. It never maps a wallet to a real-world person and
// never treats the resulting genome as proof of common control or wrongdoing.
func BuildActorCampaignGenome(dossier ActorDefenseDossier) ActorCampaignGenome {
	actor := strings.TrimSpace(dossier.Wallet)
	network := normalizeRadarNetwork(dossier.Network)
	out := ActorCampaignGenome{
		Version:          ActorCampaignGenomeVersion,
		ActorWallet:      actor,
		Network:          network,
		Status:           "insufficient",
		Descriptors:      []ActorCampaignGenomeDescriptor{},
		WatchDescriptors: []ActorCampaignGenomeDescriptor{},
		Limitations:      []string{},
		Policy: map[string]any{
			"technical_pattern_only":              true,
			"same_genome_is_not_same_person":       true,
			"identity_or_wrongdoing_claim":          false,
			"verified_required_for_genome_id":       true,
			"signature_and_slot_required_for_anchor": true,
			"inferred_policy":                       "watch_only",
			"unverified_policy":                     "excluded",
			"possible_dust_policy":                  "watch_only",
			"counterpart_addresses_in_pattern_hash": false,
			"token_mints_in_pattern_hash":           false,
		},
	}
	if actor == "" {
		out.Limitations = append(out.Limitations, "Actor wallet is unavailable; no technical campaign genome can be issued.")
		out.EvidenceHashSHA256 = actorCampaignGenomeEvidenceHash(out)
		return out
	}

	active := map[string]*actorCampaignDescriptorBuilder{}
	watch := map[string]*actorCampaignDescriptorBuilder{}
	for _, item := range dossier.Evidence {
		status := normalizeActorEvidenceStatus(item.VerificationStatus)
		if status == "unverified" {
			out.ExcludedUnverifiedEvidence++
			continue
		}
		line := BuildActorDefenseEvidenceLine(item)
		if status == "inferred" || line.PossibleDust || line.AddressPoisoningCandidate || !line.GradeEligible {
			actorCampaignCollectEvidenceDescriptors(watch, item, line, status, false)
			continue
		}
		if status != "verified" && status != "observed" {
			continue
		}
		actorCampaignCollectEvidenceDescriptors(active, item, line, status, true)
	}
	actorCampaignCollectTrackDescriptors(active, dossier.Track)

	out.Descriptors = actorCampaignFinalizeDescriptors(active)
	out.WatchDescriptors = actorCampaignFinalizeDescriptors(watch)
	out.DescriptorCount = len(out.Descriptors)
	out.WatchDescriptorCount = len(out.WatchDescriptors)
	for _, descriptor := range out.Descriptors {
		switch descriptor.EvidenceStatus {
		case "verified":
			out.VerifiedDescriptorCount++
			if descriptor.SignatureBacked {
				out.VerifiedSignatureBacked++
			}
		case "observed":
			out.ObservedDescriptorCount++
		}
	}

	patternHash := actorCampaignGenomePatternHash(out.Descriptors)
	if out.DescriptorCount < 2 {
		out.Limitations = append(out.Limitations, "Fewer than two distinct technical behavior descriptors are available.")
	} else if out.VerifiedSignatureBacked < 1 {
		out.Status = "observed_only"
		out.Limitations = append(out.Limitations, "No VERIFIED descriptor is anchored by complete signature-and-slot evidence; no campaign genome ID is issued.")
	} else {
		out.Status = "verified_supported"
		out.Complete = true
		out.PatternHashSHA256 = patternHash
		out.GenomeID = actorCampaignGenomeID(patternHash)
	}
	if !out.Complete && out.Status == "insufficient" && out.ObservedDescriptorCount > 0 {
		out.Status = "observed_only"
	}
	out.EvidenceHashSHA256 = actorCampaignGenomeEvidenceHash(out)
	return out
}

func actorCampaignCollectEvidenceDescriptors(target map[string]*actorCampaignDescriptorBuilder, item ActorDefenseEvidenceRecord, line ActorDefenseEvidenceLine, status string, gradeEligible bool) {
	relation := strings.ToLower(strings.TrimSpace(item.Relation))
	program := strings.ToLower(strings.TrimSpace(line.Program))
	role := strings.ToLower(strings.TrimSpace(line.ActorRole))
	counterpartKind := strings.ToLower(strings.TrimSpace(item.CounterpartKind))
	assetClass := actorCampaignAssetClass(item)
	if relation == "" {
		return
	}
	patterns := [][2]string{{"relation", relation}}
	if program != "" {
		patterns = append(patterns, [2]string{"relation_program", relation + "|" + program})
	}
	if role != "" {
		patterns = append(patterns, [2]string{"role_relation", role + "|" + relation})
	}
	if counterpartKind != "" {
		patterns = append(patterns, [2]string{"counterpart_relation", counterpartKind + "|" + relation})
	}
	if assetClass != "" {
		patterns = append(patterns, [2]string{"asset_relation", assetClass + "|" + relation})
	}
	for _, pattern := range patterns {
		actorCampaignUpsertDescriptor(target, pattern[0], pattern[1], item, status, gradeEligible)
	}
}

func actorCampaignCollectTrackDescriptors(target map[string]*actorCampaignDescriptorBuilder, track ActorDefenseTrack) {
	if track.CreatedTokenCount >= 2 {
		actorCampaignUpsertSyntheticDescriptor(target, "recurrence", "creator_deployer_multi_token", "observed")
	}
	if track.DominantHolderTokenCount >= 2 {
		actorCampaignUpsertSyntheticDescriptor(target, "recurrence", "dominant_holder_multi_token", "observed")
	}
	if track.RelatedActorCount > 0 && actorDefenseStateRank(track.State) >= actorDefenseStateRank("correlated") {
		actorCampaignUpsertSyntheticDescriptor(target, "recurrence", "cross_token_related_actor", "observed")
	}
}

func actorCampaignUpsertDescriptor(target map[string]*actorCampaignDescriptorBuilder, kind, value string, item ActorDefenseEvidenceRecord, status string, gradeEligible bool) {
	kind = strings.TrimSpace(kind)
	value = strings.TrimSpace(value)
	if kind == "" || value == "" {
		return
	}
	key := kind + "|" + value
	builder := target[key]
	if builder == nil {
		builder = &actorCampaignDescriptorBuilder{kind: kind, value: value, evidenceKeys: map[string]struct{}{}, signatures: map[string]struct{}{}, gradeEligible: gradeEligible}
		target[key] = builder
	}
	builder.gradeEligible = builder.gradeEligible || gradeEligible
	if actorGraphStatusRank(status) > actorGraphStatusRank(builder.strongestStatus) {
		builder.strongestStatus = normalizeActorGraphStatus(status)
	}
	if evidenceKey := strings.TrimSpace(item.EvidenceKey); evidenceKey != "" {
		builder.evidenceKeys[evidenceKey] = struct{}{}
	}
	if signature := strings.TrimSpace(item.Signature); signature != "" {
		builder.signatures[signature] = struct{}{}
		if item.Slot > 0 && !item.ObservedAt.IsZero() && normalizeActorGraphStatus(status) == "verified" {
			builder.signatureBacked = true
		}
	}
}

func actorCampaignUpsertSyntheticDescriptor(target map[string]*actorCampaignDescriptorBuilder, kind, value, status string) {
	key := kind + "|" + value
	if target[key] != nil {
		return
	}
	target[key] = &actorCampaignDescriptorBuilder{
		kind: kind, value: value, strongestStatus: normalizeActorGraphStatus(status),
		evidenceKeys: map[string]struct{}{}, signatures: map[string]struct{}{}, gradeEligible: true,
	}
}

func actorCampaignFinalizeDescriptors(builders map[string]*actorCampaignDescriptorBuilder) []ActorCampaignGenomeDescriptor {
	keys := make([]string, 0, len(builders))
	for key := range builders {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]ActorCampaignGenomeDescriptor, 0, len(keys))
	for _, key := range keys {
		builder := builders[key]
		evidenceKeys := actorCampaignSortedSet(builder.evidenceKeys)
		signatures := actorCampaignSortedSet(builder.signatures)
		status := normalizeActorGraphStatus(builder.strongestStatus)
		out = append(out, ActorCampaignGenomeDescriptor{
			Kind: builder.kind, Value: builder.value, EvidenceStatus: status,
			EvidenceKeys: evidenceKeys, Signatures: signatures,
			SignatureBacked: builder.signatureBacked, GradeEligible: builder.gradeEligible,
			VerificationWeight: actorCampaignVerificationWeight(status),
		})
	}
	return out
}

func actorCampaignGenomePatternHash(descriptors []ActorCampaignGenomeDescriptor) string {
	type pattern struct {
		Kind  string `json:"kind"`
		Value string `json:"value"`
	}
	patterns := make([]pattern, 0, len(descriptors))
	for _, descriptor := range descriptors {
		if !descriptor.GradeEligible {
			continue
		}
		patterns = append(patterns, pattern{Kind: descriptor.Kind, Value: descriptor.Value})
	}
	sort.Slice(patterns, func(i, j int) bool {
		if patterns[i].Kind == patterns[j].Kind {
			return patterns[i].Value < patterns[j].Value
		}
		return patterns[i].Kind < patterns[j].Kind
	})
	payload, _ := json.Marshal(patterns)
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func actorCampaignGenomeID(patternHash string) string {
	value := strings.TrimPrefix(strings.TrimSpace(patternHash), "sha256:")
	if len(value) < 16 {
		return ""
	}
	return "KCG1-" + strings.ToUpper(value[:16])
}

func actorCampaignGenomeEvidenceHash(genome ActorCampaignGenome) string {
	genome.EvidenceHashSHA256 = ""
	payload, _ := json.Marshal(genome)
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func actorCampaignAssetClass(item ActorDefenseEvidenceRecord) string {
	if strings.TrimSpace(item.TokenMint) != "" || item.TokenAmount != 0 {
		return "token"
	}
	if item.AmountNative != 0 {
		return "native_sol"
	}
	return "none"
}

func actorCampaignSortedSet(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func actorCampaignVerificationWeight(status string) string {
	switch normalizeActorGraphStatus(status) {
	case "verified":
		return "campaign_pattern_eligible"
	case "observed":
		return "supporting_pattern_only"
	case "inferred":
		return "watch_only"
	default:
		return "excluded"
	}
}
