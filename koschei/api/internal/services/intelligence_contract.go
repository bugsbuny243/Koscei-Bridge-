package services

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"time"
)

const (
	IntelligenceContractVersion = "koschei-intelligence-contract-v1"

	IntelligenceChainFamilyEVM     = "evm"
	IntelligenceChainFamilySolana  = "solana"
	IntelligenceChainFamilyUnknown = "unknown"

	IntelligenceSubjectAddress = "address"
	IntelligenceSubjectUnknown = "unknown"

	IntelligenceEvidenceVerified   = "verified"
	IntelligenceEvidenceObserved   = "observed"
	IntelligenceEvidenceInferred   = "inferred"
	IntelligenceEvidenceUnverified = "unverified"
)

var evmAddressPattern = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)

type IntelligenceSubject struct {
	ID                  string `json:"id"`
	Raw                 string `json:"raw"`
	CanonicalRef        string `json:"canonical_ref"`
	ChainFamily         string `json:"chain_family"`
	Chain               string `json:"chain"`
	Network             string `json:"network"`
	Kind                string `json:"kind"`
	ClassificationBasis string `json:"classification_basis"`
}

type IntelligenceEntity struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	Label        string   `json:"label,omitempty"`
	Attribution  string   `json:"attribution,omitempty"`
	Confidence   float64  `json:"confidence"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
}

type IntelligenceEvidence struct {
	ID              string         `json:"id"`
	SubjectID       string         `json:"subject_id"`
	ChainFamily     string         `json:"chain_family"`
	Chain           string         `json:"chain"`
	Network         string         `json:"network"`
	Source          string         `json:"source"`
	Status          string         `json:"status"`
	TransactionHash string         `json:"transaction_hash,omitempty"`
	BlockOrSlot     int64          `json:"block_or_slot,omitempty"`
	ObservedAt      time.Time      `json:"observed_at,omitempty"`
	Address         string         `json:"address,omitempty"`
	Contract        string         `json:"contract,omitempty"`
	Method          string         `json:"method,omitempty"`
	StateChange     string         `json:"state_change,omitempty"`
	Provenance      string         `json:"provenance,omitempty"`
	Confidence      float64        `json:"confidence"`
	Attributes      map[string]any `json:"attributes,omitempty"`
}

type IntelligenceRelationship struct {
	SourceSubjectID string   `json:"source_subject_id"`
	TargetSubjectID string   `json:"target_subject_id"`
	Relation        string   `json:"relation"`
	Status          string   `json:"status"`
	Confidence      float64  `json:"confidence"`
	EvidenceRefs    []string `json:"evidence_refs,omitempty"`
}

type IntelligenceBehaviorFinding struct {
	Kind         string   `json:"kind"`
	Summary      string   `json:"summary"`
	Status       string   `json:"status"`
	Confidence   float64  `json:"confidence"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
}

type IntelligenceAttackPathStep struct {
	Order        int      `json:"order"`
	Action       string   `json:"action"`
	Effect       string   `json:"effect"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
}

type IntelligenceAttackPath struct {
	ID            string                       `json:"id"`
	Title         string                       `json:"title"`
	Status        string                       `json:"status"`
	Preconditions []string                     `json:"preconditions,omitempty"`
	Steps         []IntelligenceAttackPathStep `json:"steps,omitempty"`
	Impact        string                       `json:"impact,omitempty"`
	Confidence    float64                      `json:"confidence"`
	EvidenceRefs  []string                     `json:"evidence_refs,omitempty"`
}

type IntelligenceDecision struct {
	Status       string   `json:"status"`
	Action       string   `json:"action"`
	Summary      string   `json:"summary"`
	Reasons      []string `json:"reasons,omitempty"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
	Confidence   float64  `json:"confidence"`
}

type IntelligenceInvestigation struct {
	ContractVersion string                        `json:"contract_version"`
	Subjects        []IntelligenceSubject         `json:"subjects"`
	Entities        []IntelligenceEntity          `json:"entities,omitempty"`
	Evidence        []IntelligenceEvidence        `json:"evidence,omitempty"`
	Relationships   []IntelligenceRelationship    `json:"relationships,omitempty"`
	Behaviors       []IntelligenceBehaviorFinding `json:"behaviors,omitempty"`
	AttackPaths     []IntelligenceAttackPath       `json:"attack_paths,omitempty"`
	Decision        IntelligenceDecision           `json:"decision"`
	GeneratedAt     time.Time                      `json:"generated_at"`
}

func ClassifyIntelligenceSubject(target, network string) IntelligenceSubject {
	target = strings.TrimSpace(target)
	network = strings.ToLower(strings.TrimSpace(network))
	family, chain, basis := classifyIntelligenceTarget(target, network)
	kind := IntelligenceSubjectUnknown
	if family != IntelligenceChainFamilyUnknown {
		kind = IntelligenceSubjectAddress
	}
	canonical := intelligenceCanonicalRef(family, chain, network, target)
	return IntelligenceSubject{
		ID:                  intelligenceStableID(canonical),
		Raw:                 target,
		CanonicalRef:        canonical,
		ChainFamily:         family,
		Chain:               chain,
		Network:             network,
		Kind:                kind,
		ClassificationBasis: basis,
	}
}

func BuildIntelligenceInvestigation(subjects []IntelligenceSubject, now time.Time) IntelligenceInvestigation {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return IntelligenceInvestigation{
		ContractVersion: IntelligenceContractVersion,
		Subjects:        append([]IntelligenceSubject(nil), subjects...),
		Decision: IntelligenceDecision{
			Status:     IntelligenceEvidenceUnverified,
			Action:     "investigate",
			Summary:    "No evidence-backed customer decision has been produced yet.",
			Confidence: 0,
		},
		GeneratedAt: now.UTC(),
	}
}

func VerifiedIntelligenceRelationship(sourceID, targetID, relation string, evidenceRefs []string, confidence float64) IntelligenceRelationship {
	status := IntelligenceEvidenceUnverified
	if strings.TrimSpace(sourceID) != "" && strings.TrimSpace(targetID) != "" && strings.TrimSpace(relation) != "" && len(nonEmptyIntelligenceRefs(evidenceRefs)) > 0 {
		status = IntelligenceEvidenceVerified
	}
	return IntelligenceRelationship{
		SourceSubjectID: strings.TrimSpace(sourceID),
		TargetSubjectID: strings.TrimSpace(targetID),
		Relation:        strings.TrimSpace(relation),
		Status:          status,
		Confidence:      clampIntelligenceConfidence(confidence),
		EvidenceRefs:    nonEmptyIntelligenceRefs(evidenceRefs),
	}
}

func classifyIntelligenceTarget(target, network string) (family, chain, basis string) {
	if evmAddressPattern.MatchString(target) {
		return IntelligenceChainFamilyEVM, evmChainFromNetwork(network), "evm_address_syntax"
	}
	if isSyntacticSolanaAddress(target) {
		return IntelligenceChainFamilySolana, "solana", "solana_base58_address_syntax"
	}
	return IntelligenceChainFamilyUnknown, "unknown", "unclassified"
}

func evmChainFromNetwork(network string) string {
	switch {
	case strings.Contains(network, "ethereum"):
		return "ethereum"
	case strings.Contains(network, "base"):
		return "base"
	case strings.Contains(network, "arbitrum"):
		return "arbitrum"
	case strings.Contains(network, "optimism"):
		return "optimism"
	case strings.Contains(network, "polygon"):
		return "polygon"
	case strings.Contains(network, "bnb"), strings.Contains(network, "bsc"):
		return "bnb-chain"
	case strings.Contains(network, "avalanche"):
		return "avalanche"
	default:
		return "evm"
	}
}

func isSyntacticSolanaAddress(value string) bool {
	if len(value) < 32 || len(value) > 44 {
		return false
	}
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	for _, r := range value {
		if !strings.ContainsRune(alphabet, r) {
			return false
		}
	}
	return true
}

func intelligenceCanonicalRef(family, chain, network, target string) string {
	return strings.Join([]string{
		strings.ToLower(strings.TrimSpace(family)),
		strings.ToLower(strings.TrimSpace(chain)),
		strings.ToLower(strings.TrimSpace(network)),
		strings.TrimSpace(target),
	}, ":")
}

func intelligenceStableID(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "kis_" + hex.EncodeToString(sum[:12])
}

func nonEmptyIntelligenceRefs(refs []string) []string {
	out := make([]string, 0, len(refs))
	seen := map[string]bool{}
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" || seen[ref] {
			continue
		}
		seen[ref] = true
		out = append(out, ref)
	}
	return out
}

func clampIntelligenceConfidence(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}
