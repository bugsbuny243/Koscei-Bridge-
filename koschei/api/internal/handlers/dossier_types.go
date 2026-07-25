package handlers

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"time"
)

const (
	dossierVersion       = "koschei-dossier-v1"
	dossierMapperVersion = "koschei-verdict-card-v4+market-v1+evidence-refs-v1"
	dossierVerifierRepo  = "https://github.com/bugsbuny243/Koschei-Web3-Hub"
)

var (
	errDossierSourceIncomplete  = errors.New("dossier_source_incomplete")
	errDossierReferenceMissing  = errors.New("populated_signal_missing_refs")
	errDossierSourceHash        = errors.New("dossier_source_hash_mismatch")
	errDossierAcceptanceMissing = errors.New("actor_acceptance_missing")
)

var dossierLimitations = []string{
	"Capability-not-intent: this export describes observed technical capability and behavior; it does not infer intent.",
	"Identity boundary: onchain_wallet_only. No person, organization or real-world identity attribution is made or implied.",
	"Evidence-window boundary: every observation is bounded by produced_at, source timestamps, slots and stored collection limits in this bundle.",
	"This is a technical evidence export, not an investment recommendation.",
}

type DossierRefs struct {
	Wallets      []string `json:"wallets"`
	Accounts     []string `json:"accounts"`
	Signatures   []string `json:"signatures"`
	Slots        []int64  `json:"slots"`
	EvidenceKeys []string `json:"evidence_keys"`
}

type DossierSignalRow struct {
	ID               string      `json:"id"`
	Label            string      `json:"label"`
	State            string      `json:"state"`
	AcceptanceStatus string      `json:"acceptance_status,omitempty"`
	Value            any         `json:"value,omitempty"`
	Refs             DossierRefs `json:"refs"`
	Limitations      []string    `json:"limitations"`
}

type dossierBody struct {
	DossierVersion        string         `json:"dossier_version"`
	CaseRef               string         `json:"case_ref"`
	ProducedAt            time.Time      `json:"produced_at"`
	SourceSnapshotHash    string         `json:"source_snapshot_hash"`
	Target                any            `json:"target,omitempty"`
	Token                 any            `json:"token,omitempty"`
	Verdict               any            `json:"verdict"`
	VerdictCard           any            `json:"verdict_card"`
	ThreatAnticipation    any            `json:"threat_anticipation,omitempty"`
	EvidenceArms          any            `json:"evidence_arms,omitempty"`
	TransactionEvidence  any            `json:"transaction_evidence,omitempty"`
	EvidenceReferences   any            `json:"evidence_references,omitempty"`
	ActorDossier          any            `json:"actor_dossier,omitempty"`
	ActorAcceptance       any            `json:"actor_acceptance,omitempty"`
	CreatedTokenHistory   any            `json:"created_token_history,omitempty"`
	FundingOrigin         any            `json:"funding_origin,omitempty"`
	CrossTokenConnections any            `json:"cross_token_connections,omitempty"`
	EvidenceLog           any            `json:"evidence_log,omitempty"`
	SectionLimitations    any            `json:"section_limitations,omitempty"`
	HolderContext         any            `json:"holder_concentration_context,omitempty"`
	TechnicalReport       map[string]any `json:"technical_report"`
	Verification          any            `json:"verification"`
	Limitations           []string       `json:"limitations"`
}

type dossierBundle struct {
	dossierBody
	BundleHash string `json:"bundle_hash"`
}

type dossierSnapshot struct {
	ID               string
	Mint             string
	Network          string
	VerdictID        string
	VerdictSignature string
	RulesetVersion   string
	ProducedAt       time.Time
	SourceHash       string
	Report           map[string]any
}

func dossierCaseRef(targetID, signature string) string {
	sum := sha256.Sum256([]byte(trimDossier(targetID) + "\n" + trimDossier(signature)))
	return "KD1-" + lowerDossier(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:20]))
}

func dossierSHA256(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
