package services

import "time"

// ProgramSecurityEvidence is a read-only control-plane observation. Open
// authority is a capability fact, not proof of malicious intent.
type ProgramSecurityEvidence struct {
	Available             bool       `json:"available"`
	Status                string     `json:"status"`
	Role                  string     `json:"role"`
	ProgramID             string     `json:"program_id"`
	LoaderID              string     `json:"loader_id,omitempty"`
	LoaderKind            string     `json:"loader_kind,omitempty"`
	ProgramDataAddress    string     `json:"programdata_address,omitempty"`
	AccountSlot           uint64     `json:"account_slot,omitempty"`
	DeploymentSlot        uint64     `json:"deployment_slot,omitempty"`
	UpgradeAuthority      string     `json:"upgrade_authority,omitempty"`
	UpgradeAuthorityOpen  bool       `json:"upgrade_authority_open"`
	Immutable             bool       `json:"immutable"`
	LastDeploymentAt      *time.Time `json:"last_deployment_or_upgrade_at,omitempty"`
	LastDeploymentAgeDays float64    `json:"last_deployment_or_upgrade_age_days,omitempty"`
	AgeAvailable          bool       `json:"age_available"`
	AgeSemantics          string     `json:"age_semantics"`
	EvidenceRefs          []string   `json:"evidence_refs"`
	Limitations           []string   `json:"limitations"`
}

// ProgramSecuritySurface is informational evidence only. It cannot issue a
// verdict by itself and never infers intent from an open upgrade authority.
type ProgramSecuritySurface struct {
	Available                 bool                      `json:"available"`
	Status                    string                    `json:"status"`
	Programs                  []ProgramSecurityEvidence `json:"programs"`
	AuthorityCoverageComplete bool                      `json:"authority_coverage_complete"`
	AgeCoverageComplete       bool                      `json:"age_coverage_complete"`
	ObservedAt                time.Time                 `json:"observed_at"`
	EvidencePolicy            string                    `json:"evidence_policy"`
	Limitations               []string                  `json:"limitations"`
}
