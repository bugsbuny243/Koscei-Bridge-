package services

const InvestigationOutputPolicyVersion = "koschei-evidence-parity-v1"

type InvestigationOutputPolicy struct {
	Version                 string   `json:"version"`
	SameEvidenceEngine      bool     `json:"same_evidence_engine"`
	SameTechnicalResult     bool     `json:"same_technical_result"`
	CallerTypeAffects       []string `json:"caller_type_affects"`
	CallerTypeDoesNotAffect []string `json:"caller_type_does_not_affect"`
	Statement               string   `json:"statement"`
}

// SharedInvestigationOutputPolicy is a product and API contract: caller type,
// commercial tier or interface may change operational capacity but never the
// evidence interpretation for the same target, evidence window and ruleset.
func SharedInvestigationOutputPolicy() InvestigationOutputPolicy {
	return InvestigationOutputPolicy{
		Version:             InvestigationOutputPolicyVersion,
		SameEvidenceEngine:  true,
		SameTechnicalResult: true,
		CallerTypeAffects: []string{
			"rate_limits", "retention", "saved_history", "watchlists", "batch_operations",
			"team_access", "api_access", "webhooks", "exports", "audit_controls",
		},
		CallerTypeDoesNotAffect: []string{
			"collector_execution", "evidence_status", "evidence_lines", "holder_resolution",
			"liquidity_findings", "actor_relations", "threat_pathways", "deterministic_verdict",
			"ruleset", "signature", "limitations",
		},
		Statement: "The same target, evidence window and ruleset produce the same technical investigation result for individual, institutional and API users.",
	}
}
