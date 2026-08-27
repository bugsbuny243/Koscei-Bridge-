package handlers

import "strings"

const transactionDefenseValidationVersion = "koschei-transaction-defense-validation-v1"

type transactionDefenseValidationReference struct {
	Programs     []string `json:"programs,omitempty"`
	Accounts     []string `json:"accounts,omitempty"`
	EvidenceKeys []string `json:"evidence_keys,omitempty"`
}

type transactionDefenseValidationCheck struct {
	ID               string                                `json:"id"`
	Category         string                                `json:"category"`
	Status           string                                `json:"status"`
	Summary          string                                `json:"summary"`
	References       transactionDefenseValidationReference `json:"references"`
	RequiredEvidence []string                              `json:"required_evidence,omitempty"`
}

type transactionDefenseValidationReport struct {
	Version        string                              `json:"version"`
	Status         string                              `json:"status"`
	Decision       string                              `json:"decision"`
	Checks         []transactionDefenseValidationCheck `json:"checks"`
	EvidencePolicy map[string]bool                     `json:"evidence_policy"`
}

func buildTransactionDefenseValidation(assessment transactionFirewallAssessment, programs transactionGuardProgramPolicy, intent transactionGuardIntentPolicy) transactionDefenseValidationReport {
	checks := []transactionDefenseValidationCheck{
		buildSimulationValidationCheck(assessment),
		buildProgramValidationCheck(assessment, programs),
		buildIntentValidationCheck(intent),
		buildSemanticValidationCheck(assessment),
	}
	status := "pass"
	decision := "pass"
	for _, check := range checks {
		switch check.Status {
		case "fail":
			status = "fail"
			decision = "block"
		case "insufficient_evidence":
			if status != "fail" {
				status = "insufficient_evidence"
				decision = "withhold"
			}
		}
	}
	return transactionDefenseValidationReport{
		Version:  transactionDefenseValidationVersion,
		Status:   status,
		Decision: decision,
		Checks:   checks,
		EvidencePolicy: map[string]bool{
			"no_evidence_no_pass":                 true,
			"numeric_score_authoritative":         false,
			"legacy_firewall_score_authoritative": false,
			"intent_is_not_inferred":              true,
			"simulation_is_not_execution":         true,
		},
	}
}

func buildSimulationValidationCheck(assessment transactionFirewallAssessment) transactionDefenseValidationCheck {
	check := transactionDefenseValidationCheck{
		ID:       "simulation_execution",
		Category: "simulation",
		Status:   "pass",
		Summary:  "RPC simulation completed without an execution error.",
		References: transactionDefenseValidationReference{
			Programs: append([]string{}, assessment.ProgramIDs...),
		},
	}
	if hasFirewallFindingCode(assessment.Findings, "simulation_failed") {
		check.Status = "fail"
		check.Summary = "RPC simulation returned an execution failure."
		check.References.EvidenceKeys = []string{"simulation:execution_failed"}
		return check
	}
	if !assessment.SimulationOK {
		check.Status = "insufficient_evidence"
		check.Summary = "A trustworthy simulation result was not available."
		check.RequiredEvidence = []string{"successful RPC simulation with execution result"}
		return check
	}
	check.References.EvidenceKeys = []string{"simulation:execution_success"}
	return check
}

func buildProgramValidationCheck(assessment transactionFirewallAssessment, policy transactionGuardProgramPolicy) transactionDefenseValidationCheck {
	check := transactionDefenseValidationCheck{
		ID:       "program_route_policy",
		Category: "route",
		Status:   "pass",
		Summary:  "Invoked programs satisfy the configured route policy.",
		References: transactionDefenseValidationReference{
			Programs: append([]string{}, policy.Invoked...),
		},
	}
	if len(policy.BlockedInvoked)+len(policy.Unexpected)+len(policy.MissingRequired) > 0 {
		check.Status = "fail"
		check.Summary = "The simulated program route violates the configured program policy."
		check.References.Programs = uniqueStringsSorted(append(append(append([]string{}, policy.BlockedInvoked...), policy.Unexpected...), policy.MissingRequired...))
		check.References.EvidenceKeys = []string{"program_policy:violation"}
		return check
	}
	if !assessment.SimulationOK || !policy.Complete {
		check.Status = "insufficient_evidence"
		check.Summary = "The program route could not be completely validated."
		check.RequiredEvidence = []string{"complete invoked-program set", "configured expected/required/blocked program policy"}
		return check
	}
	check.References.EvidenceKeys = []string{"program_policy:pass"}
	return check
}

func buildIntentValidationCheck(policy transactionGuardIntentPolicy) transactionDefenseValidationCheck {
	check := transactionDefenseValidationCheck{
		ID:       "state_delta_policy",
		Category: "state_delta",
		Status:   "pass",
		Summary:  "Guarded account state deltas satisfy the configured spend/receive policy.",
		References: transactionDefenseValidationReference{
			Accounts: []string{},
		},
	}
	if !policy.Requested {
		check.Status = "insufficient_evidence"
		check.Summary = "No guarded account state-delta policy was supplied."
		check.RequiredEvidence = []string{"guarded input/output/observe accounts", "maximum spend or minimum receive constraints where applicable"}
		return check
	}
	for _, account := range policy.Accounts {
		if strings.TrimSpace(account.Address) != "" {
			check.References.Accounts = append(check.References.Accounts, account.Address)
		}
		switch strings.ToLower(strings.TrimSpace(account.PolicyStatus)) {
		case "fail":
			check.Status = "fail"
		case "withhold", "unknown", "":
			if check.Status != "fail" {
				check.Status = "insufficient_evidence"
			}
		}
	}
	check.References.Accounts = uniqueStringsSorted(check.References.Accounts)
	switch check.Status {
	case "fail":
		check.Summary = "At least one guarded account delta violates the configured transaction intent policy."
		check.References.EvidenceKeys = []string{"state_delta_policy:violation"}
	case "insufficient_evidence":
		check.Summary = "At least one guarded account delta could not be verified."
		check.RequiredEvidence = []string{"verified pre-state and simulated post-state for every guarded account"}
	default:
		if !policy.Complete {
			check.Status = "insufficient_evidence"
			check.Summary = "Guarded account state-delta validation is incomplete."
			check.RequiredEvidence = []string{"complete guarded-account pre/post state"}
		} else {
			check.References.EvidenceKeys = []string{"state_delta_policy:pass"}
		}
	}
	return check
}

func buildSemanticValidationCheck(assessment transactionFirewallAssessment) transactionDefenseValidationCheck {
	semanticCodes := map[string]bool{
		"program_upgrade":      true,
		"permanent_delegate":   true,
		"authority_change":     true,
		"freeze_account":       true,
		"account_owner_change": true,
		"close_account":        true,
		"delegate_approval":    true,
		"transfer_hook":        true,
	}
	observed := []string{}
	for _, finding := range assessment.Findings {
		if semanticCodes[strings.TrimSpace(finding.Code)] {
			observed = append(observed, strings.TrimSpace(finding.Code))
		}
	}
	check := transactionDefenseValidationCheck{
		ID:       "decoded_semantic_effects",
		Category: "instruction_semantics",
		Status:   "pass",
		Summary:  "No unresolved security-sensitive semantic signal was observed in the legacy simulation evidence.",
		References: transactionDefenseValidationReference{
			Programs: append([]string{}, assessment.ProgramIDs...),
		},
	}
	if len(observed) > 0 {
		check.Status = "insufficient_evidence"
		check.Summary = "Security-sensitive execution signals were observed, but they are not yet verified by a decoded instruction/state-effect contract."
		check.References.EvidenceKeys = uniqueStringsSorted(observed)
		check.RequiredEvidence = []string{"decoded instruction semantics", "affected authority/account identifiers", "verified pre/post state effect"}
		return check
	}
	check.References.EvidenceKeys = []string{"semantic_effects:no_unresolved_signal"}
	return check
}

func hasFirewallFindingCode(findings []transactionFirewallFinding, code string) bool {
	for _, finding := range findings {
		if strings.EqualFold(strings.TrimSpace(finding.Code), strings.TrimSpace(code)) {
			return true
		}
	}
	return false
}
