package handlers

import (
	"fmt"
	"strings"
)

const transactionGuardAttackPathVersion = "koschei-preflight-attack-path-v1"

type transactionGuardAttackPathStep struct {
	Sequence     int    `json:"sequence"`
	Layer        string `json:"layer"`
	Kind         string `json:"kind"`
	Subject      string `json:"subject,omitempty"`
	Counterparty string `json:"counterparty,omitempty"`
	ProgramID    string `json:"program_id,omitempty"`
	Severity     string `json:"severity"`
	Evidence     string `json:"evidence"`
}

type transactionGuardAttackPath struct {
	ID         string                           `json:"id"`
	Title      string                           `json:"title"`
	Confidence string                           `json:"confidence"`
	Impact     string                           `json:"impact"`
	Steps      []transactionGuardAttackPathStep `json:"steps"`
}

type transactionGuardAttackPathAnalysis struct {
	Version     string                       `json:"version"`
	Available   bool                         `json:"available"`
	Complete    bool                         `json:"complete"`
	Status      string                       `json:"status"`
	PathCount   int                          `json:"path_count"`
	Paths       []transactionGuardAttackPath `json:"paths"`
	Limitations []string                     `json:"limitations"`
}

func buildTransactionGuardAttackPaths(
	wallet string,
	assessment transactionFirewallAssessment,
	decoded transactionGuardDecodedTransaction,
	cpi transactionGuardCPIFlowAnalysis,
	authority transactionGuardAuthoritySurfaceAnalysis,
) transactionGuardAttackPathAnalysis {
	analysis := transactionGuardAttackPathAnalysis{
		Version:     transactionGuardAttackPathVersion,
		Available:   decoded.Available || cpi.Available || authority.Available,
		Complete:    decoded.Complete && (!cpi.Required || cpi.Complete) && (!authority.Required || authority.Complete) && (!decoded.AutomaticBalance.Requested || decoded.AutomaticBalance.Complete),
		Status:      "no_attack_path_observed",
		Paths:       []transactionGuardAttackPath{},
		Limitations: []string{},
	}

	steps := make([]transactionGuardAttackPathStep, 0, 16)
	impact := make([]string, 0, 4)
	wallet = strings.TrimSpace(wallet)

	for _, op := range decoded.TokenOperations {
		severity, impactText, ok := transactionGuardAttackPathTokenOperation(op)
		if !ok {
			continue
		}
		subject := firstNonEmptyAttackPathValue(op.Account, op.Source, op.Mint)
		counterparty := firstNonEmptyAttackPathValue(op.Delegate, op.NewAuthority, op.Destination)
		steps = append(steps, transactionGuardAttackPathStep{
			Layer:        "decoded_instruction",
			Kind:         op.Kind,
			Subject:      subject,
			Counterparty: counterparty,
			ProgramID:    op.ProgramID,
			Severity:     severity,
			Evidence:     compactGuardV3Evidence(fmt.Sprintf("decoded token operation kind=%s subject=%s counterparty=%s amount_raw=%s", op.Kind, subject, counterparty, op.AmountRaw)),
		})
		impact = appendUniqueAttackPathValue(impact, impactText)
	}

	for _, event := range authority.Events {
		if !event.Persistent && !event.MintWide && !event.EffectivelyUnlimited {
			continue
		}
		severity := "high"
		if event.MintWide || event.EffectivelyUnlimited {
			severity = "critical"
		}
		counterparty := firstNonEmptyAttackPathValue(event.NewAuthority, event.Delegate, event.TransferHookProgramID)
		steps = append(steps, transactionGuardAttackPathStep{
			Layer:        "authority_surface",
			Kind:         event.Kind,
			Subject:      firstNonEmptyAttackPathValue(event.Account, event.Mint, event.Source),
			Counterparty: counterparty,
			ProgramID:    event.ProgramID,
			Severity:     severity,
			Evidence:     compactGuardV3Evidence(event.Explanation),
		})
		impact = appendUniqueAttackPathValue(impact, "persistent or broad authority may survive the transaction")
	}

	for _, movement := range cpi.AssetMovements {
		if !movement.WalletOrigin && !movement.UndeclaredByAccountPolicy {
			continue
		}
		severity := "high"
		if movement.WalletOrigin && movement.UndeclaredByAccountPolicy {
			severity = "critical"
		}
		steps = append(steps, transactionGuardAttackPathStep{
			Layer:        "cpi_asset_flow",
			Kind:         movement.Kind,
			Subject:      movement.Source,
			Counterparty: movement.Destination,
			ProgramID:    movement.ProgramID,
			Severity:     severity,
			Evidence: compactGuardV3Evidence(fmt.Sprintf(
				"asset=%s mint=%s amount_raw=%s wallet_origin=%t inner_only=%t undeclared=%t parent_program=%s",
				movement.AssetType, movement.Mint, movement.AmountRaw, movement.WalletOrigin, movement.InnerOnly, movement.UndeclaredByAccountPolicy, movement.ParentProgramID,
			)),
		})
		impact = appendUniqueAttackPathValue(impact, "asset movement can leave the wallet or declared policy boundary")
	}

	for _, delta := range decoded.AutomaticBalance.Accounts {
		if !delta.Changed {
			continue
		}
		if wallet != "" && delta.Address != wallet && delta.PreTokenOwner != wallet && delta.PostTokenOwner != wallet {
			continue
		}
		if !strings.HasPrefix(delta.LamportDelta, "-") && !strings.HasPrefix(delta.TokenDeltaRaw, "-") && !delta.AccountClosed {
			continue
		}
		steps = append(steps, transactionGuardAttackPathStep{
			Layer:    "state_diff",
			Kind:     "wallet_value_decrease",
			Subject:  delta.Address,
			Severity: "high",
			Evidence: compactGuardV3Evidence(fmt.Sprintf("lamport_delta=%s token_delta_raw=%s account_closed=%t evidence_status=%s", delta.LamportDelta, delta.TokenDeltaRaw, delta.AccountClosed, delta.EvidenceStatus)),
		})
		impact = appendUniqueAttackPathValue(impact, "simulated wallet value decreases")
	}

	for _, finding := range assessment.Findings {
		if finding.Severity != "critical" && finding.Severity != "high" {
			continue
		}
		if attackPathFindingAlreadyRepresented(steps, finding.Code) {
			continue
		}
		layer := "guard_finding"
		if strings.HasPrefix(finding.Code, "signed_ui_intent_") {
			layer = "signed_intent_boundary"
			impact = appendUniqueAttackPathValue(impact, "signed UI intent does not match the transaction or request boundary")
		}
		steps = append(steps, transactionGuardAttackPathStep{
			Layer:    layer,
			Kind:     finding.Code,
			Severity: finding.Severity,
			Evidence: compactGuardV3Evidence(finding.Evidence),
		})
	}

	if len(steps) > 0 {
		for i := range steps {
			steps[i].Sequence = i + 1
		}
		confidence := "medium"
		if analysis.Complete {
			confidence = "high"
		}
		analysis.Paths = append(analysis.Paths, transactionGuardAttackPath{
			ID:         "preflight-path-1",
			Title:      "Evidence-linked pre-signing risk path",
			Confidence: confidence,
			Impact:     strings.Join(impact, "; "),
			Steps:      steps,
		})
		analysis.PathCount = 1
		analysis.Status = "attack_path_observed"
	}

	if !analysis.Complete {
		analysis.Limitations = append(analysis.Limitations, "Attack-path ordering is evidence-linked but must not be interpreted as proven malicious intent or post-signing causation when required decode, simulation, CPI, authority, or balance evidence is incomplete.")
		if analysis.Status == "no_attack_path_observed" {
			analysis.Status = "incomplete_evidence"
		}
	}
	return analysis
}

func transactionGuardAttackPathTokenOperation(op transactionGuardDecodedTokenOperation) (string, string, bool) {
	switch op.Kind {
	case "approve", "approve_checked":
		return "high", "delegate authority can move tokens after approval", true
	case "set_authority", "initialize_permanent_delegate", "initialize_transfer_hook", "update_transfer_hook":
		return "critical", "authority or execution control changes", true
	case "close_account", "freeze_account", "burn", "burn_checked":
		return "high", "token account availability or value can be reduced", true
	default:
		return "", "", false
	}
}

func firstNonEmptyAttackPathValue(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func appendUniqueAttackPathValue(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func attackPathFindingAlreadyRepresented(steps []transactionGuardAttackPathStep, code string) bool {
	aliases := map[string][]string{
		"delegate_approval":         {"approve", "approve_checked"},
		"decoded_delegate_approval": {"approve", "approve_checked"},
		"authority_change":          {"set_authority"},
		"decoded_authority_change":  {"set_authority"},
		"decoded_close_account":     {"close_account"},
		"decoded_freeze_account":    {"freeze_account"},
		"decoded_token_burn":        {"burn", "burn_checked"},
		"permanent_delegate":        {"initialize_permanent_delegate"},
		"transfer_hook":             {"initialize_transfer_hook", "update_transfer_hook"},
	}
	for _, step := range steps {
		if step.Kind == code {
			return true
		}
		for _, alias := range aliases[code] {
			if step.Kind == alias {
				return true
			}
		}
	}
	return false
}
