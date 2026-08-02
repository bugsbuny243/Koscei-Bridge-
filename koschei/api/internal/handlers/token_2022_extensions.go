package handlers

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type tokenExtensionAssessment struct {
	Name        string         `json:"name"`
	Severity    string         `json:"severity"`
	RiskPenalty int            `json:"risk_penalty"`
	Summary     string         `json:"summary"`
	Details     map[string]any `json:"details,omitempty"`
}

func parseToken2022Extensions(info map[string]any) []tokenExtensionAssessment {
	raw, ok := info["extensions"]
	if !ok {
		return []tokenExtensionAssessment{}
	}
	items, ok := raw.([]any)
	if !ok {
		return []tokenExtensionAssessment{}
	}
	out := make([]tokenExtensionAssessment, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name := firstMapStringValue(object, "extension", "extensionType", "type")
		if name == "" {
			continue
		}
		details := map[string]any{}
		if state, ok := object["state"].(map[string]any); ok {
			details = state
		} else {
			for key, value := range object {
				if key == "extension" || key == "extensionType" || key == "type" {
					continue
				}
				details[key] = value
			}
		}
		out = append(out, assessToken2022Extension(name, details))
	}
	return out
}

func assessToken2022Extension(name string, details map[string]any) tokenExtensionAssessment {
	normalized := normalizeExtensionName(name)
	assessment := tokenExtensionAssessment{Name: canonicalExtensionName(name), Severity: "info", RiskPenalty: 0, Summary: "Token-2022 extension is active.", Details: details}
	switch normalized {
	case "permanentdelegate":
		assessment.Severity, assessment.RiskPenalty, assessment.Summary = "critical", 50, "A permanent delegate may transfer or burn tokens from holder accounts."
	case "transferhook":
		assessment.Severity, assessment.RiskPenalty, assessment.Summary = "high", 30, "A custom program can run on every token transfer."
	case "transferfeeconfig":
		bps := token2022NestedNumber(details, "transferFeeBasisPoints")
		assessment.Severity, assessment.RiskPenalty = "medium", 18
		assessment.Summary = "Protocol-level transfer fees are enabled."
		if bps >= 1000 {
			assessment.Severity, assessment.RiskPenalty = "high", 30
			assessment.Summary = "High protocol-level transfer fees are configured."
		}
		if bps >= 5000 {
			assessment.Severity, assessment.RiskPenalty = "critical", 45
			assessment.Summary = "Extremely high protocol-level transfer fees are configured."
		}
	case "mintcloseauthority":
		assessment.Severity, assessment.RiskPenalty, assessment.Summary = "high", 30, "The mint account can be closed by an authority."
	case "defaultaccountstate":
		state := strings.ToLower(token2022NestedString(details, "state"))
		assessment.Severity, assessment.RiskPenalty, assessment.Summary = "medium", 15, "New token accounts use a configured default state."
		if strings.Contains(state, "frozen") {
			assessment.Severity, assessment.RiskPenalty, assessment.Summary = "high", 30, "New token accounts start frozen and require authority intervention."
		}
	case "nontransferable":
		assessment.Severity, assessment.RiskPenalty, assessment.Summary = "medium", 20, "The token is non-transferable (soulbound behavior)."
	case "confidentialtransfermint":
		assessment.Severity, assessment.RiskPenalty, assessment.Summary = "medium", 18, "Confidential balances or transfer amounts may limit public visibility."
	case "confidentialtransferfeeconfig":
		assessment.Severity, assessment.RiskPenalty, assessment.Summary = "high", 25, "Confidential transfer-fee behavior limits complete public inspection."
	case "confidentialmintburn":
		assessment.Severity, assessment.RiskPenalty, assessment.Summary = "high", 30, "Confidential mint or burn activity may not be fully observable from public amounts."
	case "pausableconfig":
		assessment.Severity, assessment.RiskPenalty, assessment.Summary = "high", 35, "An authority can pause token transfers globally."
	case "scaleduiamountconfig":
		assessment.Severity, assessment.RiskPenalty, assessment.Summary = "medium", 15, "Displayed token amounts can be scaled independently from raw balances."
	case "interestbearingconfig":
		assessment.Severity, assessment.RiskPenalty, assessment.Summary = "low", 5, "UI balances may include an interest-bearing display calculation."
	case "metadatapointer":
		assessment.Severity, assessment.RiskPenalty, assessment.Summary = "low", 2, "Metadata is resolved through a configured pointer."
	case "tokenmetadata":
		assessment.Severity, assessment.RiskPenalty, assessment.Summary = "info", 0, "Token metadata is stored through the Token-2022 metadata extension."
	case "grouppointer", "tokengroup", "groupmemberpointer", "tokengroupmember":
		assessment.Severity, assessment.RiskPenalty, assessment.Summary = "info", 0, "Token grouping metadata is enabled."
	default:
		assessment.Summary = "An extension not yet assigned a Koschei risk rule is active and should be reviewed for compatibility."
	}
	return assessment
}

func summarizeToken2022Extensions(extensions []tokenExtensionAssessment) (int, map[string]any, []string, []string) {
	penalty := 0
	behavior := map[string]any{
		"standard_transfer":  true,
		"transfer_fee":       false,
		"transfer_hook":      false,
		"non_transferable":   false,
		"pausable":           false,
		"permanent_delegate": false,
	}
	visibility := []string{}
	compatibility := []string{}
	seenVisibility := map[string]struct{}{}
	seenCompatibility := map[string]struct{}{}
	for _, extension := range extensions {
		penalty += extension.RiskPenalty
		normalized := normalizeExtensionName(extension.Name)
		switch normalized {
		case "transferfeeconfig":
			behavior["transfer_fee"] = true
			behavior["standard_transfer"] = false
			if value := token2022NestedNumber(extension.Details, "transferFeeBasisPoints"); value > 0 {
				behavior["transfer_fee_basis_points"] = value
			}
			if value := token2022NestedAny(extension.Details, "maximumFee"); value != nil {
				behavior["maximum_fee"] = value
			}
			appendUnique(&compatibility, seenCompatibility, "Integrations must account for protocol-level transfer fees.")
		case "transferhook":
			behavior["transfer_hook"] = true
			behavior["standard_transfer"] = false
			if value := token2022NestedString(extension.Details, "programId"); value != "" {
				behavior["transfer_hook_program"] = value
			}
			appendUnique(&compatibility, seenCompatibility, "Every transfer may invoke a custom program and require additional accounts.")
		case "nontransferable":
			behavior["non_transferable"] = true
			behavior["standard_transfer"] = false
			appendUnique(&compatibility, seenCompatibility, "The token cannot be transferred through normal wallet or DEX flows.")
		case "pausableconfig":
			behavior["pausable"] = true
			behavior["standard_transfer"] = false
			appendUnique(&compatibility, seenCompatibility, "Token transfers may be paused globally by an authority.")
		case "permanentdelegate":
			behavior["permanent_delegate"] = true
			if value := token2022NestedString(extension.Details, "delegate"); value != "" {
				behavior["permanent_delegate_address"] = value
			}
			appendUnique(&compatibility, seenCompatibility, "A permanent delegate may transfer or burn holder balances.")
		case "confidentialtransfermint", "confidentialtransferfeeconfig", "confidentialmintburn":
			appendUnique(&visibility, seenVisibility, "Confidential Token-2022 features may hide balances, transfer amounts, fees, minting, or burning from ordinary public inspection.")
		case "scaleduiamountconfig":
			appendUnique(&compatibility, seenCompatibility, "Displayed balances may differ from raw token amounts because of UI scaling.")
		case "defaultaccountstate":
			appendUnique(&compatibility, seenCompatibility, "New token accounts may require thawing before they can receive or transfer tokens.")
		default:
			if extension.Summary == "An extension not yet assigned a Koschei risk rule is active and should be reviewed for compatibility." {
				appendUnique(&compatibility, seenCompatibility, "Unknown or newly introduced Token-2022 extension: "+extension.Name)
			}
		}
	}
	if penalty > 75 {
		penalty = 75
	}
	return penalty, behavior, visibility, compatibility
}

func token2022Findings(extensions []tokenExtensionAssessment) []string {
	out := make([]string, 0, len(extensions)+1)
	if len(extensions) > 0 {
		out = append(out, fmt.Sprintf("Token-2022 mint exposes %d parsed extension(s).", len(extensions)))
	}
	for _, extension := range extensions {
		out = append(out, extension.Name+": "+extension.Summary)
	}
	return out
}

func token2022ExtensionResolution(isToken2022 bool, accountSpace int, extensions []tokenExtensionAssessment) (string, bool) {
	if !isToken2022 {
		return "not_applicable", true
	}
	if len(extensions) > 0 {
		return "resolved", true
	}
	// A classic mint is 82 bytes. Extra Token-2022 account space with no parsed
	// extension list means the parser did not expose the active TLV state.
	if accountSpace > 82 {
		return "token_2022_extensions_unresolved", false
	}
	return "resolved_empty", true
}

func token2022FinalPolicy(score int, extensions []tokenExtensionAssessment, visibility []string, evidenceComplete bool) string {
	if !evidenceComplete {
		return "withhold"
	}
	return tokenFinalPolicy(score, extensions, visibility)
}

func tokenFinalPolicy(score int, extensions []tokenExtensionAssessment, visibility []string) string {
	for _, extension := range extensions {
		if extension.Severity == "critical" {
			return "block"
		}
	}
	if len(visibility) > 0 {
		return "warn"
	}
	for _, extension := range extensions {
		if extension.Severity == "high" || extension.Severity == "medium" {
			return "warn"
		}
	}
	if score < 40 {
		return "block"
	}
	if score < 70 {
		return "warn"
	}
	return "allow"
}

func tokenRiskLevel(score int) string {
	if score < 40 {
		return "high"
	}
	if score < 70 {
		return "medium"
	}
	return "low"
}

func firstMapStringValue(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func token2022NestedAny(value any, key string) any {
	target := normalizeExtensionName(key)
	switch current := value.(type) {
	case map[string]any:
		for candidate, child := range current {
			if normalizeExtensionName(candidate) == target {
				return child
			}
		}
		for _, child := range current {
			if found := token2022NestedAny(child, key); found != nil {
				return found
			}
		}
	case []any:
		for _, child := range current {
			if found := token2022NestedAny(child, key); found != nil {
				return found
			}
		}
	}
	return nil
}

func token2022NestedString(value any, key string) string {
	found := token2022NestedAny(value, key)
	switch typed := found.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return ""
	}
}

func token2022NestedNumber(value any, key string) float64 {
	found := token2022NestedAny(value, key)
	switch typed := found.(type) {
	case float64:
		return typed
	case json.Number:
		number, _ := typed.Float64()
		return number
	case string:
		number, _ := strconv.ParseFloat(typed, 64)
		return number
	default:
		return 0
	}
}

func appendUnique(target *[]string, seen map[string]struct{}, value string) {
	if _, exists := seen[value]; exists {
		return
	}
	seen[value] = struct{}{}
	*target = append(*target, value)
}

func canonicalExtensionName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "UnknownExtension"
	}
	return value
}

func normalizeExtensionName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') {
			builder.WriteRune(character)
		}
	}
	return builder.String()
}
