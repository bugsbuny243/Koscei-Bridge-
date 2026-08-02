package handlers

import (
	"fmt"
	"strconv"
	"strings"
)

func buildTransactionGuardV3ExplanationWithAuthority(
	wallet string,
	assessment transactionFirewallAssessment,
	decoded transactionGuardDecodedTransaction,
	threat transactionGuardThreatHistoryAnalysis,
	cpi transactionGuardCPIFlowAnalysis,
	authority transactionGuardAuthoritySurfaceAnalysis,
) transactionGuardPreSigningExplanation {
	out := buildTransactionGuardV3ExplanationWithCPI(wallet, assessment, decoded, threat, cpi)
	indexes := map[string]int{}
	for index, item := range out.Authorities {
		indexes[guardV3ExplanationAuthorityKey(item.Kind, item.Account, item.Delegate, item.NewAuthority)] = index
	}
	for _, event := range authority.Events {
		item := transactionGuardExplanationAuthority{
			Kind: event.Kind, Account: firstNonEmptyString(event.Account, event.Source, event.Mint),
			Authority: event.CurrentAuthority, Delegate: event.Delegate,
			NewAuthority: firstNonEmptyString(event.NewAuthority, event.TransferHookProgramID),
			AmountRaw:    event.AmountRaw, Persistent: event.Persistent,
			Explanation: guardV3AuthorityHumanExplanation(event),
		}
		key := guardV3ExplanationAuthorityKey(item.Kind, item.Account, item.Delegate, item.NewAuthority)
		if index, exists := indexes[key]; exists {
			out.Authorities[index] = item
		} else {
			indexes[key] = len(out.Authorities)
			out.Authorities = append(out.Authorities, item)
		}
		switch event.Kind {
		case "initialize_permanent_delegate":
			out.HiddenOrSensitiveActions = append(out.HiddenOrSensitiveActions,
				"A mint-wide permanent delegate can transfer or burn tokens from every token account for this mint.")
		case "initialize_transfer_hook", "update_transfer_hook":
			if event.TransferHookProgramID != "revoked" {
				out.HiddenOrSensitiveActions = append(out.HiddenOrSensitiveActions,
					"Future transfers may invoke transfer-hook program "+event.TransferHookProgramID+".")
			}
		case "initialize_transfer_fee_config", "set_transfer_fee":
			if event.TransferFeeBasisPoints != nil {
				out.HiddenOrSensitiveActions = append(out.HiddenOrSensitiveActions,
					fmt.Sprintf("Future transfers may be charged %d basis points, capped at %s raw units.", *event.TransferFeeBasisPoints, event.MaximumFeeRaw))
			}
		case "approve", "approve_checked":
			if event.ActiveAfterSimulation != nil && *event.ActiveAfterSimulation {
				out.HiddenOrSensitiveActions = append(out.HiddenOrSensitiveActions,
					"Delegate "+event.Delegate+" remains authorized for "+event.PostDelegatedAmountRaw+" raw token units after simulation.")
			}
		}
	}
	if authority.Required && !authority.Complete {
		out.EvidenceStatus = "partial"
		out.HiddenOrSensitiveActions = append(out.HiddenOrSensitiveActions,
			"Koschei could not complete the required final authority-state check and withheld a safe decision.")
	}
	out.HiddenOrSensitiveActions = uniqueExplanationStrings(out.HiddenOrSensitiveActions)
	out.Limitations = uniqueExplanationStrings(append(out.Limitations, authority.Limitations...))
	out.PlainLanguageSummary = guardV3ExplanationSummary(out)
	return out
}

func guardV3AuthorityHumanExplanation(event transactionGuardAuthorityEvent) string {
	parts := []string{event.Explanation}
	if event.Scope != "" && event.Scope != "not_applicable" {
		parts = append(parts, "Scope: "+strings.ReplaceAll(event.Scope, "_", " ")+".")
	}
	if event.Amount != "" && event.Amount != event.AmountRaw {
		parts = append(parts, "Amount: "+event.Amount+" tokens (raw "+event.AmountRaw+").")
	}
	if event.ActiveAfterSimulation != nil {
		if *event.ActiveAfterSimulation {
			parts = append(parts, "Final simulated state: active.")
		} else {
			parts = append(parts, "Final simulated state: not active.")
		}
	}
	if event.PostDelegatedAmountRaw != "" {
		parts = append(parts, "Remaining delegated amount: "+event.PostDelegatedAmountRaw+" raw units.")
	}
	if event.TransferFeeBasisPoints != nil {
		parts = append(parts, "Fee: "+strconv.Itoa(*event.TransferFeeBasisPoints)+" basis points; maximum raw fee "+event.MaximumFeeRaw+".")
	}
	return strings.Join(uniqueExplanationStrings(parts), " ")
}

func guardV3ExplanationAuthorityKey(kind, account, delegate, newAuthority string) string {
	return strings.Join([]string{kind, account, delegate, newAuthority}, "|")
}
