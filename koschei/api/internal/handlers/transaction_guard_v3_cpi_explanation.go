package handlers

import (
	"fmt"
	"sort"
	"strings"
)

func buildTransactionGuardV3ExplanationWithCPI(
	wallet string,
	assessment transactionFirewallAssessment,
	decoded transactionGuardDecodedTransaction,
	threat transactionGuardThreatHistoryAnalysis,
	cpi transactionGuardCPIFlowAnalysis,
) transactionGuardPreSigningExplanation {
	out := buildTransactionGuardV3Explanation(wallet, assessment, decoded, threat)
	if !cpi.Available {
		out.Limitations = uniqueExplanationStrings(append(out.Limitations, cpi.Limitations...))
		if cpi.Required {
			out.EvidenceStatus = "partial"
		}
		out.PlainLanguageSummary = guardV3ExplanationSummary(out)
		return out
	}

	seenSends := map[string]bool{}
	for _, movement := range out.Sends {
		seenSends[explanationMovementKey("send", movement)] = true
	}
	seenReceives := map[string]bool{}
	for _, movement := range out.Receives {
		seenReceives[explanationMovementKey("receive", movement)] = true
	}
	wallet = strings.TrimSpace(wallet)
	for _, movement := range cpi.AssetMovements {
		explained := transactionGuardExplanationMovement{
			AssetType: movement.AssetType,
			Mint:      movement.Mint,
			AmountRaw: movement.AmountRaw,
			Amount:    formatGuardRawAmount(movement.AmountRaw, movement.Decimals),
			From:      movement.Source,
			To:        movement.Destination,
			Account:   movement.Source,
			Evidence:  "decoded_inner_cpi_instruction",
		}
		if movement.AssetType == "SOL" {
			explained.Amount = formatGuardRawAmount(movement.AmountRaw, intPointer(9))
		}
		if movement.WalletOrigin {
			key := explanationMovementKey("send", explained)
			if !seenSends[key] {
				seenSends[key] = true
				out.Sends = append(out.Sends, explained)
			}
			continue
		}
		if wallet != "" && (movement.Destination == wallet || movement.DestinationController == wallet) {
			key := explanationMovementKey("receive", explained)
			if !seenReceives[key] {
				seenReceives[key] = true
				out.Receives = append(out.Receives, explained)
			}
		}
	}

	out.InvokedPrograms = normalizeGuardProgramList(append(out.InvokedPrograms, cpi.ProgramIDs...))
	out.Recipients = mergeTransactionGuardCPIRecipients(out.Recipients, cpi, threat)
	if cpi.WalletOriginMovementCount > 0 {
		out.HiddenOrSensitiveActions = append(out.HiddenOrSensitiveActions,
			fmt.Sprintf("%d wallet-origin asset movement(s) execute inside CPI calls.", cpi.WalletOriginMovementCount))
	}
	if cpi.UndeclaredMovementCount > 0 {
		out.HiddenOrSensitiveActions = append(out.HiddenOrSensitiveActions,
			fmt.Sprintf("%d CPI asset movement(s) target addresses absent from the declared account policy.", cpi.UndeclaredMovementCount))
	}
	vaultCandidates := 0
	for _, account := range cpi.Accounts {
		if account.VaultCandidate {
			vaultCandidates++
		}
	}
	if vaultCandidates > 0 {
		out.HiddenOrSensitiveActions = append(out.HiddenOrSensitiveActions,
			fmt.Sprintf("%d program-controlled token vault candidate(s) participate in the execution path.", vaultCandidates))
	}
	if cpi.Required && !cpi.Complete {
		out.HiddenOrSensitiveActions = append(out.HiddenOrSensitiveActions,
			"CPI evidence is incomplete; Koschei cannot safely explain the full inner execution path.")
		out.EvidenceStatus = "partial"
	}
	out.HiddenOrSensitiveActions = uniqueExplanationStrings(out.HiddenOrSensitiveActions)
	out.Limitations = uniqueExplanationStrings(append(out.Limitations, cpi.Limitations...))
	out.PlainLanguageSummary = guardV3ExplanationSummary(out)
	return out
}

func mergeTransactionGuardCPIRecipients(
	existing []transactionGuardExplanationRecipient,
	cpi transactionGuardCPIFlowAnalysis,
	threat transactionGuardThreatHistoryAnalysis,
) []transactionGuardExplanationRecipient {
	roles := map[string]map[string]bool{}
	canonical := map[string]string{}
	for _, recipient := range existing {
		key := strings.ToLower(strings.TrimSpace(recipient.Address))
		if key == "" {
			continue
		}
		if roles[key] == nil {
			roles[key] = map[string]bool{}
		}
		canonical[key] = recipient.Address
		for _, role := range recipient.Roles {
			roles[key][role] = true
		}
	}
	add := func(address, role string) {
		address = strings.TrimSpace(address)
		if !looksLikeGuardPubkey(address) {
			return
		}
		key := strings.ToLower(address)
		if roles[key] == nil {
			roles[key] = map[string]bool{}
			canonical[key] = address
		}
		roles[key][role] = true
	}
	for _, movement := range cpi.AssetMovements {
		role := "cpi_token_destination"
		if movement.AssetType == "SOL" {
			role = "cpi_sol_recipient"
		}
		add(movement.Destination, role)
	}
	for _, program := range cpi.ProgramIDs {
		add(program, "cpi_program")
	}
	threatByAddress := map[string]transactionGuardThreatSubject{}
	for _, subject := range threat.Subjects {
		threatByAddress[strings.ToLower(subject.Address)] = subject
	}
	keys := make([]string, 0, len(roles))
	for key := range roles {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]transactionGuardExplanationRecipient, 0, len(keys))
	for _, key := range keys {
		roleList := make([]string, 0, len(roles[key]))
		for role := range roles[key] {
			roleList = append(roleList, role)
		}
		sort.Strings(roleList)
		subject, matched := threatByAddress[key]
		out = append(out, transactionGuardExplanationRecipient{
			Address: canonical[key], Roles: roleList, HistoricalMatch: matched,
			HistoricalRisk: subject.HighestRiskLevel, HistoricalIndex: subject.HighestRiskIndex,
		})
	}
	return out
}
