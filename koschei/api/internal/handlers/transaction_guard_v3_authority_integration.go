package handlers

import (
	"strconv"
	"strings"
)

func unavailableTransactionGuardV3AuthoritySurface() transactionGuardAuthoritySurfaceAnalysis {
	return transactionGuardAuthoritySurfaceAnalysis{
		Requested:              true,
		Required:               envBool("TRANSACTION_GUARD_REQUIRE_AUTHORITY_SURFACE", true),
		Available:              false,
		Complete:               false,
		Status:                 "simulation_unavailable",
		Events:                 []transactionGuardAuthorityEvent{},
		TransferHookProgramIDs: []string{},
		Limitations:            []string{"Authority persistence evidence requires a decoded transaction and successful Solana simulation."},
	}
}

func transactionGuardV3DecodedWithAuthoritySurface(decoded transactionGuardDecodedTransaction, authority transactionGuardAuthoritySurfaceAnalysis) transactionGuardDecodedTransaction {
	decoded.ProgramIDs = normalizeGuardProgramList(append(decoded.ProgramIDs, authority.TransferHookProgramIDs...))
	for _, event := range authority.Events {
		operation, ok := guardV3DecodedTokenOperationFromAuthorityEvent(event)
		if ok && !guardV3TokenOperationExists(decoded.TokenOperations, operation) {
			decoded.TokenOperations = append(decoded.TokenOperations, operation)
		}
	}
	return decoded
}

func removeTransactionGuardV3LegacyAuthorityFindings(assessment transactionFirewallAssessment, authority transactionGuardAuthoritySurfaceAnalysis) transactionFirewallAssessment {
	remove := map[string]bool{}
	for _, event := range authority.Events {
		switch event.Kind {
		case "approve", "approve_checked", "revoke":
			remove["delegate_approval"] = true
		case "set_authority":
			remove["authority_change"] = true
			if event.AuthorityType != nil && *event.AuthorityType == 8 {
				remove["permanent_delegate"] = true
			}
		case "initialize_permanent_delegate":
			remove["permanent_delegate"] = true
		case "initialize_transfer_hook", "update_transfer_hook":
			remove["transfer_hook"] = true
		}
	}
	if len(remove) == 0 {
		return assessment
	}
	filtered := make([]transactionFirewallFinding, 0, len(assessment.Findings))
	for _, finding := range assessment.Findings {
		if !remove[finding.Code] {
			filtered = append(filtered, finding)
		}
	}
	assessment.Findings = filtered
	return assessment
}

func guardV3DecodedTokenOperationFromAuthorityEvent(event transactionGuardAuthorityEvent) (transactionGuardDecodedTokenOperation, bool) {
	switch event.Kind {
	case "approve", "approve_checked":
		return transactionGuardDecodedTokenOperation{
			Kind: event.Kind, ProgramID: event.ProgramID, Source: event.Source, Mint: event.Mint,
			Authority: event.CurrentAuthority, Delegate: event.Delegate, AmountRaw: event.AmountRaw, Decimals: event.Decimals,
		}, true
	case "revoke":
		return transactionGuardDecodedTokenOperation{
			Kind: event.Kind, ProgramID: event.ProgramID, Source: event.Source, Authority: event.CurrentAuthority,
		}, true
	case "set_authority":
		return transactionGuardDecodedTokenOperation{
			Kind: event.Kind, ProgramID: event.ProgramID, Account: event.Account,
			Authority: event.CurrentAuthority, AuthorityType: event.AuthorityType, NewAuthority: event.NewAuthority,
		}, true
	case "initialize_permanent_delegate":
		return transactionGuardDecodedTokenOperation{
			Kind: event.Kind, ProgramID: event.ProgramID, Account: event.Mint, Mint: event.Mint,
			Delegate: event.Delegate, NewAuthority: event.Delegate,
		}, true
	case "initialize_transfer_hook", "update_transfer_hook":
		return transactionGuardDecodedTokenOperation{
			Kind: event.Kind, ProgramID: event.ProgramID, Account: event.Mint, Mint: event.Mint,
			Authority: event.CurrentAuthority, NewAuthority: event.TransferHookProgramID,
		}, true
	default:
		return transactionGuardDecodedTokenOperation{}, false
	}
}

func guardV3TokenOperationExists(values []transactionGuardDecodedTokenOperation, candidate transactionGuardDecodedTokenOperation) bool {
	key := guardV3TokenOperationKey(candidate)
	for _, value := range values {
		if guardV3TokenOperationKey(value) == key {
			return true
		}
	}
	return false
}

func guardV3TokenOperationKey(value transactionGuardDecodedTokenOperation) string {
	authorityType := ""
	if value.AuthorityType != nil {
		authorityType = strconv.Itoa(*value.AuthorityType)
	}
	return strings.Join([]string{
		value.Kind, value.ProgramID, value.Account, value.Source, value.Mint,
		value.Authority, value.Delegate, value.NewAuthority, authorityType,
	}, "|")
}
