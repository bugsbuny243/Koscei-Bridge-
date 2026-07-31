package handlers

import "strings"

func unavailableTransactionGuardV3AuthoritySurface() transactionGuardAuthoritySurfaceAnalysis {
	return transactionGuardAuthoritySurfaceAnalysis{
		Requested: true,
		Required:  envBool("TRANSACTION_GUARD_REQUIRE_AUTHORITY_SURFACE", true),
		Available: false,
		Complete:  false,
		Status:    "simulation_unavailable",
		Events:    []transactionGuardAuthorityEvent{},
		TransferHookProgramIDs: []string{},
		Limitations: []string{"Authority persistence evidence requires a decoded transaction and successful Solana simulation."},
	}
}

func transactionGuardV3DecodedWithAuthoritySurface(decoded transactionGuardDecodedTransaction, authority transactionGuardAuthoritySurfaceAnalysis) transactionGuardDecodedTransaction {
	decoded.ProgramIDs = normalizeGuardProgramList(append(decoded.ProgramIDs, authority.TransferHookProgramIDs...))
	for _, event := range authority.Events {
		operation := transactionGuardDecodedTokenOperation{}
		switch event.Kind {
		case "approve", "approve_checked":
			operation = transactionGuardDecodedTokenOperation{
				Kind: event.Kind, ProgramID: event.ProgramID, Source: event.Source, Mint: event.Mint,
				Authority: event.CurrentAuthority, Delegate: event.Delegate, AmountRaw: event.AmountRaw, Decimals: event.Decimals,
			}
		case "set_authority":
			operation = transactionGuardDecodedTokenOperation{
				Kind: event.Kind, ProgramID: event.ProgramID, Account: event.Account,
				Authority: event.CurrentAuthority, AuthorityType: event.AuthorityType, NewAuthority: event.NewAuthority,
			}
		case "initialize_permanent_delegate":
			operation = transactionGuardDecodedTokenOperation{
				Kind: event.Kind, ProgramID: event.ProgramID, Account: event.Mint, Mint: event.Mint,
				Delegate: event.Delegate, NewAuthority: event.Delegate,
			}
		case "initialize_transfer_hook", "update_transfer_hook":
			operation = transactionGuardDecodedTokenOperation{
				Kind: event.Kind, ProgramID: event.ProgramID, Account: event.Mint, Mint: event.Mint,
				Authority: event.CurrentAuthority, NewAuthority: event.TransferHookProgramID,
			}
		default:
			continue
		}
		if !guardV3TokenOperationExists(decoded.TokenOperations, operation) {
			decoded.TokenOperations = append(decoded.TokenOperations, operation)
		}
	}
	return decoded
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
		authorityType = string(rune(*value.AuthorityType + 48))
	}
	return strings.Join([]string{
		value.Kind, value.ProgramID, value.Account, value.Source, value.Mint,
		value.Authority, value.Delegate, value.NewAuthority, authorityType,
	}, "|")
}
