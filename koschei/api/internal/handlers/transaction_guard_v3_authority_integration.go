package handlers

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
		switch event.Kind {
		case "approve", "approve_checked":
			decoded.TokenOperations = append(decoded.TokenOperations, transactionGuardDecodedTokenOperation{
				Kind: event.Kind, ProgramID: event.ProgramID, Source: event.Source, Mint: event.Mint,
				Authority: event.CurrentAuthority, Delegate: event.Delegate, AmountRaw: event.AmountRaw, Decimals: event.Decimals,
			})
		case "set_authority":
			decoded.TokenOperations = append(decoded.TokenOperations, transactionGuardDecodedTokenOperation{
				Kind: event.Kind, ProgramID: event.ProgramID, Account: event.Account,
				Authority: event.CurrentAuthority, AuthorityType: event.AuthorityType, NewAuthority: event.NewAuthority,
			})
		case "initialize_permanent_delegate":
			decoded.TokenOperations = append(decoded.TokenOperations, transactionGuardDecodedTokenOperation{
				Kind: event.Kind, ProgramID: event.ProgramID, Account: event.Mint, Mint: event.Mint,
				Delegate: event.Delegate, NewAuthority: event.Delegate,
			})
		case "initialize_transfer_hook", "update_transfer_hook":
			decoded.TokenOperations = append(decoded.TokenOperations, transactionGuardDecodedTokenOperation{
				Kind: event.Kind, ProgramID: event.ProgramID, Account: event.Mint, Mint: event.Mint,
				Authority: event.CurrentAuthority, NewAuthority: event.TransferHookProgramID,
			})
		}
	}
	return decoded
}
