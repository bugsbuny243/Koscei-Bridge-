package handlers

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"

	"koschei/api/internal/services"
)

const guardV3AutomaticAccountLimit = 32

func transactionGuardV3BalanceAddresses(decoded transactionGuardDecodedTransaction, wallet string, declared []string, limit int) ([]string, bool, int) {
	if limit <= 0 {
		limit = guardV3AutomaticAccountLimit
	}
	addresses := []string{}
	seen := map[string]bool{}
	complete := decoded.Available && decoded.Complete
	appendAddress := func(address string) {
		address = strings.TrimSpace(address)
		if address == "" || strings.HasPrefix(address, "lookup-") || strings.HasPrefix(address, "unresolved-account:") || seen[address] {
			if strings.HasPrefix(address, "lookup-") || strings.HasPrefix(address, "unresolved-account:") {
				complete = false
			}
			return
		}
		seen[address] = true
		addresses = append(addresses, address)
	}
	for _, address := range declared {
		appendAddress(address)
	}
	wallet = strings.TrimSpace(wallet)
	if wallet != "" && looksLikeGuardPubkey(wallet) {
		appendAddress(wallet)
	}
	for _, account := range decoded.StaticAccounts {
		if account.Writable {
			appendAddress(account.Address)
		}
	}
	for _, account := range decoded.LoadedAccounts {
		if account.Writable {
			appendAddress(account.Address)
		}
	}
	required := len(addresses)
	if len(addresses) > limit {
		addresses = addresses[:limit]
		complete = false
	}
	return addresses, complete, required
}

func evaluateTransactionGuardV3AutomaticBalances(
	decoded transactionGuardDecodedTransaction,
	wallet string,
	addresses []string,
	addressesRequired int,
	coverageComplete bool,
	preOrder, postOrder []string,
	pre, post []*services.SolanaAccountInfo,
) (transactionGuardAutomaticBalanceAnalysis, []transactionFirewallFinding) {
	analysis := transactionGuardAutomaticBalanceAnalysis{
		Requested: len(addresses) > 0, Status: "not_requested", Wallet: strings.TrimSpace(wallet),
		AddressesRequired: addressesRequired, AddressesRequested: len(addresses),
		WalletSOLDeltaLamports: "0", WalletSOLSpentLamports: "0", WalletSOLReceivedLamports: "0",
		Accounts: []transactionGuardAutomaticBalanceDelta{}, Limitations: []string{},
	}
	findings := []transactionFirewallFinding{}
	if len(addresses) == 0 {
		return analysis, findings
	}
	analysis.Status = "evidence_incomplete"
	preIndex, postIndex := addressIndex(preOrder), addressIndex(postOrder)
	missingEvidence := 0
	walletDelta := big.NewInt(0)
	closedTokenAccounts := []string{}
	for _, address := range addresses {
		delta := transactionGuardAutomaticBalanceDelta{
			Address: address, Writable: transactionGuardV3AddressWritable(decoded, address),
			PreLamports: "0", PostLamports: "0", LamportDelta: "0", EvidenceStatus: "verified_rpc_simulation",
		}
		prePosition, preOK := preIndex[address]
		postPosition, postOK := postIndex[address]
		if !preOK || !postOK || prePosition >= len(pre) || postPosition >= len(post) {
			delta.EvidenceStatus = "account_order_missing"
			analysis.Accounts = append(analysis.Accounts, delta)
			missingEvidence++
			continue
		}
		preInfo, postInfo := pre[prePosition], post[postPosition]
		delta.PrePresent, delta.PostPresent = preInfo != nil, postInfo != nil
		if preInfo == nil && postInfo == nil {
			delta.EvidenceStatus = "transient_or_unavailable"
			analysis.Accounts = append(analysis.Accounts, delta)
			missingEvidence++
			continue
		}
		analysis.AddressesObserved++
		delta.AccountCreated = preInfo == nil && postInfo != nil
		delta.AccountClosed = preInfo != nil && postInfo == nil
		if delta.AccountCreated {
			analysis.CreatedAccountCount++
			delta.EvidenceStatus = "verified_rpc_simulation_created_account"
		}
		if delta.AccountClosed {
			analysis.ClosedAccountCount++
			delta.EvidenceStatus = "verified_rpc_simulation_closed_account"
		}
		preLamports, postLamports := int64(0), int64(0)
		if preInfo != nil {
			preLamports = preInfo.Lamports
			delta.PreProgramOwner = strings.TrimSpace(preInfo.Owner)
		}
		if postInfo != nil {
			postLamports = postInfo.Lamports
			delta.PostProgramOwner = strings.TrimSpace(postInfo.Owner)
		}
		preBig, postBig := big.NewInt(preLamports), big.NewInt(postLamports)
		lamportDelta := new(big.Int).Sub(new(big.Int).Set(postBig), preBig)
		delta.PreLamports, delta.PostLamports, delta.LamportDelta = preBig.String(), postBig.String(), lamportDelta.String()
		if strings.EqualFold(strings.TrimSpace(wallet), address) {
			walletDelta.Set(lamportDelta)
		}
		if preInfo != nil && postInfo != nil && !strings.EqualFold(delta.PreProgramOwner, delta.PostProgramOwner) {
			findings = append(findings, transactionFirewallFinding{
				Code: "automatic_account_program_owner_changed", Severity: "high", Title: "Writable account program owner changed",
				Evidence: fmt.Sprintf("account=%s before=%s after=%s", address, delta.PreProgramOwner, delta.PostProgramOwner), Score: 30,
			})
		}

		preToken, preTokenPresent, preTokenErr := transactionGuardV3TokenSnapshot(preInfo)
		postToken, postTokenPresent, postTokenErr := transactionGuardV3TokenSnapshot(postInfo)
		if preTokenErr != nil || postTokenErr != nil {
			delta.EvidenceStatus = "token_account_decode_failed"
			missingEvidence++
		}
		if preTokenPresent || postTokenPresent {
			delta.TokenAccount = true
			preAmount, postAmount := uint64(0), uint64(0)
			if preTokenPresent {
				delta.Mint = guardV3Base58Encode(preToken.Mint[:])
				delta.PreTokenOwner = guardV3Base58Encode(preToken.Owner[:])
				preAmount = preToken.Amount
			}
			if postTokenPresent {
				postMint := guardV3Base58Encode(postToken.Mint[:])
				if delta.Mint == "" {
					delta.Mint = postMint
				}
				delta.PostTokenOwner = guardV3Base58Encode(postToken.Owner[:])
				postAmount = postToken.Amount
				if preTokenPresent && !bytes.Equal(preToken.Mint[:], postToken.Mint[:]) {
					findings = append(findings, transactionFirewallFinding{
						Code: "automatic_token_account_mint_changed", Severity: "critical", Title: "Writable token account mint changed",
						Evidence: fmt.Sprintf("account=%s before=%s after=%s", address, delta.Mint, postMint), Score: 100,
					})
				}
				if preTokenPresent && !bytes.Equal(preToken.Owner[:], postToken.Owner[:]) {
					findings = append(findings, transactionFirewallFinding{
						Code: "automatic_token_account_owner_changed", Severity: "critical", Title: "Writable token account authority owner changed",
						Evidence: fmt.Sprintf("account=%s before=%s after=%s", address, delta.PreTokenOwner, delta.PostTokenOwner), Score: 100,
					})
				}
			}
			preTokenBig, postTokenBig := new(big.Int).SetUint64(preAmount), new(big.Int).SetUint64(postAmount)
			tokenDelta := new(big.Int).Sub(new(big.Int).Set(postTokenBig), preTokenBig)
			delta.PreTokenAmountRaw, delta.PostTokenAmountRaw, delta.TokenDeltaRaw = preTokenBig.String(), postTokenBig.String(), tokenDelta.String()
			if tokenDelta.Sign() != 0 {
				analysis.TokenAccountChangeCount++
			}
			if delta.AccountClosed && preTokenPresent {
				closedTokenAccounts = append(closedTokenAccounts, address)
			}
		}
		delta.Changed = delta.AccountCreated || delta.AccountClosed || lamportDelta.Sign() != 0 || delta.TokenDeltaRaw != "" && delta.TokenDeltaRaw != "0" || !strings.EqualFold(delta.PreProgramOwner, delta.PostProgramOwner)
		if delta.Changed {
			analysis.ChangedAccountCount++
		}
		analysis.Accounts = append(analysis.Accounts, delta)
	}
	analysis.Available = analysis.AddressesObserved > 0
	analysis.Complete = coverageComplete && missingEvidence == 0 && analysis.AddressesRequested == analysis.AddressesRequired
	if analysis.Complete {
		analysis.Status = "verified_rpc_simulation_balance_changes"
	} else {
		analysis.Limitations = append(analysis.Limitations, "Automatic balance coverage did not observe every required account; missing evidence is not treated as a safe result.")
		findings = append(findings, transactionFirewallFinding{
			Code: "automatic_balance_coverage_incomplete", Severity: "high", Title: "Automatic balance-change coverage is incomplete",
			Evidence: fmt.Sprintf("required=%d requested=%d observed=%d missing=%d", analysis.AddressesRequired, analysis.AddressesRequested, analysis.AddressesObserved, missingEvidence), Score: 30,
		})
	}
	analysis.WalletSOLDeltaLamports = walletDelta.String()
	if walletDelta.Sign() < 0 {
		analysis.WalletSOLSpentLamports = new(big.Int).Neg(new(big.Int).Set(walletDelta)).String()
	} else if walletDelta.Sign() > 0 {
		analysis.WalletSOLReceivedLamports = walletDelta.String()
	}
	if strings.TrimSpace(wallet) != "" && walletDelta.Sign() != 0 {
		findings = append(findings, transactionFirewallFinding{
			Code: "automatic_wallet_sol_delta", Severity: "info", Title: "Simulated wallet SOL balance change",
			Evidence: fmt.Sprintf("wallet=%s delta_lamports=%s spent_lamports=%s received_lamports=%s", wallet, analysis.WalletSOLDeltaLamports, analysis.WalletSOLSpentLamports, analysis.WalletSOLReceivedLamports), Score: 0,
		})
	}
	if analysis.TokenAccountChangeCount > 0 {
		findings = append(findings, transactionFirewallFinding{
			Code: "automatic_token_balance_changes", Severity: "info", Title: "Simulated token balance changes observed",
			Evidence: fmt.Sprintf("changed_token_accounts=%d changed_accounts=%d", analysis.TokenAccountChangeCount, analysis.ChangedAccountCount), Score: 0,
		})
	}
	if len(closedTokenAccounts) > 0 {
		findings = append(findings, transactionFirewallFinding{
			Code: "automatic_token_account_closed", Severity: "medium", Title: "Simulated transaction closes token account",
			Evidence: strings.Join(closedTokenAccounts, ", "), Score: 20,
		})
	}
	return analysis, uniqueGuardV3Findings(findings)
}

func transactionGuardV3TokenSnapshot(info *services.SolanaAccountInfo) (services.SolanaTokenAccountSnapshot, bool, error) {
	if info == nil {
		return services.SolanaTokenAccountSnapshot{}, false, nil
	}
	owner := strings.TrimSpace(info.Owner)
	if owner != guardV3SPLTokenProgramID && owner != guardV3Token2022ProgramID {
		return services.SolanaTokenAccountSnapshot{}, false, nil
	}
	snapshot, err := services.SolanaTokenAccountSnapshotFromInfo(info)
	return snapshot, err == nil, err
}

func transactionGuardV3AddressWritable(decoded transactionGuardDecodedTransaction, address string) bool {
	for _, account := range decoded.StaticAccounts {
		if strings.EqualFold(account.Address, address) {
			return account.Writable
		}
	}
	for _, account := range decoded.LoadedAccounts {
		if strings.EqualFold(account.Address, address) {
			return account.Writable
		}
	}
	return false
}
