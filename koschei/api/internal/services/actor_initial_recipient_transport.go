package services

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ActorInitialRecipientTransport isolates the distribution investigator from a
// concrete RPC vendor. Implementations may use a Koschei-owned node, a
// multi-provider manager, or a temporary commercial fallback. The investigator
// only asks for canonical Solana RPC primitives.
type ActorInitialRecipientTransport interface {
	Transaction(ctx context.Context, signature string) (map[string]any, error)
	TokenAccountsByOwnerForMint(ctx context.Context, owner, mint string) (SolanaOwnedTokenAccountsResult, error)
	SignaturesForAddressPage(ctx context.Context, address string, options SolanaSignaturePageOptions) ([]SolanaSignatureInfo, error)
	TokenSupply(ctx context.Context, mint string) (SolanaTokenSupplyResult, error)
	LargestTokenAccounts(ctx context.Context, mint string) (SolanaLargestAccountsResult, error)
	MultipleAccounts(ctx context.Context, addresses []string) (SolanaMultipleAccountInfoResult, error)
}

// InvestigateActorInitialRecipientsWithTransport is the provider-neutral
// version of InvestigateActorInitialRecipients. It preserves the same evidence
// semantics while routing every network read through the supplied transport.
// Recipient-wide wallet history is still forbidden; only the creator's
// mint-specific token accounts and recipient balance checks are used.
func InvestigateActorInitialRecipientsWithTransport(ctx context.Context, transport ActorInitialRecipientTransport, creator, mint, creationSignature string, options ActorInitialRecipientOptions) ActorInitialRecipientReport {
	creator = strings.TrimSpace(creator)
	mint = strings.TrimSpace(mint)
	creationSignature = strings.TrimSpace(creationSignature)
	result := ActorInitialRecipientReport{
		Mint: mint, CreatorWallet: creator, CreationSignature: creationSignature,
		Status: "not_investigated", DistributionScope: "not_investigated",
		SourceTokenAccounts: []string{}, Recipients: []ActorInitialRecipient{},
		TopHolderStatus: "not_investigated", Limitations: []string{}, GeneratedAt: time.Now().UTC(),
	}
	if transport == nil {
		result.Status = "rpc_unavailable"
		result.Limitations = append(result.Limitations, "Koschei Solana transport is unavailable; mint-specific recipient investigation was not run.")
		return result
	}
	if creator == "" || mint == "" {
		result.Status = "invalid_target"
		result.Limitations = append(result.Limitations, "Creator wallet and token mint are required.")
		return result
	}
	maxRecipients, pageSize, maxPages, maxTransactions := normalizeActorRecipientOptions(options)

	sourceAccounts := map[string]bool{}
	if creationSignature != "" {
		if tx, err := transport.Transaction(ctx, creationSignature); err == nil {
			for _, address := range actorRecipientOwnedTokenAccounts(tx, creator, mint) {
				sourceAccounts[address] = true
			}
		} else {
			result.Limitations = append(result.Limitations, "Creation transaction token-account resolution failed: "+compactActorFundingError(err))
		}
	}
	if current, err := transport.TokenAccountsByOwnerForMint(ctx, creator, mint); err == nil {
		for _, account := range current.Value {
			if address := strings.TrimSpace(account.Pubkey); address != "" {
				sourceAccounts[address] = true
			}
		}
	} else {
		result.Limitations = append(result.Limitations, "Creator mint-specific token accounts could not be read: "+compactActorFundingError(err))
	}
	for address := range sourceAccounts {
		result.SourceTokenAccounts = append(result.SourceTokenAccounts, address)
	}
	sort.Strings(result.SourceTokenAccounts)
	if len(result.SourceTokenAccounts) == 0 {
		result.Status = "creator_token_accounts_not_observed"
		result.DistributionScope = "not_investigated"
		result.Limitations = append(result.Limitations, "No creator-owned mint-specific token account was observed in the creation transaction or current owner query.")
		return result
	}

	signatureIndex := map[string]SolanaSignatureInfo{}
	complete := true
	for _, tokenAccount := range result.SourceTokenAccounts {
		before := ""
		accountComplete := false
		for page := 0; page < maxPages && ctx.Err() == nil; page++ {
			rows, err := transport.SignaturesForAddressPage(ctx, tokenAccount, SolanaSignaturePageOptions{Limit: pageSize, Before: before})
			if err != nil {
				result.Limitations = append(result.Limitations, "Token-account signature history remained partial: "+compactActorFundingError(err))
				break
			}
			for _, row := range rows {
				if signature := strings.TrimSpace(row.Signature); signature != "" {
					signatureIndex[signature] = row
				}
			}
			if len(rows) < pageSize {
				accountComplete = true
				break
			}
			last := strings.TrimSpace(rows[len(rows)-1].Signature)
			if last == "" || last == before {
				result.Limitations = append(result.Limitations, "Token-account signature cursor did not advance; history was not marked complete.")
				break
			}
			before = last
		}
		if !accountComplete {
			complete = false
		}
	}
	result.HistoryComplete = complete
	if complete {
		result.DistributionScope = "complete_creator_token_account_history"
	} else {
		result.DistributionScope = "bounded_creator_token_account_history"
		result.Limitations = append(result.Limitations, "ATA history did not reach its end; discovered transfers are recipient-in-window evidence, not asserted initial recipients.")
	}

	signatures := make([]SolanaSignatureInfo, 0, len(signatureIndex))
	for _, row := range signatureIndex {
		signatures = append(signatures, row)
	}
	sort.SliceStable(signatures, func(i, j int) bool {
		left, right := actorFundingSignatureTime(signatures[i]), actorFundingSignatureTime(signatures[j])
		if !left.Equal(right) {
			if left.IsZero() {
				return false
			}
			if right.IsZero() {
				return true
			}
			return left.Before(right)
		}
		if signatures[i].Slot != signatures[j].Slot {
			return signatures[i].Slot < signatures[j].Slot
		}
		return signatures[i].Signature < signatures[j].Signature
	})
	result.SignaturesScanned = len(signatures)

	transfers := []actorRecipientTransfer{}
	seenRecipient := map[string]bool{}
	for _, signature := range signatures {
		if len(transfers) >= maxRecipients || result.TransactionsParsed >= maxTransactions || ctx.Err() != nil {
			break
		}
		if signature.Err != nil || strings.TrimSpace(signature.Signature) == "" {
			continue
		}
		tx, err := transport.Transaction(ctx, signature.Signature)
		if err != nil {
			continue
		}
		result.TransactionsParsed++
		for _, transfer := range actorRecipientTransfersFromTransaction(tx, signature, creator, mint, sourceAccounts) {
			if seenRecipient[transfer.Wallet] {
				continue
			}
			seenRecipient[transfer.Wallet] = true
			transfers = append(transfers, transfer)
			if len(transfers) >= maxRecipients {
				break
			}
		}
	}

	topHolders, holderStatus := actorRecipientTopHoldersWithTransport(ctx, transport, mint)
	result.TopHolderStatus = holderStatus
	for index, transfer := range transfers {
		recipient := ActorInitialRecipient{
			Sequence: index + 1, Wallet: transfer.Wallet,
			SourceTokenAccount: transfer.SourceTokenAccount, DestinationTokenAccount: transfer.DestinationTokenAccount,
			Amount: transfer.Amount, RawAmount: transfer.RawAmount, Decimals: transfer.Decimals,
			Signature: transfer.Signature, Slot: transfer.Slot, ObservedAt: transfer.ObservedAt,
			Program: transfer.Program, VerificationStatus: "verified",
			CurrentBalanceStatus: "not_investigated", CurrentBalanceRaw: "0", CurrentTokenAccounts: []string{}, Limitations: []string{},
		}
		balance, err := transport.TokenAccountsByOwnerForMint(ctx, transfer.Wallet, mint)
		result.RecipientBalanceQueries++
		if err != nil {
			recipient.CurrentBalanceStatus = "rpc_failed"
			recipient.Fate = "current_balance_unresolved"
			recipient.Limitations = append(recipient.Limitations, compactActorFundingError(err))
		} else {
			raw, ui, _, accounts := AggregateOwnedTokenAccounts(balance, mint)
			recipient.CurrentBalanceRaw = raw
			recipient.CurrentBalance = ui
			recipient.CurrentTokenAccounts = accounts
			switch {
			case len(accounts) == 0:
				recipient.CurrentBalanceStatus = "no_current_token_account"
				recipient.Fate = "exited_or_account_closed"
			case ui <= 0:
				recipient.CurrentBalanceStatus = "zero_balance"
				recipient.Fate = "zero_balance"
			default:
				recipient.CurrentBalanceStatus = "current_balance_observed"
				recipient.Fate = "still_holds"
			}
		}
		if holder, ok := topHolders[transfer.Wallet]; ok {
			recipient.MatchesTopHolder = true
			recipient.TopHolderRank = holder.Rank
			recipient.TopHolderPercentage = holder.Percentage
			if recipient.Fate == "still_holds" {
				recipient.Fate = "became_top_holder"
			}
		}
		result.Recipients = append(result.Recipients, recipient)
	}

	switch {
	case len(result.Recipients) == 0:
		result.Status = "no_creator_distribution_observed"
	case complete:
		result.Status = "initial_recipients_resolved"
	default:
		result.Status = "recipient_window_resolved"
	}
	return result
}

func actorRecipientTopHoldersWithTransport(ctx context.Context, transport ActorInitialRecipientTransport, mint string) (map[string]actorRecipientTopHolder, string) {
	out := map[string]actorRecipientTopHolder{}
	supply, err := transport.TokenSupply(ctx, mint)
	if err != nil {
		return out, "supply_unavailable"
	}
	largest, err := transport.LargestTokenAccounts(ctx, mint)
	if err != nil {
		return out, "largest_accounts_unavailable"
	}
	total := solanaTokenAmountFloat(supply.Value)
	if total <= 0 || len(largest.Value) == 0 {
		return out, "invalid_supply"
	}
	if len(largest.Value) > 20 {
		largest.Value = largest.Value[:20]
	}
	addresses := make([]string, 0, len(largest.Value))
	for _, row := range largest.Value {
		if address := strings.TrimSpace(row.Address); address != "" {
			addresses = append(addresses, address)
		}
	}
	tokenAccounts, err := transport.MultipleAccounts(ctx, addresses)
	if err != nil {
		return out, "token_account_owner_resolution_unavailable"
	}
	owners := SolanaHolderOwnerAddresses(tokenAccounts.Value)
	ownerMap := map[string]*SolanaAccountInfo{}
	ownerComplete := true
	if len(owners) > 0 {
		ownerAccounts, err := transport.MultipleAccounts(ctx, owners)
		if err != nil {
			ownerComplete = false
		} else {
			for i, owner := range owners {
				if i < len(ownerAccounts.Value) {
					ownerMap[owner] = ownerAccounts.Value[i]
				}
			}
		}
	}
	analysis := AnalyzeSolanaHolderRolesSnapshot(HolderRoleSnapshotInput{
		TotalSupply: total, Largest: largest.Value, TokenAccounts: tokenAccounts.Value,
		OwnerAccounts: ownerMap, OwnerMetadataComplete: ownerComplete,
	})
	if !analysis.Available {
		return out, analysis.Status
	}
	for _, account := range analysis.Accounts {
		wallet := strings.TrimSpace(account.OwnerWallet)
		if wallet == "" {
			continue
		}
		row := out[wallet]
		if row.Rank == 0 || account.Rank < row.Rank {
			row.Rank = account.Rank
		}
		row.Percentage += account.RawPercentage
		out[wallet] = row
	}
	return out, analysis.Status
}

func validateActorInitialRecipientTransport(transport ActorInitialRecipientTransport) error {
	if transport == nil {
		return fmt.Errorf("actor initial recipient transport is nil")
	}
	return nil
}
