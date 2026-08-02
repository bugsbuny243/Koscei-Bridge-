package services

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ActorInitialRecipientOptions struct {
	MaxRecipients        int
	SignaturePageSize    int
	MaxPagesPerTokenATA  int
	MaxTransactionsParse int
}

type ActorInitialRecipient struct {
	Sequence                int       `json:"sequence"`
	Wallet                  string    `json:"wallet"`
	SourceTokenAccount      string    `json:"source_token_account"`
	DestinationTokenAccount string    `json:"destination_token_account"`
	Amount                  float64   `json:"amount"`
	RawAmount               string    `json:"raw_amount,omitempty"`
	Decimals                int       `json:"decimals"`
	Signature               string    `json:"signature"`
	Slot                    int64     `json:"slot"`
	ObservedAt              time.Time `json:"observed_at"`
	Program                 string    `json:"program"`
	VerificationStatus      string    `json:"verification_status"`
	CurrentBalanceStatus    string    `json:"current_balance_status"`
	CurrentBalanceRaw       string    `json:"current_balance_raw"`
	CurrentBalance          float64   `json:"current_balance"`
	CurrentTokenAccounts    []string  `json:"current_token_accounts"`
	MatchesTopHolder        bool      `json:"matches_top_holder"`
	TopHolderRank           int       `json:"top_holder_rank,omitempty"`
	TopHolderPercentage     float64   `json:"top_holder_percentage,omitempty"`
	Fate                    string    `json:"fate"`
	Limitations             []string  `json:"limitations"`
}

type ActorInitialRecipientReport struct {
	Mint                    string                  `json:"mint"`
	CreatorWallet           string                  `json:"creator_wallet"`
	CreationSignature       string                  `json:"creation_signature,omitempty"`
	Status                  string                  `json:"status"`
	DistributionScope       string                  `json:"distribution_scope"`
	HistoryComplete         bool                    `json:"history_complete"`
	SourceTokenAccounts     []string                `json:"source_token_accounts"`
	Recipients              []ActorInitialRecipient `json:"recipients"`
	SignaturesScanned       int                     `json:"signatures_scanned"`
	TransactionsParsed      int                     `json:"transactions_parsed"`
	RecipientBalanceQueries int                     `json:"recipient_balance_queries"`
	TopHolderStatus         string                  `json:"top_holder_status"`
	Limitations             []string                `json:"limitations"`
	GeneratedAt             time.Time               `json:"generated_at"`
}

type actorRecipientTransfer struct {
	Wallet                  string
	SourceTokenAccount      string
	DestinationTokenAccount string
	Amount                  float64
	RawAmount               string
	Decimals                int
	Signature               string
	Slot                    int64
	ObservedAt              time.Time
	Program                 string
}

type actorRecipientTopHolder struct {
	Rank       int
	Percentage float64
}

// InvestigateActorInitialRecipients follows only token accounts for the given
// mint. It never requests recipient-wide wallet signature history.
func InvestigateActorInitialRecipients(ctx context.Context, rpcURL, creator, mint, creationSignature string, options ActorInitialRecipientOptions) ActorInitialRecipientReport {
	creator = strings.TrimSpace(creator)
	mint = strings.TrimSpace(mint)
	creationSignature = strings.TrimSpace(creationSignature)
	result := ActorInitialRecipientReport{
		Mint: mint, CreatorWallet: creator, CreationSignature: creationSignature,
		Status: "not_investigated", DistributionScope: "not_investigated",
		SourceTokenAccounts: []string{}, Recipients: []ActorInitialRecipient{},
		TopHolderStatus: "not_investigated", Limitations: []string{}, GeneratedAt: time.Now().UTC(),
	}
	if strings.TrimSpace(rpcURL) == "" {
		result.Status = "rpc_unavailable"
		result.Limitations = append(result.Limitations, "Solana RPC yapılandırılmadığı için mint-spesifik recipient araştırması yapılmadı.")
		return result
	}
	if creator == "" || mint == "" {
		result.Status = "invalid_target"
		result.Limitations = append(result.Limitations, "Creator wallet ve token mint zorunludur.")
		return result
	}
	maxRecipients, pageSize, maxPages, maxTransactions := normalizeActorRecipientOptions(options)

	sourceAccounts := map[string]bool{}
	if creationSignature != "" {
		if tx, err := SolanaGetTransactionJSONParsed(ctx, rpcURL, creationSignature); err == nil {
			for _, address := range actorRecipientOwnedTokenAccounts(map[string]any(tx), creator, mint) {
				sourceAccounts[address] = true
			}
		} else {
			result.Limitations = append(result.Limitations, "Creation transaction token-account çözümlemesi yapılamadı: "+compactActorFundingError(err))
		}
	}
	if current, err := SolanaGetTokenAccountsByOwnerForMint(ctx, rpcURL, creator, mint); err == nil {
		for _, account := range current.Value {
			if strings.TrimSpace(account.Pubkey) != "" {
				sourceAccounts[strings.TrimSpace(account.Pubkey)] = true
			}
		}
	} else {
		result.Limitations = append(result.Limitations, "Creator'ın mevcut mint-spesifik token hesapları alınamadı: "+compactActorFundingError(err))
	}
	for address := range sourceAccounts {
		result.SourceTokenAccounts = append(result.SourceTokenAccounts, address)
	}
	sort.Strings(result.SourceTokenAccounts)
	if len(result.SourceTokenAccounts) == 0 {
		result.Status = "creator_token_accounts_not_observed"
		result.DistributionScope = "not_investigated"
		result.Limitations = append(result.Limitations, "Creation transaction veya mevcut owner query içinde creator'a ait mint-spesifik token hesabı gözlemlenmedi.")
		return result
	}

	signatureIndex := map[string]SolanaSignatureInfo{}
	complete := true
	for _, tokenAccount := range result.SourceTokenAccounts {
		before := ""
		accountComplete := false
		for page := 0; page < maxPages && ctx.Err() == nil; page++ {
			rows, err := SolanaGetSignaturesForAddressPage(ctx, rpcURL, tokenAccount, SolanaSignaturePageOptions{Limit: pageSize, Before: before})
			if err != nil {
				result.Limitations = append(result.Limitations, "Token-account imza geçmişi kısmi kaldı: "+compactActorFundingError(err))
				break
			}
			for _, row := range rows {
				if strings.TrimSpace(row.Signature) != "" {
					signatureIndex[row.Signature] = row
				}
			}
			if len(rows) < pageSize {
				accountComplete = true
				break
			}
			last := strings.TrimSpace(rows[len(rows)-1].Signature)
			if last == "" || last == before {
				result.Limitations = append(result.Limitations, "Token-account signature cursor ilerlemedi; geçmiş tamamlandı kabul edilmedi.")
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
		result.Limitations = append(result.Limitations, "ATA geçmişi sona ulaşmadığı için bulunan transferler 'initial' olarak değil, taranan penceredeki creator recipient'ları olarak adlandırılır.")
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
		tx, err := SolanaGetTransactionJSONParsed(ctx, rpcURL, signature.Signature)
		if err != nil {
			continue
		}
		result.TransactionsParsed++
		for _, transfer := range actorRecipientTransfersFromTransaction(map[string]any(tx), signature, creator, mint, sourceAccounts) {
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

	topHolders, holderStatus := actorRecipientTopHolders(ctx, rpcURL, mint)
	result.TopHolderStatus = holderStatus
	for index, transfer := range transfers {
		recipient := ActorInitialRecipient{
			Sequence:                index + 1,
			Wallet:                  transfer.Wallet,
			SourceTokenAccount:      transfer.SourceTokenAccount,
			DestinationTokenAccount: transfer.DestinationTokenAccount,
			Amount:                  transfer.Amount,
			RawAmount:               transfer.RawAmount,
			Decimals:                transfer.Decimals,
			Signature:               transfer.Signature,
			Slot:                    transfer.Slot,
			ObservedAt:              transfer.ObservedAt,
			Program:                 transfer.Program,
			VerificationStatus:      "verified",
			CurrentBalanceStatus:    "not_investigated",
			CurrentBalanceRaw:       "0",
			CurrentTokenAccounts:    []string{},
			Limitations:             []string{},
		}
		balance, err := SolanaGetTokenAccountsByOwnerForMint(ctx, rpcURL, transfer.Wallet, mint)
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
			if len(accounts) == 0 {
				recipient.CurrentBalanceStatus = "no_current_token_account"
				recipient.Fate = "exited_or_account_closed"
			} else if ui <= 0 {
				recipient.CurrentBalanceStatus = "zero_balance"
				recipient.Fate = "zero_balance"
			} else {
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

func ActorInitialRecipientEvidence(report ActorInitialRecipientReport, network string) []ActorDefenseEvidenceRecord {
	out := make([]ActorDefenseEvidenceRecord, 0, len(report.Recipients))
	relation := "creator_recipient_in_window"
	if report.HistoryComplete {
		relation = "initial_token_recipient"
	}
	for _, recipient := range report.Recipients {
		if recipient.VerificationStatus != "verified" || recipient.Wallet == "" || recipient.Signature == "" || recipient.Slot <= 0 || recipient.ObservedAt.IsZero() {
			continue
		}
		out = append(out, ActorDefenseEvidenceRecord{
			Network:            normalizeRadarNetwork(network),
			ActorWallet:        strings.TrimSpace(report.CreatorWallet),
			CounterpartKind:    "wallet",
			CounterpartID:      strings.TrimSpace(recipient.Wallet),
			Relation:           relation,
			VerificationStatus: "verified",
			EvidenceKey:        fmt.Sprintf("%s:%s:%d", recipient.Signature, relation, recipient.Sequence),
			Source:             "mint_specific_ata_history",
			Signature:          recipient.Signature,
			Slot:               recipient.Slot,
			ObservedAt:         recipient.ObservedAt,
			TokenMint:          report.Mint,
			TokenAmount:        recipient.Amount,
			Metadata: map[string]any{
				"actor_role":                "creator_deployer",
				"source_wallet":             report.CreatorWallet,
				"destination_wallet":        recipient.Wallet,
				"program":                   recipient.Program,
				"source_token_account":      recipient.SourceTokenAccount,
				"destination_token_account": recipient.DestinationTokenAccount,
				"raw_amount":                recipient.RawAmount,
				"decimals":                  recipient.Decimals,
				"recipient_sequence":        recipient.Sequence,
				"distribution_scope":        report.DistributionScope,
				"history_complete":          report.HistoryComplete,
				"current_balance_status":    recipient.CurrentBalanceStatus,
				"current_balance_raw":       recipient.CurrentBalanceRaw,
				"current_balance":           recipient.CurrentBalance,
				"matches_top_holder":        recipient.MatchesTopHolder,
				"top_holder_rank":           recipient.TopHolderRank,
				"top_holder_percentage":     recipient.TopHolderPercentage,
				"fate":                      recipient.Fate,
				"mint_specific_ata_only":    true,
				"persistent_actor_index":    true,
			},
		})
	}
	return out
}

func normalizeActorRecipientOptions(options ActorInitialRecipientOptions) (maxRecipients, pageSize, maxPages, maxTransactions int) {
	maxRecipients = options.MaxRecipients
	if maxRecipients <= 0 || maxRecipients > 20 {
		maxRecipients = 20
	}
	pageSize = options.SignaturePageSize
	if pageSize <= 0 || pageSize > 1000 {
		pageSize = 250
	}
	maxPages = options.MaxPagesPerTokenATA
	if maxPages <= 0 || maxPages > 20 {
		maxPages = 8
	}
	maxTransactions = options.MaxTransactionsParse
	if maxTransactions <= 0 || maxTransactions > 500 {
		maxTransactions = 160
	}
	return
}

func actorRecipientOwnedTokenAccounts(tx map[string]any, owner, mint string) []string {
	meta := actorRecipientMap(tx["meta"])
	message := actorRecipientMap(actorRecipientMap(tx["transaction"])["message"])
	keys := actorRecipientAccountKeys(message)
	seen := map[string]bool{}
	collect := func(raw any) {
		items, _ := raw.([]any)
		for _, item := range items {
			row := actorRecipientMap(item)
			if strings.TrimSpace(actorRecipientString(row["owner"])) != owner || strings.TrimSpace(actorRecipientString(row["mint"])) != mint {
				continue
			}
			index := actorRecipientInt(row["accountIndex"])
			if index >= 0 && index < len(keys) && keys[index] != "" {
				seen[keys[index]] = true
			}
		}
	}
	collect(meta["preTokenBalances"])
	collect(meta["postTokenBalances"])
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func actorRecipientTransfersFromTransaction(tx map[string]any, signature SolanaSignatureInfo, creator, mint string, sourceAccounts map[string]bool) []actorRecipientTransfer {
	meta := actorRecipientMap(tx["meta"])
	if meta["err"] != nil {
		return nil
	}
	message := actorRecipientMap(actorRecipientMap(tx["transaction"])["message"])
	keys, signers := actorRecipientAccountKeysAndSigners(message)
	if !signers[creator] {
		return nil
	}
	owners := actorRecipientTokenAccountOwners(meta, keys)
	observedAt := actorFundingTransactionTime(signature, tx)
	out := []actorRecipientTransfer{}
	for _, instruction := range actorRecipientInstructions(message, meta) {
		program := strings.TrimSpace(firstActorFundingString(actorRecipientString(instruction["programId"]), actorRecipientString(instruction["program"])))
		if !strings.Contains(strings.ToLower(program), "token") && !strings.EqualFold(program, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA") && !strings.EqualFold(program, "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb") {
			continue
		}
		parsed := actorRecipientMap(instruction["parsed"])
		kind := strings.ToLower(strings.TrimSpace(actorRecipientString(parsed["type"])))
		if kind != "transfer" && kind != "transferchecked" {
			continue
		}
		info := actorRecipientMap(parsed["info"])
		sourceATA := strings.TrimSpace(actorRecipientString(info["source"]))
		destinationATA := strings.TrimSpace(actorRecipientString(info["destination"]))
		authority := strings.TrimSpace(actorRecipientString(info["authority"]))
		if !sourceAccounts[sourceATA] || authority != creator || destinationATA == "" {
			continue
		}
		sourceOwner := owners[sourceATA]
		destinationOwner := owners[destinationATA]
		transferMint := firstActorFundingString(sourceOwner.Mint, destinationOwner.Mint, actorRecipientString(info["mint"]))
		if transferMint != mint || sourceOwner.Owner != creator || destinationOwner.Owner == "" || destinationOwner.Owner == creator {
			continue
		}
		amount, raw, decimals := actorRecipientTransferAmount(info)
		out = append(out, actorRecipientTransfer{
			Wallet:                  destinationOwner.Owner,
			SourceTokenAccount:      sourceATA,
			DestinationTokenAccount: destinationATA,
			Amount:                  amount,
			RawAmount:               raw,
			Decimals:                decimals,
			Signature:               signature.Signature,
			Slot:                    signature.Slot,
			ObservedAt:              observedAt,
			Program:                 program,
		})
	}
	return out
}

type actorRecipientTokenOwner struct{ Owner, Mint string }

func actorRecipientTokenAccountOwners(meta map[string]any, keys []string) map[string]actorRecipientTokenOwner {
	out := map[string]actorRecipientTokenOwner{}
	collect := func(raw any) {
		items, _ := raw.([]any)
		for _, item := range items {
			row := actorRecipientMap(item)
			index := actorRecipientInt(row["accountIndex"])
			if index < 0 || index >= len(keys) {
				continue
			}
			owner := strings.TrimSpace(actorRecipientString(row["owner"]))
			mint := strings.TrimSpace(actorRecipientString(row["mint"]))
			if owner != "" || mint != "" {
				out[keys[index]] = actorRecipientTokenOwner{Owner: owner, Mint: mint}
			}
		}
	}
	collect(meta["preTokenBalances"])
	collect(meta["postTokenBalances"])
	return out
}

func actorRecipientTopHolders(ctx context.Context, rpcURL, mint string) (map[string]actorRecipientTopHolder, string) {
	out := map[string]actorRecipientTopHolder{}
	supply, err := SolanaGetTokenSupply(ctx, rpcURL, mint)
	if err != nil {
		return out, "supply_unavailable"
	}
	largest, err := SolanaGetTokenLargestAccounts(ctx, rpcURL, mint)
	if err != nil {
		return out, "largest_accounts_unavailable"
	}
	total := solanaTokenAmountFloat(supply.Value)
	if total <= 0 {
		return out, "invalid_supply"
	}
	analysis := AnalyzeSolanaHolderRoles(ctx, rpcURL, total, largest.Value)
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

func actorRecipientTransferAmount(info map[string]any) (float64, string, int) {
	tokenAmount := actorRecipientMap(info["tokenAmount"])
	if len(tokenAmount) > 0 {
		raw := strings.TrimSpace(actorRecipientString(tokenAmount["amount"]))
		decimals := actorRecipientInt(tokenAmount["decimals"])
		ui := actorRecipientFloat(tokenAmount["uiAmount"])
		if ui == 0 {
			ui, _ = strconv.ParseFloat(strings.TrimSpace(actorRecipientString(tokenAmount["uiAmountString"])), 64)
		}
		return ui, raw, decimals
	}
	return 0, strings.TrimSpace(actorRecipientString(info["amount"])), 0
}

func actorRecipientInstructions(message, meta map[string]any) []map[string]any {
	out := []map[string]any{}
	appendRows := func(raw any) {
		items, _ := raw.([]any)
		for _, item := range items {
			row := actorRecipientMap(item)
			if len(row) > 0 {
				out = append(out, row)
			}
		}
	}
	appendRows(message["instructions"])
	inner, _ := meta["innerInstructions"].([]any)
	for _, item := range inner {
		appendRows(actorRecipientMap(item)["instructions"])
	}
	return out
}

func actorRecipientAccountKeys(message map[string]any) []string {
	keys, _ := actorRecipientAccountKeysAndSigners(message)
	return keys
}

func actorRecipientAccountKeysAndSigners(message map[string]any) ([]string, map[string]bool) {
	keys := []string{}
	signers := map[string]bool{}
	items, _ := message["accountKeys"].([]any)
	for _, item := range items {
		key := ""
		signer := false
		switch value := item.(type) {
		case string:
			key = strings.TrimSpace(value)
		case map[string]any:
			key = strings.TrimSpace(actorRecipientString(value["pubkey"]))
			signer = actorRecipientBool(value["signer"])
		}
		if key == "" {
			continue
		}
		keys = append(keys, key)
		if signer {
			signers[key] = true
		}
	}
	return keys, signers
}

func actorRecipientMap(value any) map[string]any {
	if result, ok := value.(map[string]any); ok {
		return result
	}
	return map[string]any{}
}
func actorRecipientString(value any) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}
func actorRecipientInt(value any) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		parsed, _ := strconv.Atoi(strings.TrimSpace(v))
		return parsed
	default:
		return -1
	}
}
func actorRecipientFloat(value any) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case string:
		parsed, _ := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return parsed
	default:
		return 0
	}
}
func actorRecipientBool(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		parsed, _ := strconv.ParseBool(strings.TrimSpace(v))
		return parsed
	default:
		return false
	}
}
