package services

// Helius Enhanced Transactions API collector for holder cluster analysis.
//
// One GET to /v0/addresses/{wallet}/transactions returns up to 100 parsed
// transactions. The legacy path spends 1 RPC call for signatures plus 1 RPC
// call per transaction; this path spends 1 HTTP call per 100 transactions.
//
// Design rules honored:
//   - Falls back to the legacy tiered path when no Helius key is resolvable
//     or the API call fails. Nothing breaks if Helius is removed.
//   - Never fabricates evidence: statuses and evidence wording mirror the
//     bounded-observation language of the tiered path.
//   - Budget accounting still goes through holderScanRPCBudget so the
//     existing degradation semantics stay intact.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	heliusEnhancedBaseURL  = "https://api.helius.xyz/v0/addresses"
	heliusEnhancedPageSize = 100
	heliusEnhancedMaxPages = 3
)

type heliusTokenTransfer struct {
	FromTokenAccount string  `json:"fromTokenAccount"`
	ToTokenAccount   string  `json:"toTokenAccount"`
	FromUserAccount  string  `json:"fromUserAccount"`
	ToUserAccount    string  `json:"toUserAccount"`
	TokenAmount      float64 `json:"tokenAmount"`
	Mint             string  `json:"mint"`
	TokenStandard    string  `json:"tokenStandard"`
	Decimals         *int    `json:"decimals"`
}

type heliusRawTokenAmount struct {
	TokenAmount string `json:"tokenAmount"`
	Decimals    *int   `json:"decimals"`
}

type heliusTokenBalanceChange struct {
	UserAccount    string               `json:"userAccount"`
	TokenAccount   string               `json:"tokenAccount"`
	Mint           string               `json:"mint"`
	RawTokenAmount heliusRawTokenAmount `json:"rawTokenAmount"`
}

type heliusAccountData struct {
	Account             string                     `json:"account"`
	TokenBalanceChanges []heliusTokenBalanceChange `json:"tokenBalanceChanges"`
}

type heliusNativeTransfer struct {
	FromUserAccount string `json:"fromUserAccount"`
	ToUserAccount   string `json:"toUserAccount"`
	Amount          int64  `json:"amount"` // lamports
}

type heliusInstruction struct {
	ProgramID string `json:"programId"`
}

type heliusEnhancedTransaction struct {
	Signature        string                 `json:"signature"`
	Slot             int64                  `json:"slot"`
	Timestamp        int64                  `json:"timestamp"`
	TransactionError any                    `json:"transactionError"`
	TokenTransfers   []heliusTokenTransfer  `json:"tokenTransfers"`
	NativeTransfers  []heliusNativeTransfer `json:"nativeTransfers"`
	AccountData      []heliusAccountData    `json:"accountData"`
	Instructions     []heliusInstruction    `json:"instructions"`
}

// heliusEnhancedAPIKey resolves the Helius API key. Resolution order:
// explicit HELIUS_API_KEY env, then the api-key query parameter of the
// configured Solana RPC URL when that URL points at a Helius host.
func heliusEnhancedAPIKey(rpcURL string) string {
	if key := strings.TrimSpace(os.Getenv("HELIUS_API_KEY")); key != "" {
		return key
	}
	parsed, err := url.Parse(strings.TrimSpace(rpcURL))
	if err != nil || parsed == nil {
		return ""
	}
	if !strings.Contains(strings.ToLower(parsed.Hostname()), "helius") {
		return ""
	}
	return strings.TrimSpace(parsed.Query().Get("api-key"))
}

func fetchHeliusEnhancedTransactionsPage(ctx context.Context, apiKey, address, before string, limit int) ([]heliusEnhancedTransaction, error) {
	if limit <= 0 || limit > heliusEnhancedPageSize {
		limit = heliusEnhancedPageSize
	}
	endpoint := fmt.Sprintf("%s/%s/transactions", heliusEnhancedBaseURL, url.PathEscape(strings.TrimSpace(address)))
	query := url.Values{}
	query.Set("api-key", apiKey)
	query.Set("limit", fmt.Sprintf("%d", limit))
	if strings.TrimSpace(before) != "" {
		query.Set("before", strings.TrimSpace(before))
	}
	reqCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint+"?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("helius enhanced api status %d: %s", res.StatusCode, compactClusterError(fmt.Errorf("%s", strings.TrimSpace(string(body)))))
	}
	var out []heliusEnhancedTransaction
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("helius enhanced api decode: %w", err)
	}
	return out, nil
}

func holderClusterObservationFromHeliusTransfer(transfer heliusTokenTransfer, tx heliusEnhancedTransaction, sourceWallet, mint string, holderWallets map[string]bool, programIDs []string, assetMetadata heliusAssetMetadata) (HolderClusterFlowObservation, bool) {
	if !strings.EqualFold(strings.TrimSpace(transfer.Mint), strings.TrimSpace(mint)) {
		return HolderClusterFlowObservation{}, false
	}
	if !strings.EqualFold(strings.TrimSpace(transfer.FromUserAccount), strings.TrimSpace(sourceWallet)) || transfer.TokenAmount <= holderClusterFlowEpsilon {
		return HolderClusterFlowObservation{}, false
	}

	destination := strings.TrimSpace(transfer.ToUserAccount)
	kind := "external_token_recipient"
	switch {
	case destination != "" && holderWallets[destination]:
		kind = "holder_to_holder"
	case destination != "":
		// Keep the external recipient owner.
	case strings.TrimSpace(transfer.ToTokenAccount) != "":
		destination = strings.TrimSpace(transfer.ToTokenAccount)
		kind = "token_account_recipient_unresolved"
	case len(programIDs) > 0:
		destination = programIDs[0]
		kind = "dex_program_exit_context"
	default:
		return HolderClusterFlowObservation{}, false
	}

	observation := holderClusterHeliusTransferObservation(transfer, tx, assetMetadata)
	observation.SourceWallet = strings.TrimSpace(sourceWallet)
	observation.Destination = destination
	observation.Direction = "outbound"
	observation.Kind = kind
	observation.ProgramIDs = append([]string{}, programIDs...)
	observation.Evidence = []string{
		"Target-token transfer out of the holder wallet was parsed from the Helius Enhanced Transactions API; this is route context, not proof of a sale or common ownership.",
	}
	holderClusterAppendHeliusMetadataEvidence(&observation)
	return observation, true
}

func holderClusterInboundObservationFromHeliusTransfer(transfer heliusTokenTransfer, tx heliusEnhancedTransaction, destinationWallet, mint string, holderWallets map[string]bool, programIDs []string, assetMetadata heliusAssetMetadata) (HolderClusterFlowObservation, bool) {
	if !strings.EqualFold(strings.TrimSpace(transfer.Mint), strings.TrimSpace(mint)) {
		return HolderClusterFlowObservation{}, false
	}
	if !strings.EqualFold(strings.TrimSpace(transfer.ToUserAccount), strings.TrimSpace(destinationWallet)) || transfer.TokenAmount <= holderClusterFlowEpsilon {
		return HolderClusterFlowObservation{}, false
	}
	source := strings.TrimSpace(transfer.FromUserAccount)
	if source == "" || strings.EqualFold(source, destinationWallet) {
		return HolderClusterFlowObservation{}, false
	}
	kind := "inbound_token_sender_context"
	if holderWallets[source] {
		kind = "holder_to_holder_inbound_context"
	}
	observation := holderClusterHeliusTransferObservation(transfer, tx, assetMetadata)
	observation.SourceWallet = source
	observation.Destination = strings.TrimSpace(destinationWallet)
	observation.Direction = "inbound"
	observation.Kind = kind
	observation.ProgramIDs = append([]string{}, programIDs...)
	observation.Evidence = []string{
		"Target-token transfer into the holder wallet was parsed from the Helius Enhanced Transactions API.",
		"Inbound context is preserved for entity direction classification and is excluded from common-exit and circular-flow scoring.",
	}
	holderClusterAppendHeliusMetadataEvidence(&observation)
	return observation, true
}

func holderClusterHeliusTransferObservation(transfer heliusTokenTransfer, tx heliusEnhancedTransaction, assetMetadata heliusAssetMetadata) HolderClusterFlowObservation {
	tokenStandard := strings.TrimSpace(transfer.TokenStandard)
	if tokenStandard == "" {
		tokenStandard = strings.TrimSpace(assetMetadata.TokenStandard)
	}
	decimals := heliusTransferDecimals(tx, transfer)
	if decimals == nil {
		decimals = firstHolderClusterDecimals(assetMetadata.Decimals)
	}
	return HolderClusterFlowObservation{
		Mint:                    strings.TrimSpace(transfer.Mint),
		SourceTokenAccount:      strings.TrimSpace(transfer.FromTokenAccount),
		DestinationTokenAccount: strings.TrimSpace(transfer.ToTokenAccount),
		TokenStandard:           tokenStandard,
		Decimals:                decimals,
		Amount:                  holderClusterRound(transfer.TokenAmount, 9),
		Slot:                    tx.Slot,
		Signature:               strings.TrimSpace(tx.Signature),
	}
}

func holderClusterAppendHeliusMetadataEvidence(observation *HolderClusterFlowObservation) {
	if observation == nil {
		return
	}
	if observation.SourceTokenAccount != "" || observation.DestinationTokenAccount != "" {
		observation.Evidence = append(observation.Evidence, "Helius token-account endpoints were preserved alongside the resolved user-account endpoints.")
	}
	if observation.TokenStandard != "" || observation.Decimals != nil {
		observation.Evidence = append(observation.Evidence, "Helius token metadata was preserved for amount interpretation and asset-standard filtering.")
	}
}

// analyzeHolderClusterWalletEnhanced is the Enhanced-API twin of
// analyzeHolderClusterWalletTiered. The second return value reports whether
// the enhanced path produced a usable row; on false the caller must run the
// legacy tiered path instead.
func analyzeHolderClusterWalletEnhanced(ctx context.Context, rpcURL, mint string, account HolderRoleAccount, launchBlockTime int64, holderWallets map[string]bool, plan holderScanPlan, budget *holderScanRPCBudget) (HolderClusterWallet, bool) {
	apiKey := heliusEnhancedAPIKey(rpcURL)
	if apiKey == "" {
		return HolderClusterWallet{}, false
	}

	percentage := account.CirculatingPercentage
	if percentage <= 0 {
		percentage = account.RawPercentage
	}
	row := HolderClusterWallet{
		Rank: account.Rank, Wallet: account.OwnerWallet, HolderPercentage: holderClusterRound(percentage, 4),
		Status: "signature_history_unavailable", Tier: plan.Tier, Collector: "helius_enhanced", BudgetDegraded: plan.BudgetDegraded,
		FlowObservations: []HolderClusterFlowObservation{}, Evidence: []string{},
	}

	requested := plan.SignatureLimit
	if requested <= 0 {
		requested = heliusEnhancedPageSize
	}
	assetMetadata := resolveHeliusAssetMetadata(ctx, apiKey, mint, budget)

	transactions := []heliusEnhancedTransaction{}
	before := ""
	for page := 0; page < heliusEnhancedMaxPages && len(transactions) < requested; page++ {
		if !budget.Reserve(1) {
			row.BudgetDegraded = true
			row.Evidence = append(row.Evidence, "RPC budget reached during enhanced history collection; partial evidence is preserved.")
			break
		}
		remaining := requested - len(transactions)
		batch, err := fetchHeliusEnhancedTransactionsPage(ctx, apiKey, account.OwnerWallet, before, remaining)
		if err != nil {
			if len(transactions) == 0 {
				// Total failure on the first page: let the legacy path try.
				return HolderClusterWallet{}, false
			}
			row.Evidence = append(row.Evidence, "Enhanced history pagination stopped early: "+compactClusterError(err))
			break
		}
		transactions = append(transactions, batch...)
		if len(batch) < heliusEnhancedPageSize {
			break // wallet history exhausted
		}
		before = batch[len(batch)-1].Signature
	}

	row.SignaturesFetched = len(transactions)
	row.SignaturesObserved = len(transactions)
	row.WindowExhausted = len(transactions) < requested
	row.HistoryExhausted = row.WindowExhausted
	if len(transactions) == 0 {
		row.Status = "no_observed_signatures"
		row.Evidence = append(row.Evidence, "No transactions were returned in the enhanced holder history window; this is not a safety signal.")
		return row, true
	}

	var oldestTime, newestTime, oldestSlot int64
	for _, tx := range transactions {
		if tx.Timestamp <= 0 {
			continue
		}
		if newestTime == 0 || tx.Timestamp > newestTime {
			newestTime = tx.Timestamp
		}
		if oldestTime == 0 || tx.Timestamp < oldestTime {
			oldestTime = tx.Timestamp
			oldestSlot = tx.Slot
		}
	}
	row.OldestObservedSlot = oldestSlot
	row.OldestObservedAt = holderClusterUnixTime(oldestTime)
	row.NewestObservedAt = holderClusterUnixTime(newestTime)
	if row.WindowExhausted && launchBlockTime > 0 && oldestTime > 0 {
		delta := oldestTime - launchBlockTime
		row.FreshNearLaunch = delta >= -86400 && delta <= 86400
	}

	selectedTransactions := holderClusterEnhancedTransactionsForLimit(transactions, launchBlockTime, plan.TransactionLimit)
	var earliestFundingTimestamp int64
	for _, tx := range selectedTransactions {
		if tx.TransactionError != nil || strings.TrimSpace(tx.Signature) == "" {
			continue
		}
		row.ParsedTransactions++
		row.TxsParsed = row.ParsedTransactions

		programIDs := []string{}
		for _, instruction := range tx.Instructions {
			if id := strings.TrimSpace(instruction.ProgramID); id != "" {
				programIDs = append(programIDs, id)
			}
		}

		for _, transfer := range tx.TokenTransfers {
			if observation, ok := holderClusterObservationFromHeliusTransfer(transfer, tx, account.OwnerWallet, mint, holderWallets, programIDs, assetMetadata); ok {
				row.FlowObservations = append(row.FlowObservations, observation)
			}
			if observation, ok := holderClusterInboundObservationFromHeliusTransfer(transfer, tx, account.OwnerWallet, mint, holderWallets, programIDs, assetMetadata); ok {
				row.FlowObservations = append(row.FlowObservations, observation)
			}
		}

		// Preserve the earliest native inflow found inside the examined window.
		for _, native := range tx.NativeTransfers {
			if !strings.EqualFold(native.ToUserAccount, account.OwnerWallet) || native.Amount <= 0 {
				continue
			}
			source := strings.TrimSpace(native.FromUserAccount)
			if source == "" || strings.EqualFold(source, account.OwnerWallet) {
				continue
			}
			if row.FundingSource == "" || (tx.Timestamp > 0 && (earliestFundingTimestamp == 0 || tx.Timestamp < earliestFundingTimestamp)) {
				row.FundingSource = source
				row.FundingAmountSOL = holderClusterRound(float64(native.Amount)/1e9, 9)
				row.FundingObservedAt = holderClusterUnixTime(tx.Timestamp)
				earliestFundingTimestamp = tx.Timestamp
			}
		}

		// Acquisition: earliest slot where the owner received the target mint.
		for _, transfer := range tx.TokenTransfers {
			if !strings.EqualFold(strings.TrimSpace(transfer.Mint), strings.TrimSpace(mint)) {
				continue
			}
			if !strings.EqualFold(transfer.ToUserAccount, account.OwnerWallet) || transfer.TokenAmount <= holderClusterFlowEpsilon {
				continue
			}
			if row.AcquisitionSlot == 0 || (tx.Slot > 0 && tx.Slot < row.AcquisitionSlot) {
				row.AcquisitionSlot = tx.Slot
				row.AcquisitionObservedAt = holderClusterUnixTime(tx.Timestamp)
			}
		}
	}

	row.FlowObservations = enrichHolderClusterFlowObservations(ctx, rpcURL, holderWallets, row.FlowObservations, budget)
	if row.ParsedTransactions > 0 {
		row.Status = "verified_bounded_observation"
	} else {
		row.Status = "signature_only_observation"
	}
	row.Evidence = append(row.Evidence, fmt.Sprintf("%s tier used the Helius Enhanced Transactions collector: %d history entries fetched, %d transactions parsed (limit %d); window_exhausted=%t.", plan.Tier, row.SignaturesFetched, row.TxsParsed, plan.TransactionLimit, row.WindowExhausted))
	if row.FreshNearLaunch {
		row.Evidence = append(row.Evidence, "Oldest observed wallet activity falls within 24 hours of the bounded token launch estimate.")
	}
	return row, true
}

func holderClusterEnhancedTransactionsForLimit(transactions []heliusEnhancedTransaction, launchBlockTime int64, limit int) []heliusEnhancedTransaction {
	if limit <= 0 || len(transactions) <= limit {
		return append([]heliusEnhancedTransaction{}, transactions...)
	}
	indexes := []int{}
	seen := map[int]bool{}
	appendIndex := func(index int) {
		if len(indexes) >= limit || index < 0 || index >= len(transactions) || seen[index] {
			return
		}
		seen[index] = true
		indexes = append(indexes, index)
	}
	appendIndex(0)
	appendIndex(len(transactions) - 1)
	if launchBlockTime > 0 {
		closest, best := -1, int64(1<<62)
		for index, tx := range transactions {
			if tx.Timestamp <= 0 {
				continue
			}
			delta := tx.Timestamp - launchBlockTime
			if delta < 0 {
				delta = -delta
			}
			if delta < best {
				best, closest = delta, index
			}
		}
		appendIndex(closest)
	}
	for index := 1; len(indexes) < limit && index < len(transactions)-1; index++ {
		appendIndex(index)
	}
	out := make([]heliusEnhancedTransaction, 0, len(indexes))
	for _, index := range indexes {
		out = append(out, transactions[index])
	}
	return out
}
