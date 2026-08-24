package services

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

const standardRPCCreatedMintProvider = "solana_standard_rpc_created_mint"

func heliusCreatedMintGTFAEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("KOSCHEI_HELIUS_CREATED_MINT_GTFA_ENABLED"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// FetchSolanaRPCCreatedMintDiscovery performs bounded created-mint discovery
// with standard getSignaturesForAddress + getTransaction calls. It deliberately
// reports bounded coverage when only a sample of the observed signature window
// is decoded; absence of a candidate in a bounded window is never a safety
// signal or proof that the actor never created a mint.
func FetchSolanaRPCCreatedMintDiscovery(ctx context.Context, rpcURL, wallet string) CreatedMintDiscovery {
	rpcURL = strings.TrimSpace(rpcURL)
	wallet = strings.TrimSpace(wallet)
	out := CreatedMintDiscovery{
		Status:      "not_configured",
		Provider:    standardRPCCreatedMintProvider,
		Wallet:      wallet,
		Candidates:  []ActorCreatedMintCandidate{},
		ObservedAt:  time.Now().UTC(),
		Limitations: []string{},
	}
	if wallet == "" {
		out.Status = "wallet_required"
		out.Limitations = append(out.Limitations, "Creator wallet is required for created-mint discovery.")
		return out
	}
	if rpcURL == "" {
		out.Limitations = append(out.Limitations, "Solana RPC is not configured; created-mint discovery was skipped.")
		return out
	}
	out.Configured = true

	maxPages := holderScanEnvInt("SOLANA_CREATED_MINT_MAX_PAGES", 2, 1, 8)
	pageLimit := holderScanEnvInt("SOLANA_CREATED_MINT_PAGE_LIMIT", 250, 25, 1000)
	transactionLimit := holderScanEnvInt("SOLANA_CREATED_MINT_TX_LIMIT", 40, 1, 200)

	signatures := make([]SolanaSignatureInfo, 0, maxPages*pageLimit)
	seen := map[string]bool{}
	before := ""
	historyExhausted := false
	collectionFailed := false

	for page := 0; page < maxPages && ctx.Err() == nil; page++ {
		rows, err := SolanaGetSignaturesForAddressPage(ctx, rpcURL, wallet, SolanaSignaturePageOptions{Limit: pageLimit, Before: before})
		if err != nil {
			collectionFailed = true
			if out.PagesFetched == 0 {
				out.Status = "collection_failed"
			} else {
				out.Status = "partial"
			}
			out.Limitations = append(out.Limitations, "Standard RPC signature history could not be collected: "+compactClusterError(err))
			break
		}
		out.PagesFetched++
		if len(rows) == 0 {
			historyExhausted = true
			before = ""
			break
		}
		for _, row := range rows {
			signature := strings.TrimSpace(row.Signature)
			if signature == "" || row.Err != nil || seen[signature] {
				continue
			}
			seen[signature] = true
			signatures = append(signatures, row)
		}
		last := strings.TrimSpace(rows[len(rows)-1].Signature)
		if len(rows) < pageLimit || last == "" || last == before {
			historyExhausted = true
			before = ""
			break
		}
		before = last
	}

	if ctx.Err() != nil {
		out.Status = "partial"
		out.Limitations = append(out.Limitations, "Standard RPC created-mint discovery stopped because the request context ended.")
	}
	if !historyExhausted && before != "" {
		out.NextCursor = before
	}

	selected := selectCreatedMintSignatureSample(signatures, transactionLimit)
	transactions, transactionFailures := fetchStandardCreatedMintTransactions(ctx, rpcURL, selected)
	out.TransactionsSeen = len(transactions)
	out.Candidates = ExtractActorCreatedMintCandidates(transactions, wallet, out.Provider)
	sort.SliceStable(out.Candidates, func(i, j int) bool {
		if out.Candidates[i].Slot != out.Candidates[j].Slot {
			return out.Candidates[i].Slot > out.Candidates[j].Slot
		}
		return out.Candidates[i].Mint < out.Candidates[j].Mint
	})

	out.Available = out.PagesFetched > 0
	sampled := len(selected) < len(signatures)
	bounded := !historyExhausted || sampled || transactionFailures > 0
	if len(signatures) > 0 {
		out.Limitations = append(out.Limitations, fmt.Sprintf(
			"Standard RPC observed %d successful wallet signatures across %d page(s) and decoded %d transaction(s); coverage is evidence-bounded.",
			len(signatures), out.PagesFetched, out.TransactionsSeen,
		))
	}
	if sampled {
		out.Limitations = append(out.Limitations, fmt.Sprintf(
			"Created-mint decoding sampled %d of %d observed successful signatures across the bounded window; unparsed signatures may contain additional mint creation events.",
			len(selected), len(signatures),
		))
	}
	if transactionFailures > 0 {
		out.Limitations = append(out.Limitations, fmt.Sprintf(
			"%d selected transaction(s) could not be decoded; missing transactions are not treated as clean evidence.",
			transactionFailures,
		))
	}
	if !historyExhausted && out.NextCursor != "" {
		out.Limitations = append(out.Limitations, fmt.Sprintf(
			"Created-mint signature discovery stopped after %d standard RPC page(s); the continuation cursor is preserved.",
			out.PagesFetched,
		))
	}

	if collectionFailed && out.PagesFetched == 0 {
		return out
	}
	if out.Status == "partial" {
		return out
	}
	switch {
	case bounded && len(out.Candidates) == 0:
		out.Status = "bounded_no_created_mints_observed"
	case bounded:
		out.Status = "bounded"
	case len(out.Candidates) == 0:
		out.Status = "complete_no_created_mints_observed"
	default:
		out.Status = "complete"
	}
	return out
}

func selectCreatedMintSignatureSample(signatures []SolanaSignatureInfo, limit int) []SolanaSignatureInfo {
	if limit <= 0 || len(signatures) <= limit {
		return append([]SolanaSignatureInfo{}, signatures...)
	}
	if limit == 1 {
		return []SolanaSignatureInfo{signatures[len(signatures)-1]}
	}
	out := make([]SolanaSignatureInfo, 0, limit)
	seen := map[int]bool{}
	for i := 0; i < limit; i++ {
		index := i * (len(signatures) - 1) / (limit - 1)
		if seen[index] {
			continue
		}
		seen[index] = true
		out = append(out, signatures[index])
	}
	return out
}

func fetchStandardCreatedMintTransactions(ctx context.Context, rpcURL string, signatures []SolanaSignatureInfo) ([]map[string]any, int) {
	if len(signatures) == 0 {
		return []map[string]any{}, 0
	}
	requested := make([]string, 0, len(signatures))
	for _, row := range signatures {
		if signature := strings.TrimSpace(row.Signature); signature != "" {
			requested = append(requested, signature)
		}
	}

	results, _ := SolanaGetTransactionsJSONParsedBatch(ctx, rpcURL, requested)
	if results == nil {
		results = map[string]SolanaTransactionResult{}
	}
	failures := 0
	for _, signature := range requested {
		if _, ok := results[signature]; ok {
			continue
		}
		if ctx.Err() != nil {
			failures++
			continue
		}
		transaction, err := SolanaGetTransactionJSONParsed(ctx, rpcURL, signature)
		if err != nil || transaction == nil {
			failures++
			continue
		}
		results[signature] = transaction
	}

	transactions := make([]map[string]any, 0, len(results))
	for _, signature := range requested {
		transaction, ok := results[signature]
		if !ok || transaction == nil {
			continue
		}
		transactions = append(transactions, map[string]any(transaction))
	}
	return transactions, failures
}
