package services

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

const boundedCreatedMintRPCProvider = "solana_rpc_bounded_created_mint"

// heliusCreatedMintArchivalEnabled gates Helius getTransactionsForAddress.
// The archival method is intentionally opt-in so free-plan/default scans do
// not depend on a paid/high-credit provider feature merely because a Helius
// API key is configured.
func heliusCreatedMintArchivalEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("HELIUS_CREATED_MINT_ARCHIVAL_ENABLED"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// FetchBoundedRPCCreatedMintDiscovery uses provider-portable Solana RPC as the
// default created-mint discovery path. It deliberately samples a bounded recent
// signature window and labels incomplete coverage as bounded instead of
// pretending that a whole-wallet history search was completed.
func FetchBoundedRPCCreatedMintDiscovery(ctx context.Context, rpcURL, wallet string) CreatedMintDiscovery {
	wallet = strings.TrimSpace(wallet)
	out := CreatedMintDiscovery{
		Status: "not_configured", Provider: boundedCreatedMintRPCProvider,
		Wallet: wallet, Candidates: []ActorCreatedMintCandidate{},
		ObservedAt: time.Now().UTC(), Limitations: []string{},
	}
	if wallet == "" {
		out.Status = "wallet_required"
		out.Limitations = append(out.Limitations, "Creator wallet is required for created-mint discovery.")
		return out
	}

	endpoint := strings.TrimSpace(rpcURL)
	if endpoint == "" {
		if apiKey := heliusEnhancedAPIKey(""); apiKey != "" {
			endpoint = heliusRPCProviderURL("", apiKey)
		}
	}
	if endpoint == "" {
		out.Limitations = append(out.Limitations, "No Solana RPC URL or Helius provider key resolved; bounded created-mint discovery was skipped.")
		return out
	}
	out.Configured = true

	signatureLimit := holderScanEnvInt("CREATED_MINT_RPC_SIGNATURE_LIMIT", 100, 10, 500)
	transactionLimit := holderScanEnvInt("CREATED_MINT_RPC_TRANSACTION_LIMIT", 40, 1, 100)
	signatures, err := SolanaGetSignaturesForAddressPage(ctx, endpoint, wallet, SolanaSignaturePageOptions{Limit: signatureLimit})
	if err != nil {
		out.Status = "collection_failed"
		out.Limitations = append(out.Limitations, "Bounded creator signature history could not be collected: "+compactClusterError(err))
		return out
	}
	out.PagesFetched = 1
	out.Available = true

	successful := make([]SolanaSignatureInfo, 0, len(signatures))
	for _, row := range signatures {
		if strings.TrimSpace(row.Signature) == "" || row.Err != nil {
			continue
		}
		successful = append(successful, row)
	}
	selected := selectCreatedMintRPCSignatures(successful, transactionLimit)
	if len(signatures) >= signatureLimit && len(signatures) > 0 {
		out.NextCursor = strings.TrimSpace(signatures[len(signatures)-1].Signature)
	}
	if len(selected) == 0 {
		if len(signatures) < signatureLimit {
			out.Status = "complete_no_successful_activity_observed"
		} else {
			out.Status = "bounded"
			out.Limitations = append(out.Limitations, fmt.Sprintf("Created-mint discovery inspected a bounded %d-signature window; older history remains outside this run.", len(signatures)))
		}
		return out
	}

	transactions, detailErr := fetchCreatedMintRPCTransactions(ctx, endpoint, selected)
	out.TransactionsSeen = len(transactions)
	rows := make([]map[string]any, 0, len(transactions))
	for _, signature := range selected {
		if tx, ok := transactions[signature]; ok && tx != nil {
			rows = append(rows, map[string]any(tx))
		}
	}
	out.Candidates = ExtractActorCreatedMintCandidates(rows, wallet, out.Provider)

	historyExhausted := len(signatures) < signatureLimit
	allSuccessfulTransactionsInspected := len(selected) == len(successful)
	allSelectedDetailsAvailable := len(transactions) == len(selected)
	if historyExhausted && allSuccessfulTransactionsInspected && allSelectedDetailsAvailable {
		if len(out.Candidates) == 0 {
			out.Status = "complete_no_created_mints_observed"
		} else {
			out.Status = "complete"
		}
	} else {
		out.Status = "bounded"
		out.Limitations = append(out.Limitations, fmt.Sprintf("Created-mint discovery used %d transaction details selected from %d successful signatures in a %d-signature bounded window; uninspected history is not treated as clean evidence.", len(transactions), len(successful), len(signatures)))
	}
	if detailErr != nil {
		out.Limitations = append(out.Limitations, "Some bounded creator transaction details were unavailable: "+compactClusterError(detailErr))
	}
	return out
}

func selectCreatedMintRPCSignatures(rows []SolanaSignatureInfo, limit int) []string {
	clean := make([]string, 0, len(rows))
	seen := map[string]bool{}
	for _, row := range rows {
		signature := strings.TrimSpace(row.Signature)
		if signature == "" || row.Err != nil || seen[signature] {
			continue
		}
		seen[signature] = true
		clean = append(clean, signature)
	}
	if limit <= 0 || len(clean) <= limit {
		return clean
	}
	if limit == 1 {
		return clean[:1]
	}
	out := make([]string, 0, limit)
	used := map[int]bool{}
	for i := 0; i < limit; i++ {
		index := i * (len(clean) - 1) / (limit - 1)
		if used[index] {
			continue
		}
		used[index] = true
		out = append(out, clean[index])
	}
	return out
}

func fetchCreatedMintRPCTransactions(ctx context.Context, rpcURL string, signatures []string) (map[string]SolanaTransactionResult, error) {
	out := map[string]SolanaTransactionResult{}
	if len(signatures) == 0 {
		return out, nil
	}
	batch, batchErr := SolanaGetTransactionsJSONParsedBatch(ctx, rpcURL, signatures)
	mergeSolanaTransactionResults(out, batch)
	if batchErr == nil && len(out) == len(signatures) {
		return out, nil
	}

	var lastErr error
	if batchErr != nil {
		lastErr = batchErr
	}
	for _, signature := range signatures {
		if _, ok := out[signature]; ok {
			continue
		}
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		tx, err := SolanaGetTransactionJSONParsed(ctx, rpcURL, signature)
		if err != nil {
			lastErr = err
			continue
		}
		if tx != nil {
			out[signature] = tx
		}
	}
	return out, lastErr
}
