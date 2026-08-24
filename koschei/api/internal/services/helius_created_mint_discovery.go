package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// FetchHeliusCreatedMintDiscovery is retained as the compatibility entry point
// used by the actor pipeline. Standard Solana RPC is the default so Helius Free
// and non-Helius RPC providers can collect bounded created-mint evidence.
// getTransactionsForAddress is a paid-plan optimization and only runs after
// explicit KOSCHEI_HELIUS_CREATED_MINT_GTFA_ENABLED opt-in.
func FetchHeliusCreatedMintDiscovery(ctx context.Context, rpcURL, wallet string) CreatedMintDiscovery {
	if !heliusCreatedMintGTFAEnabled() {
		return FetchSolanaRPCCreatedMintDiscovery(ctx, rpcURL, wallet)
	}
	helius := fetchHeliusCreatedMintDiscoveryGTFA(ctx, rpcURL, wallet)
	if helius.Available {
		return helius
	}
	fallback := FetchSolanaRPCCreatedMintDiscovery(ctx, rpcURL, wallet)
	if len(helius.Limitations) > 0 {
		fallback.Limitations = append(fallback.Limitations, "Helius getTransactionsForAddress was unavailable; standard RPC fallback was used.")
		fallback.Limitations = append(fallback.Limitations, helius.Limitations...)
	}
	return fallback
}

// Helius paid created-mint discovery uses getTransactionsForAddress with full
// jsonParsed transactions. Candidate extraction still requires the actor signer
// and exact Pump/SPL mint instruction instead of provider labels or fee-payer
// heuristics. The full-transaction request is capped at 100 records per current
// Helius method limits.
type heliusTransactionsForAddressResponse struct {
	Result struct {
		Data            []map[string]any `json:"data"`
		PaginationToken string           `json:"paginationToken"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func fetchHeliusCreatedMintDiscoveryGTFA(ctx context.Context, rpcURL, wallet string) CreatedMintDiscovery {
	wallet = strings.TrimSpace(wallet)
	out := CreatedMintDiscovery{
		Status: "not_configured", Provider: "helius_get_transactions_for_address",
		Wallet: wallet, Candidates: []ActorCreatedMintCandidate{},
		ObservedAt: time.Now().UTC(), Limitations: []string{},
	}
	if wallet == "" {
		out.Status = "wallet_required"
		out.Limitations = append(out.Limitations, "Creator wallet is required for created-mint discovery.")
		return out
	}

	apiKey := heliusEnhancedAPIKey(rpcURL)
	if apiKey == "" {
		out.Limitations = append(out.Limitations, "No Helius API key resolved; paid getTransactionsForAddress discovery was skipped.")
		return out
	}
	out.Configured = true

	endpoint := heliusRPCProviderURL(rpcURL, apiKey)
	maxPages := holderScanEnvInt("HELIUS_CREATED_MINT_MAX_PAGES", 6, 1, 20)
	pageLimit := holderScanEnvInt("HELIUS_CREATED_MINT_PAGE_LIMIT", 100, 10, 100)
	pageDelay := time.Duration(holderScanEnvInt("HELIUS_CREATED_MINT_PAGE_DELAY_MS", 150, 0, 2000)) * time.Millisecond

	paginationToken := ""
	candidateIndex := map[string]ActorCreatedMintCandidate{}
	for page := 0; page < maxPages && ctx.Err() == nil; page++ {
		if page > 0 && pageDelay > 0 {
			select {
			case <-ctx.Done():
				out.Limitations = append(out.Limitations, "Creator discovery stopped: context deadline.")
				return out
			case <-time.After(pageDelay):
			}
		}
		batch, next, err := fetchHeliusCreatedMintPage(ctx, endpoint, wallet, paginationToken, pageLimit)
		if err != nil {
			if out.PagesFetched == 0 {
				out.Status = "collection_failed"
			} else {
				out.Status = "partial"
			}
			out.Limitations = append(out.Limitations, "Helius creator history could not be collected: "+compactClusterError(err))
			break
		}
		out.PagesFetched++
		out.TransactionsSeen += len(batch)
		for _, candidate := range ExtractActorCreatedMintCandidates(batch, wallet, out.Provider) {
			key := candidate.Mint + "|" + candidate.Signature
			if existing, ok := candidateIndex[key]; !ok || candidate.Slot > existing.Slot {
				candidateIndex[key] = candidate
			}
		}
		if strings.TrimSpace(next) == "" || next == paginationToken {
			paginationToken = ""
			break
		}
		paginationToken = next
	}

	out.NextCursor = paginationToken
	for _, candidate := range candidateIndex {
		out.Candidates = append(out.Candidates, candidate)
	}
	sort.SliceStable(out.Candidates, func(i, j int) bool {
		if out.Candidates[i].Slot != out.Candidates[j].Slot {
			return out.Candidates[i].Slot > out.Candidates[j].Slot
		}
		return out.Candidates[i].Mint < out.Candidates[j].Mint
	})
	out.Available = out.PagesFetched > 0
	if out.Status == "not_configured" {
		switch {
		case out.PagesFetched == 0:
			out.Status = "collection_failed"
		case paginationToken != "":
			out.Status = "bounded"
		case len(out.Candidates) == 0:
			out.Status = "complete_no_created_mints_observed"
		default:
			out.Status = "complete"
		}
	}
	if paginationToken != "" {
		out.Limitations = append(out.Limitations, fmt.Sprintf("Created-mint discovery stopped after %d Helius pages; pagination token is preserved.", out.PagesFetched))
	}
	return out
}

func fetchHeliusCreatedMintPage(ctx context.Context, endpoint, wallet, paginationToken string, limit int) ([]map[string]any, string, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	options := map[string]any{
		"transactionDetails":             "full",
		"sortOrder":                      "desc",
		"limit":                          limit,
		"encoding":                       "jsonParsed",
		"maxSupportedTransactionVersion": 0,
		"filters": map[string]any{
			"status": "succeeded",
		},
	}
	if strings.TrimSpace(paginationToken) != "" {
		options["paginationToken"] = strings.TrimSpace(paginationToken)
	}
	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      "koschei-created-mint-discovery",
		"method":  "getTransactionsForAddress",
		"params":  []any{strings.TrimSpace(wallet), options},
	})
	if err != nil {
		return nil, "", err
	}
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return nil, "", err
	}
	if res.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("helius RPC status %d: %s", res.StatusCode, compactClusterError(fmt.Errorf("%s", strings.TrimSpace(string(body)))))
	}
	var response heliusTransactionsForAddressResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, "", fmt.Errorf("helius getTransactionsForAddress decode: %w", err)
	}
	if response.Error != nil {
		return nil, "", fmt.Errorf("helius RPC error %d: %s", response.Error.Code, strings.TrimSpace(response.Error.Message))
	}
	if response.Result.Data == nil {
		response.Result.Data = []map[string]any{}
	}
	return response.Result.Data, strings.TrimSpace(response.Result.PaginationToken), nil
}

func heliusRPCProviderURL(rpcURL, apiKey string) string {
	parsed, err := url.Parse(strings.TrimSpace(rpcURL))
	if err == nil && parsed != nil && strings.Contains(strings.ToLower(parsed.Hostname()), "helius") {
		query := parsed.Query()
		query.Set("api-key", strings.TrimSpace(apiKey))
		parsed.RawQuery = query.Encode()
		return parsed.String()
	}
	query := url.Values{}
	query.Set("api-key", strings.TrimSpace(apiKey))
	return "https://mainnet.helius-rpc.com/?" + query.Encode()
}
