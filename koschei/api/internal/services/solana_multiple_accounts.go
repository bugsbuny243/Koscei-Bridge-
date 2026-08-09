package services

import (
	"context"
	"fmt"
	"strings"
)

// SolanaMultipleAccountInfoResult is the context-bearing response returned by
// getMultipleAccounts. Preserving the slot is required by Transaction Guard's
// state-witness contract; callers that only need Value remain source-compatible.
type SolanaMultipleAccountInfoResult struct {
	Context struct {
		Slot int64 `json:"slot"`
	} `json:"context"`
	Value []*SolanaAccountInfo `json:"value"`
}

func SolanaGetMultipleAccountsJSONParsed(ctx context.Context, rpcURL string, addresses []string) (SolanaMultipleAccountInfoResult, error) {
	rpcURL = strings.TrimSpace(rpcURL)
	if rpcURL == "" {
		return SolanaMultipleAccountInfoResult{}, fmt.Errorf("solana rpc url is empty")
	}
	clean := make([]string, 0, len(addresses))
	seen := map[string]bool{}
	for _, address := range addresses {
		address = strings.TrimSpace(address)
		if address == "" || seen[address] {
			continue
		}
		seen[address] = true
		clean = append(clean, address)
		if len(clean) == 100 {
			break
		}
	}
	if len(clean) == 0 {
		return SolanaMultipleAccountInfoResult{}, fmt.Errorf("solana account list is empty")
	}
	return solanaRPCDo[SolanaMultipleAccountInfoResult](ctx, rpcURL, "getMultipleAccounts", []any{clean, map[string]any{"encoding": "jsonParsed", "commitment": "confirmed"}})
}
