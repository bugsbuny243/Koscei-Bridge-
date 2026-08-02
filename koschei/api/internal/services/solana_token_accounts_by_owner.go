package services

import (
	"context"
	"fmt"
	"math/big"
	"strings"
)

type SolanaOwnedTokenAccount struct {
	Pubkey  string `json:"pubkey"`
	Account struct {
		Data struct {
			Parsed struct {
				Type string `json:"type"`
				Info struct {
					Mint        string            `json:"mint"`
					Owner       string            `json:"owner"`
					State       string            `json:"state"`
					TokenAmount SolanaTokenAmount `json:"tokenAmount"`
				} `json:"info"`
			} `json:"parsed"`
		} `json:"data"`
	} `json:"account"`
}

type SolanaOwnedTokenAccountsResult struct {
	Value []SolanaOwnedTokenAccount `json:"value"`
}

// SolanaGetTokenAccountsByOwnerForMint is intentionally mint-specific. Broad
// recipient wallet history is forbidden by ACTOR_INVESTIGATION_ENGINE.md.
func SolanaGetTokenAccountsByOwnerForMint(ctx context.Context, rpcURL, owner, mint string) (SolanaOwnedTokenAccountsResult, error) {
	rpcURL = strings.TrimSpace(rpcURL)
	owner = strings.TrimSpace(owner)
	mint = strings.TrimSpace(mint)
	if rpcURL == "" {
		return SolanaOwnedTokenAccountsResult{}, fmt.Errorf("solana rpc url is empty")
	}
	if owner == "" {
		return SolanaOwnedTokenAccountsResult{}, fmt.Errorf("solana token owner is empty")
	}
	if mint == "" {
		return SolanaOwnedTokenAccountsResult{}, fmt.Errorf("solana token mint is empty")
	}
	return solanaRPCDo[SolanaOwnedTokenAccountsResult](ctx, rpcURL, "getTokenAccountsByOwner", []any{
		owner,
		map[string]any{"mint": mint},
		map[string]any{"encoding": "jsonParsed", "commitment": "confirmed"},
	})
}

func AggregateOwnedTokenAccounts(result SolanaOwnedTokenAccountsResult, mint string) (rawAmount string, uiAmount float64, decimals int, tokenAccounts []string) {
	mint = strings.TrimSpace(mint)
	total := new(big.Int)
	seen := map[string]bool{}
	decimals = -1
	for _, account := range result.Value {
		info := account.Account.Data.Parsed.Info
		if mint != "" && strings.TrimSpace(info.Mint) != mint {
			continue
		}
		if account.Pubkey != "" && !seen[account.Pubkey] {
			seen[account.Pubkey] = true
			tokenAccounts = append(tokenAccounts, account.Pubkey)
		}
		amount := new(big.Int)
		if _, ok := amount.SetString(strings.TrimSpace(info.TokenAmount.Amount), 10); ok && amount.Sign() >= 0 {
			total.Add(total, amount)
		}
		if decimals < 0 {
			decimals = info.TokenAmount.Decimals
		}
		if info.TokenAmount.UIAmount != nil {
			uiAmount += *info.TokenAmount.UIAmount
		} else if info.TokenAmount.UIAmountString != "" {
			uiAmount += solanaTokenAmountFloat(info.TokenAmount)
		}
	}
	if decimals < 0 {
		decimals = 0
	}
	return total.String(), uiAmount, decimals, tokenAccounts
}

func solanaTokenAmountFloat(value SolanaTokenAmount) float64 {
	if value.UIAmount != nil {
		return *value.UIAmount
	}
	if strings.TrimSpace(value.UIAmountString) != "" {
		parsed, _ := new(big.Float).SetString(strings.TrimSpace(value.UIAmountString))
		if parsed != nil {
			result, _ := parsed.Float64()
			return result
		}
	}
	return 0
}
