package handlers

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"koschei/api/internal/services"
)

type koscheiActorRecipientTransport struct {
	h       *Handler
	network string
	client  *http.Client
	rpcURL  string
}

func (h *Handler) actorRecipientTransport(network string) services.ActorInitialRecipientTransport {
	network = strings.TrimSpace(network)
	if network == "" {
		network = "solana-mainnet"
	}
	return &koscheiActorRecipientTransport{
		h: h, network: network, client: &http.Client{Timeout: 12 * time.Second},
		rpcURL: solanaRPCURL(network, os.Getenv("ALCHEMY_API_KEY")),
	}
}

func (t *koscheiActorRecipientTransport) Transaction(ctx context.Context, signature string) (map[string]any, error) {
	var out map[string]any
	err := t.h.callSolanaRPC(ctx, t.client, t.rpcURL, t.network, "getTransaction", []any{
		strings.TrimSpace(signature),
		map[string]any{"encoding": "jsonParsed", "commitment": "confirmed", "maxSupportedTransactionVersion": 0},
	}, &out)
	return out, err
}

func (t *koscheiActorRecipientTransport) TokenAccountsByOwnerForMint(ctx context.Context, owner, mint string) (services.SolanaOwnedTokenAccountsResult, error) {
	var out services.SolanaOwnedTokenAccountsResult
	err := t.h.callSolanaRPC(ctx, t.client, t.rpcURL, t.network, "getTokenAccountsByOwner", []any{
		strings.TrimSpace(owner), map[string]any{"mint": strings.TrimSpace(mint)},
		map[string]any{"encoding": "jsonParsed", "commitment": "confirmed"},
	}, &out)
	return out, err
}

func (t *koscheiActorRecipientTransport) SignaturesForAddressPage(ctx context.Context, address string, options services.SolanaSignaturePageOptions) ([]services.SolanaSignatureInfo, error) {
	limit := options.Limit
	if limit <= 0 || limit > 1000 {
		limit = 250
	}
	config := map[string]any{"limit": limit}
	if before := strings.TrimSpace(options.Before); before != "" {
		config["before"] = before
	}
	if until := strings.TrimSpace(options.Until); until != "" {
		config["until"] = until
	}
	var out []services.SolanaSignatureInfo
	err := t.h.callSolanaRPC(ctx, t.client, t.rpcURL, t.network, "getSignaturesForAddress", []any{strings.TrimSpace(address), config}, &out)
	return out, err
}

func (t *koscheiActorRecipientTransport) TokenSupply(ctx context.Context, mint string) (services.SolanaTokenSupplyResult, error) {
	var out services.SolanaTokenSupplyResult
	err := t.h.callSolanaRPC(ctx, t.client, t.rpcURL, t.network, "getTokenSupply", []any{strings.TrimSpace(mint), map[string]any{"commitment": "confirmed"}}, &out)
	return out, err
}

func (t *koscheiActorRecipientTransport) LargestTokenAccounts(ctx context.Context, mint string) (services.SolanaLargestAccountsResult, error) {
	var out services.SolanaLargestAccountsResult
	err := t.h.callSolanaRPC(ctx, t.client, t.rpcURL, t.network, "getTokenLargestAccounts", []any{strings.TrimSpace(mint), map[string]any{"commitment": "confirmed"}}, &out)
	return out, err
}

func (t *koscheiActorRecipientTransport) MultipleAccounts(ctx context.Context, addresses []string) (services.SolanaMultipleAccountInfoResult, error) {
	var out services.SolanaMultipleAccountInfoResult
	err := t.h.callSolanaRPC(ctx, t.client, t.rpcURL, t.network, "getMultipleAccounts", []any{addresses, map[string]any{"encoding": "jsonParsed", "commitment": "confirmed"}}, &out)
	return out, err
}
