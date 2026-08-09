package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/services"
)

var exitLiquidityNotionalTiers = []float64{1000, 10000, 100000}

func (h *Handler) collectExitLiquiditySimulation(ctx context.Context, network, mint string, market services.TokenMarketSnapshot, jupiter services.JupiterMarketContext) services.ExitLiquiditySimulation {
	return collectExitLiquiditySimulation(ctx, h.lpRPC(), &http.Client{Timeout: 8 * time.Second}, network, mint, market, jupiter)
}

func collectExitLiquiditySimulation(ctx context.Context, rpc solanaRPCCall, client *http.Client, network, mint string, market services.TokenMarketSnapshot, jupiter services.JupiterMarketContext) services.ExitLiquiditySimulation {
	now := time.Now().UTC()
	out := services.ExitLiquiditySimulation{
		Status: "exit_liquidity_unavailable", Provider: "jupiter_quote", Mint: strings.TrimSpace(mint),
		OutputMint: jupiterUSDCMint, QuoteOnly: true, Tiers: []services.ExitLiquidityTier{},
		ObservedAt: now, Limitations: []string{},
	}
	for _, notional := range exitLiquidityNotionalTiers {
		out.Tiers = append(out.Tiers, services.ExitLiquidityTier{
			RequestedNotionalUSD: notional, Status: "not_quoted", RouteLabels: []string{}, RoutePlan: []services.ExitLiquidityRouteStep{}, Limitations: []string{},
		})
	}
	if out.Mint == "" {
		out.Status = "mint_required"
		return out
	}
	if !strings.EqualFold(strings.TrimSpace(network), "solana-mainnet") && strings.TrimSpace(network) != "" {
		out.Status = "network_not_supported"
		out.Limitations = append(out.Limitations, "Exit liquidity simulation currently uses Solana mainnet Jupiter routes only.")
		return out
	}
	out.ReferencePriceUSD = market.PriceUSD
	out.ReferencePriceFrom = "dexscreener"
	if out.ReferencePriceUSD <= 0 && jupiter.PriceAvailable && jupiter.PriceUSD > 0 {
		out.ReferencePriceUSD = jupiter.PriceUSD
		out.ReferencePriceFrom = "jupiter_price"
	}
	if out.ReferencePriceUSD <= 0 {
		out.Status = "reference_price_unavailable"
		out.Limitations = append(out.Limitations, "A positive token USD reference price is required to convert the fixed sell notionals into token input amounts.")
		return out
	}
	if rpc == nil {
		out.Status = "rpc_unavailable"
		return out
	}
	var supply rpcTokenSupplyResponse
	if err := rpc(ctx, network, "getTokenSupply", []any{out.Mint, map[string]any{"commitment": "confirmed"}}, &supply); err != nil {
		out.Status = "token_supply_unavailable"
		out.Limitations = append(out.Limitations, compactCollectorError(err))
		return out
	}
	out.TokenDecimals = supply.Value.Decimals
	supplyRaw, _ := strconv.ParseUint(strings.TrimSpace(supply.Value.Amount), 10, 64)
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	quoteURL := strings.TrimSpace(os.Getenv("JUPITER_QUOTE_URL"))
	if quoteURL == "" {
		quoteURL = defaultJupiterQuoteURL
	}
	base, err := validatedReadOnlyQuoteEndpoint(quoteURL)
	if err != nil {
		out.Status = "quote_endpoint_rejected"
		out.Limitations = append(out.Limitations, err.Error())
		return out
	}

	available := 0
	for i := range out.Tiers {
		tier := &out.Tiers[i]
		tokenAmount := tier.RequestedNotionalUSD / out.ReferencePriceUSD
		raw := decimalToRaw(tokenAmount, out.TokenDecimals)
		if raw == "" || raw == "0" {
			tier.Status = "input_amount_unrepresentable"
			continue
		}
		rawAmount, rawErr := strconv.ParseUint(raw, 10, 64)
		if rawErr != nil || (supplyRaw > 0 && rawAmount > supplyRaw) {
			tier.Status = "requested_notional_exceeds_observed_supply"
			continue
		}
		tier.InputTokenAmount = roundExitNumber(tokenAmount, 8)
		tier.InputAmountRaw = raw
		endpoint := *base
		q := endpoint.Query()
		q.Set("inputMint", out.Mint)
		q.Set("outputMint", jupiterUSDCMint)
		q.Set("amount", raw)
		q.Set("swapMode", "ExactIn")
		q.Set("slippageBps", "100")
		q.Set("restrictIntermediateTokens", "true")
		endpoint.RawQuery = q.Encode()
		quote, quoteErr := requestExitLiquidityQuote(ctx, client, endpoint.String())
		if quoteErr != nil {
			tier.Status = "quote_unavailable"
			tier.Limitations = append(tier.Limitations, compactCollectorError(quoteErr))
			continue
		}
		outRaw, parseErr := strconv.ParseUint(strings.TrimSpace(quote.OutAmount), 10, 64)
		if parseErr != nil || outRaw == 0 {
			tier.Status = "quote_output_invalid"
			continue
		}
		proceeds := float64(outRaw) / 1_000_000
		shortfall := math.Max(0, tier.RequestedNotionalUSD-proceeds)
		tier.Available = true
		tier.Status = "quoted"
		tier.OutputAmountRaw = quote.OutAmount
		tier.EstimatedProceedsUSD = roundExitNumber(proceeds, 2)
		tier.ExecutionShortfallUSD = roundExitNumber(shortfall, 2)
		tier.ExecutionShortfallPct = roundExitPct(shortfall / tier.RequestedNotionalUSD * 100)
		tier.ProceedsToNotionalPct = roundExitPct(proceeds / tier.RequestedNotionalUSD * 100)
		if tokenAmount > 0 {
			tier.EffectiveExecutionPrice = roundExitNumber(proceeds/tokenAmount, 12)
			tier.ReferencePriceDropPct = roundExitPct(math.Max(0, out.ReferencePriceUSD-tier.EffectiveExecutionPrice) / out.ReferencePriceUSD * 100)
		}
		if impact, impactErr := strconv.ParseFloat(strings.TrimSpace(quote.PriceImpactPct), 64); impactErr == nil {
			tier.JupiterPriceImpactPct = roundExitPct(math.Max(0, impact) * 100)
		}
		tier.QuoteContextSlot = quote.ContextSlot
		tier.ObservedAt = time.Now().UTC()
		for _, step := range quote.RoutePlan {
			label := strings.TrimSpace(step.SwapInfo.Label)
			ammKey := strings.TrimSpace(step.SwapInfo.AMMKey)
			if label != "" {
				tier.RouteLabels = appendUniqueExitLabel(tier.RouteLabels, label)
			}
			if !isValidSolanaAddress(ammKey) {
				ammKey = ""
			}
			if ammKey != "" || label != "" {
				tier.RoutePlan = append(tier.RoutePlan, services.ExitLiquidityRouteStep{AMMKey: ammKey, Label: label, Percent: step.Percent})
			}
		}
		available++
	}
	out.Available = available > 0
	switch available {
	case len(out.Tiers):
		out.Status = "complete"
	case 0:
		out.Status = "no_quoted_exit_tiers"
	default:
		out.Status = "partial"
	}
	out.Limitations = append(out.Limitations,
		"Quotes are read-only point-in-time estimates; they are not guaranteed proceeds and can change before execution.",
		"Returned AMM account identities describe the quote plan only and are not proof of later execution.",
		"Koschei does not request a swap transaction, sign, submit or custody assets.",
	)
	return out
}

func validatedReadOnlyQuoteEndpoint(raw string) (*url.URL, error) {
	endpoint, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || endpoint.Host == "" {
		return nil, fmt.Errorf("invalid Jupiter quote endpoint")
	}
	host := endpoint.Hostname()
	ip := net.ParseIP(host)
	local := host == "localhost" || (ip != nil && ip.IsLoopback())
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && local) {
		return nil, fmt.Errorf("Jupiter quote endpoint must use HTTPS")
	}
	if !strings.HasSuffix(strings.TrimRight(endpoint.Path, "/"), "/quote") {
		return nil, fmt.Errorf("Jupiter endpoint rejected: only the read-only /quote path is allowed")
	}
	return endpoint, nil
}

type exitLiquidityQuoteResponse struct {
	OutAmount      string `json:"outAmount"`
	PriceImpactPct string `json:"priceImpactPct"`
	ContextSlot    uint64 `json:"contextSlot"`
	RoutePlan      []struct {
		SwapInfo struct {
			AMMKey string `json:"ammKey"`
			Label  string `json:"label"`
		} `json:"swapInfo"`
		Percent int `json:"percent"`
	} `json:"routePlan"`
}

func requestExitLiquidityQuote(ctx context.Context, client *http.Client, endpoint string) (exitLiquidityQuoteResponse, error) {
	var out exitLiquidityQuoteResponse
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return out, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Koschei-Exit-Liquidity/1.0")
	if apiKey := strings.TrimSpace(os.Getenv("JUPITER_API_KEY")); apiKey != "" {
		req.Header.Set("x-api-key", apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return out, fmt.Errorf("quote http %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&out); err != nil {
		return out, err
	}
	if strings.TrimSpace(out.OutAmount) == "" {
		return out, fmt.Errorf("quote route returned no output amount")
	}
	return out, nil
}

func appendUniqueExitLabel(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func roundExitPct(value float64) float64 {
	return roundExitNumber(value, 2)
}

func roundExitNumber(value float64, decimals int) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0
	}
	factor := math.Pow10(decimals)
	return math.Round(value*factor) / factor
}
