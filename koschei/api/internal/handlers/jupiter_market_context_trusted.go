package handlers

import (
	"context"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"koschei/api/internal/services"
)

type jupiterPriceEnvelope map[string]struct {
	USDPrice float64 `json:"usdPrice"`
	BlockID  uint64  `json:"blockId"`
}

func (h *Handler) collectTrustedJupiterMarketContext(ctx context.Context, network, mint string, holder services.HolderIntelligence, market services.TokenMarketSnapshot) services.JupiterMarketContext {
	return collectTrustedJupiterMarketContext(ctx, h.lpRPC(), &http.Client{Timeout: 7 * time.Second}, network, mint, holder, market)
}

func collectTrustedJupiterMarketContext(ctx context.Context, rpc solanaRPCCall, client *http.Client, network, mint string, holder services.HolderIntelligence, market services.TokenMarketSnapshot) services.JupiterMarketContext {
	now := time.Now().UTC()
	out := services.JupiterMarketContext{
		Status: "jupiter_context_unavailable", DexScreenerPriceUSD: market.PriceUSD,
		RouteLabels: []string{}, Limitations: []string{},
	}
	mint = strings.TrimSpace(mint)
	if mint == "" {
		out.Status = "mint_required"
		return out
	}
	network = strings.TrimSpace(network)
	if network == "" {
		network = "solana-mainnet"
	}
	if client == nil {
		client = &http.Client{Timeout: 7 * time.Second}
	}

	priceRaw := strings.TrimSpace(os.Getenv("JUPITER_PRICE_URL"))
	if priceRaw == "" {
		priceRaw = defaultJupiterPriceURL
	}
	if endpoint, err := validatedReadOnlyJupiterPriceEndpoint(priceRaw); err != nil {
		out.Limitations = append(out.Limitations, "Jupiter price endpoint rejected: "+err.Error())
	} else {
		priceURL := *endpoint
		query := priceURL.Query()
		query.Set("ids", mint)
		priceURL.RawQuery = query.Encode()
		var prices jupiterPriceEnvelope
		if err := trustedJupiterGETJSON(ctx, client, priceURL.String(), &prices); err != nil {
			out.Limitations = append(out.Limitations, "Jupiter price evidence unavailable: "+compactCollectorError(err))
		} else if item, ok := prices[mint]; ok && item.USDPrice > 0 {
			out.PriceAvailable = true
			out.PriceUSD = item.USDPrice
			out.PriceBlockID = item.BlockID
			out.PriceObservedAt = now
			if market.PriceUSD > 0 {
				out.PriceDifferencePct = roundCollectorPct(math.Abs(item.USDPrice-market.PriceUSD) / market.PriceUSD * 100)
			}
		}
	}

	if rpc != nil && holder.Available && holder.CirculatingSupply > 0 && holder.Top1Percentage > 0 {
		var supply rpcTokenSupplyResponse
		if err := rpc(ctx, network, "getTokenSupply", []any{mint, map[string]any{"commitment": "confirmed"}}, &supply); err == nil {
			topHolderTokens := holder.CirculatingSupply * holder.Top1Percentage / 100
			rawAmount := decimalToRaw(topHolderTokens, supply.Value.Decimals)
			if rawAmount != "" && rawAmount != "0" {
				out.SellInputAmountRaw = rawAmount
				out.SellOutputMint = jupiterUSDCMint
				provider, providerErr := resolveExitLiquidityQuoteProvider()
				if providerErr != nil {
					out.Limitations = append(out.Limitations, "Jupiter sell-impact provider unavailable: "+compactCollectorError(providerErr))
				} else {
					quote, quoteErr := provider.quote(ctx, client, mint, jupiterUSDCMint, rawAmount)
					if quoteErr != nil {
						out.Limitations = append(out.Limitations, "Jupiter sell-impact quote unavailable: "+compactCollectorError(quoteErr))
					} else if strings.TrimSpace(quote.OutAmount) != "" {
						out.SellImpactAvailable = true
						out.SellQuoteAPI = provider.API
						out.SellQuoteRouter = strings.TrimSpace(quote.Router)
						out.SellQuoteMode = strings.TrimSpace(quote.Mode)
						out.SellOutputAmountRaw = strings.TrimSpace(quote.OutAmount)
						out.EstimatedPriceImpactPct = roundCollectorPct(math.Max(0, math.Min(100, quote.AdverseImpactPct)))
						out.QuoteContextSlot = quote.ContextSlot
						out.QuoteObservedAt = time.Now().UTC()
						for _, step := range quote.RoutePlan {
							label := strings.TrimSpace(step.Label)
							if label != "" {
								out.RouteLabels = uniqueStrings(append(out.RouteLabels, label))
							}
						}
					}
				}
			}
		}
	}

	out.Available = out.PriceAvailable || out.SellImpactAvailable
	switch {
	case out.PriceAvailable && out.SellImpactAvailable:
		out.Status = "complete"
	case out.PriceAvailable:
		out.Status = "price_only"
	case out.SellImpactAvailable:
		out.Status = "sell_impact_only"
	default:
		out.Status = "jupiter_context_unavailable"
	}
	out.Limitations = append(out.Limitations,
		"Jupiter context is read-only supplementary evidence and cannot issue a verdict by itself.",
		"Sell impact is a quote estimate, not a guaranteed execution result.",
	)
	return out
}
