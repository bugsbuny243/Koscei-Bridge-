package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"koschei/api/internal/services"
)

const defaultJupiterOrderURL = "https://api.jup.ag/swap/v2/order"

var errJupiterAPIKeyUnavailable = errors.New("jupiter api key unavailable")

type exitLiquidityQuoteProvider struct {
	API      string
	Endpoint *url.URL
}

type exitLiquidityEvidenceQuote struct {
	OutAmount       string
	AdverseImpactPct float64
	ContextSlot     uint64
	Router          string
	Mode            string
	RoutePlan       []services.ExitLiquidityRouteStep
}

func resolveExitLiquidityQuoteProvider() (exitLiquidityQuoteProvider, error) {
	if legacy := strings.TrimSpace(os.Getenv("JUPITER_QUOTE_URL")); legacy != "" {
		endpoint, err := validatedReadOnlyQuoteEndpoint(legacy)
		if err != nil {
			return exitLiquidityQuoteProvider{}, err
		}
		if strings.EqualFold(endpoint.Hostname(), "api.jup.ag") && strings.TrimSpace(os.Getenv("JUPITER_API_KEY")) == "" {
			return exitLiquidityQuoteProvider{}, errJupiterAPIKeyUnavailable
		}
		return exitLiquidityQuoteProvider{API: "metis_v1_quote", Endpoint: endpoint}, nil
	}

	raw := strings.TrimSpace(os.Getenv("JUPITER_ORDER_URL"))
	if raw == "" {
		raw = defaultJupiterOrderURL
	}
	endpoint, err := validatedReadOnlyOrderEndpoint(raw)
	if err != nil {
		return exitLiquidityQuoteProvider{}, err
	}
	if strings.EqualFold(endpoint.Hostname(), "api.jup.ag") && strings.TrimSpace(os.Getenv("JUPITER_API_KEY")) == "" {
		return exitLiquidityQuoteProvider{}, errJupiterAPIKeyUnavailable
	}
	return exitLiquidityQuoteProvider{API: "swap_v2_order", Endpoint: endpoint}, nil
}

func validatedReadOnlyOrderEndpoint(raw string) (*url.URL, error) {
	endpoint, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || endpoint.Host == "" {
		return nil, fmt.Errorf("invalid Jupiter order endpoint")
	}
	if err := validateJupiterReadOnlyEndpointTransport(endpoint); err != nil {
		return nil, err
	}
	if !strings.HasSuffix(strings.TrimRight(endpoint.Path, "/"), "/order") {
		return nil, fmt.Errorf("Jupiter endpoint rejected: only the read-only /order path is allowed")
	}
	return endpoint, nil
}

func validateJupiterReadOnlyEndpointTransport(endpoint *url.URL) error {
	if endpoint == nil {
		return fmt.Errorf("Jupiter endpoint is unavailable")
	}
	host := endpoint.Hostname()
	if endpoint.Scheme == "https" {
		return nil
	}
	if endpoint.Scheme == "http" && isLoopbackJupiterHost(host) {
		return nil
	}
	return fmt.Errorf("Jupiter endpoint must use HTTPS")
}

func isLoopbackJupiterHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	return host == "localhost" || strings.HasPrefix(host, "127.") || host == "::1"
}

func (provider exitLiquidityQuoteProvider) quote(ctx context.Context, client *http.Client, inputMint, outputMint, amount string) (exitLiquidityEvidenceQuote, error) {
	if provider.Endpoint == nil {
		return exitLiquidityEvidenceQuote{}, fmt.Errorf("Jupiter quote provider is unavailable")
	}
	endpoint := *provider.Endpoint
	query := endpoint.Query()
	query.Set("inputMint", strings.TrimSpace(inputMint))
	query.Set("outputMint", strings.TrimSpace(outputMint))
	query.Set("amount", strings.TrimSpace(amount))
	query.Set("swapMode", "ExactIn")
	if provider.API == "metis_v1_quote" {
		query.Set("slippageBps", "100")
		query.Set("restrictIntermediateTokens", "true")
	}
	endpoint.RawQuery = query.Encode()

	switch provider.API {
	case "swap_v2_order":
		return requestJupiterV2QuoteOnlyOrder(ctx, client, endpoint.String())
	case "metis_v1_quote":
		legacy, err := requestExitLiquidityQuote(ctx, client, endpoint.String())
		if err != nil {
			return exitLiquidityEvidenceQuote{}, err
		}
		impact := 0.0
		if value, parseErr := strconv.ParseFloat(strings.TrimSpace(legacy.PriceImpactPct), 64); parseErr == nil {
			impact = math.Max(0, value) * 100
		}
		return exitLiquidityEvidenceQuote{
			OutAmount: legacy.OutAmount, AdverseImpactPct: impact, ContextSlot: legacy.ContextSlot,
			RoutePlan: normalizeExitLiquidityRoutePlan(legacy.RoutePlan),
		}, nil
	default:
		return exitLiquidityEvidenceQuote{}, fmt.Errorf("unsupported Jupiter quote API %q", provider.API)
	}
}

type jupiterV2OrderResponse struct {
	OutAmount      string  `json:"outAmount"`
	PriceImpact    float64 `json:"priceImpact"`
	PriceImpactPct string  `json:"priceImpactPct"`
	Router         string  `json:"router"`
	Mode           string  `json:"mode"`
	Transaction    *string `json:"transaction"`
	RoutePlan      []struct {
		SwapInfo struct {
			AMMKey string `json:"ammKey"`
			Label  string `json:"label"`
		} `json:"swapInfo"`
		Percent  int     `json:"percent"`
		BPS      int     `json:"bps"`
		USDValue float64 `json:"usdValue"`
	} `json:"routePlan"`
}

func requestJupiterV2QuoteOnlyOrder(ctx context.Context, client *http.Client, endpoint string) (exitLiquidityEvidenceQuote, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return exitLiquidityEvidenceQuote{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Koschei-Exit-Liquidity/2.0")
	if apiKey := jupiterAPIKeyForQuoteEndpoint(endpoint); apiKey != "" {
		req.Header.Set("x-api-key", apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return exitLiquidityEvidenceQuote{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return exitLiquidityEvidenceQuote{}, fmt.Errorf("order http %d", resp.StatusCode)
	}
	var order jupiterV2OrderResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&order); err != nil {
		return exitLiquidityEvidenceQuote{}, err
	}
	if strings.TrimSpace(order.OutAmount) == "" {
		return exitLiquidityEvidenceQuote{}, fmt.Errorf("order returned no output amount")
	}
	if order.Transaction != nil {
		return exitLiquidityEvidenceQuote{}, fmt.Errorf("quote-only order unexpectedly returned a transaction")
	}

	impact := 0.0
	if order.PriceImpact < 0 {
		impact = -order.PriceImpact
	} else if order.PriceImpact == 0 && strings.TrimSpace(order.PriceImpactPct) != "" {
		if deprecated, parseErr := strconv.ParseFloat(strings.TrimSpace(order.PriceImpactPct), 64); parseErr == nil {
			impact = math.Max(0, deprecated) * 100
		}
	}
	plan := make([]services.ExitLiquidityRouteStep, 0, len(order.RoutePlan))
	for _, step := range order.RoutePlan {
		plan = append(plan, services.ExitLiquidityRouteStep{
			AMMKey: strings.TrimSpace(step.SwapInfo.AMMKey), Label: strings.TrimSpace(step.SwapInfo.Label),
			Percent: step.Percent, BPS: step.BPS, USDValue: step.USDValue,
		})
	}
	return exitLiquidityEvidenceQuote{
		OutAmount: order.OutAmount, AdverseImpactPct: impact,
		Router: strings.TrimSpace(order.Router), Mode: strings.TrimSpace(order.Mode), RoutePlan: plan,
	}, nil
}

func normalizeExitLiquidityRoutePlan(plan []struct {
	SwapInfo struct {
		AMMKey string `json:"ammKey"`
		Label  string `json:"label"`
	} `json:"swapInfo"`
	Percent int `json:"percent"`
}) []services.ExitLiquidityRouteStep {
	out := make([]services.ExitLiquidityRouteStep, 0, len(plan))
	for _, step := range plan {
		out = append(out, services.ExitLiquidityRouteStep{
			AMMKey: strings.TrimSpace(step.SwapInfo.AMMKey), Label: strings.TrimSpace(step.SwapInfo.Label), Percent: step.Percent,
		})
	}
	return out
}
