package handlers

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"koschei/api/internal/runtimecfg"
	"koschei/api/internal/web3"
)

func (h *Handler) Config(w http.ResponseWriter, _ *http.Request) {
	cfg := runtimecfg.Load()
	writeJSON(w, http.StatusOK, map[string]any{
		"version":        "3.1.0",
		"app_name":       cfg.AppName,
		"runtime_config": runtimecfg.PublicSnapshot(),
		"neonAuthUrl":    configuredPublicNeonAuthURL(),
		"access": map[string]any{
			"provider":       "free_core_plus_kosch_premium",
			"mode":           "public_basic_verified_holder_premium",
			"free_core":      []string{"safe_check", "basic_token_scan"},
			"premium":        []string{"security_radar", "exposure_reports", "graph", "watchlist", "webhooks", "developer_api", "advanced_agents"},
			"mint":           configuredKoscheiTokenMint(),
			"network":        firstNonEmptyString(os.Getenv("KOSCHEI_TOKEN_NETWORK"), os.Getenv("KOSCH_TOKEN_NETWORK"), "solana-mainnet"),
			"wallet_proof":   "phantom_message_signature",
			"custodial":      false,
			"legacy_billing": false,
		},
	})
}

func configuredURL(envKey, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(envKey)); value != "" {
		return value
	}
	return fallback
}

func (h *Handler) Provision(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	claims, err := parseAndVerifyNeonJWT(token)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if !h.RequireDB(w) {
		return
	}
	summary, err := h.provisionMember(r.Context(), claims)
	if err != nil {
		log.Printf("provisionMember failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "account provisioning unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"ok":    "true",
		"sub":   claims.Sub,
		"email": summary.Email,
		"plan":  freePlanID,
	})
}

type chainHealthResponse struct {
	OK       bool   `json:"ok"`
	Status   string `json:"status"`
	Chain    string `json:"chain"`
	Network  string `json:"network"`
	Provider string `json:"provider"`
	Result   string `json:"result"`
	Error    string `json:"error"`
}

func (h *Handler) Web3Health(w http.ResponseWriter, r *http.Request) {
	chain := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("chain")))
	if chain == "" {
		chain = "solana"
	}

	if chain == "solana" {
		h.web3SolanaHealth(w, r)
		return
	}

	type rpcConfig struct {
		url     string
		network string
		body    string
	}
	apiKey := os.Getenv("ALCHEMY_API_KEY")
	configs := map[string]rpcConfig{
		"ethereum": {url: "https://eth-sepolia.g.alchemy.com/v2/" + apiKey, network: "sepolia", body: `{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}`},
		"base":     {url: "https://base-sepolia.g.alchemy.com/v2/" + apiKey, network: "sepolia", body: `{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}`},
		"arbitrum": {url: "https://arb-sepolia.g.alchemy.com/v2/" + apiKey, network: "sepolia", body: `{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}`},
		"polygon":  {url: "https://polygon-amoy.g.alchemy.com/v2/" + apiKey, network: "amoy", body: `{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}`},
		"optimism": {url: "https://opt-sepolia.g.alchemy.com/v2/" + apiKey, network: "sepolia", body: `{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}`},
	}
	cfg, ok := configs[chain]
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown chain"})
		return
	}
	status := "online"
	errorText := ""
	if apiKey == "" {
		status = "no_api_key"
		errorText = "Alchemy API key is not configured"
	} else {
		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, cfg.url, strings.NewReader(cfg.body))
		if err != nil {
			status = "error"
			errorText = err.Error()
		} else {
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				status = "error"
				errorText = err.Error()
			} else {
				resp.Body.Close()
				if resp.StatusCode >= http.StatusBadRequest {
					status = "error"
					errorText = fmt.Sprintf("Alchemy returned HTTP %d", resp.StatusCode)
				}
			}
		}
	}
	result := status
	response := chainHealthResponse{OK: status == "online", Status: status, Chain: chain, Network: cfg.network, Provider: "Alchemy", Result: result, Error: errorText}
	h.recordChainHealth(chainHealthLog{Chain: chain, Network: cfg.network, Provider: "alchemy", Healthy: response.OK, Result: result, Error: errorText, CheckedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) web3SolanaHealth(w http.ResponseWriter, r *http.Request) {
	cfg := runtimecfg.Load()
	provider := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("provider")))
	if provider == "" || provider == "auto" {
		provider = cfg.Web3Provider
	}
	if provider == "" || provider == "auto" {
		provider = cfg.SecurityProvider
	}
	if provider == "" || provider == "auto" {
		provider = "rpc"
	}

	if provider == "solscan" {
		usage, err := web3.SolscanUsageHealth(r.Context(), &http.Client{Timeout: 5 * time.Second})
		status := "online"
		errorText := ""
		result := "usage_endpoint_reachable"
		if err != nil {
			status = "error"
			errorText = err.Error()
			result = "unavailable"
		}
		response := chainHealthResponse{OK: err == nil, Status: status, Chain: "solana", Network: cfg.SolanaNetwork, Provider: "solscan", Result: result, Error: errorText}
		h.recordChainHealth(chainHealthLog{Chain: "solana", Network: cfg.SolanaNetwork, Provider: "solscan", Healthy: response.OK, Result: fmt.Sprintf("%s; remaining_cus=%.0f; requests_24h=%.0f", result, usage.RemainingCUs, usage.TotalRequests24H), Error: errorText, CheckedAt: time.Now().UTC()})
		writeJSON(w, http.StatusOK, response)
		return
	}

	rpcURL := web3.SolanaRPCURL(cfg.SolanaNetwork, strings.TrimSpace(os.Getenv("ALCHEMY_API_KEY")))
	providerName := web3.RPCProviderHost(rpcURL)
	if providerName == "" {
		providerName = provider
	}
	status := "online"
	errorText := ""
	body := `{"jsonrpc":"2.0","id":1,"method":"getHealth"}`
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, rpcURL, strings.NewReader(body))
	if err != nil {
		status = "error"
		errorText = err.Error()
	} else {
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			status = "error"
			errorText = err.Error()
		} else {
			resp.Body.Close()
			if resp.StatusCode >= http.StatusBadRequest {
				status = "error"
				errorText = fmt.Sprintf("Solana RPC returned HTTP %d", resp.StatusCode)
			}
		}
	}
	result := status
	response := chainHealthResponse{OK: status == "online", Status: status, Chain: "solana", Network: cfg.SolanaNetwork, Provider: providerName, Result: result, Error: errorText}
	h.recordChainHealth(chainHealthLog{Chain: "solana", Network: cfg.SolanaNetwork, Provider: providerName, Healthy: response.OK, Result: result, Error: errorText, CheckedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, response)
}
