package web3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/cache"
	"koschei/api/internal/runtimecfg"
)

type SolanaRPC struct {
	Client        *http.Client
	Cache         cache.Cache
	KeyPrefix     string
	AlchemyAPIKey string
}

type solanaRPCEnvelope struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func NewSolanaRPC(c cache.Cache) *SolanaRPC {
	if c == nil {
		c = cache.NewNoop()
	}
	prefix := strings.TrimSpace(os.Getenv("CACHE_KEY_PREFIX"))
	if prefix == "" {
		prefix = "koschei"
	}
	return &SolanaRPC{Client: &http.Client{Timeout: 12 * time.Second}, Cache: c, KeyPrefix: prefix, AlchemyAPIKey: os.Getenv("ALCHEMY_API_KEY")}
}

func (s *SolanaRPC) URL(network string) string {
	return configuredSolanaRPCURL(network, s.AlchemyAPIKey)
}

func configuredSolanaRPCURL(network, apiKey string) string {
	cfg := runtimecfg.Load()
	if strings.TrimSpace(network) == "" {
		network = cfg.SolanaNetwork
	}
	if isSolanaMainnet(network) {
		if value := strings.TrimSpace(os.Getenv("SOLANA_RPC_URL")); value != "" {
			return value
		}
		provider := cfg.Web3Provider
		if provider == "auto" && cfg.SecurityProvider != "auto" {
			provider = cfg.SecurityProvider
		}
		for _, key := range preferredMainnetRPCKeys(provider) {
			if value := strings.TrimSpace(os.Getenv(key)); value != "" {
				return value
			}
		}
		if strings.TrimSpace(apiKey) != "" {
			return "https://solana-mainnet.g.alchemy.com/v2/" + strings.TrimSpace(apiKey)
		}
		return "https://api.mainnet-beta.solana.com"
	}
	for _, key := range []string{"SOLANA_DEVNET_RPC_URL", "ALCHEMY_SOLANA_DEVNET_RPC_URL"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	if strings.TrimSpace(apiKey) != "" {
		return "https://solana-devnet.g.alchemy.com/v2/" + strings.TrimSpace(apiKey)
	}
	return "https://api.devnet.solana.com"
}

func preferredMainnetRPCKeys(provider string) []string {
	base := map[string]string{
		"alchemy":   "ALCHEMY_SOLANA_RPC_URL",
		"helius":    "HELIUS_SOLANA_RPC_URL",
		"quicknode": "QUICKNODE_SOLANA_RPC_URL",
	}
	ordered := []string{}
	if key := base[strings.ToLower(strings.TrimSpace(provider))]; key != "" {
		ordered = append(ordered, key)
	}
	for _, key := range []string{"ALCHEMY_SOLANA_RPC_URL", "HELIUS_SOLANA_RPC_URL", "QUICKNODE_SOLANA_RPC_URL"} {
		found := false
		for _, existing := range ordered {
			if existing == key {
				found = true
				break
			}
		}
		if !found {
			ordered = append(ordered, key)
		}
	}
	return ordered
}

func SolanaRPCURL(network, apiKey string) string {
	return configuredSolanaRPCURL(network, apiKey)
}

func SolanaRPCFallbackURL(network string) string {
	cfg := runtimecfg.Load()
	if strings.TrimSpace(network) == "" {
		network = cfg.SolanaNetwork
	}
	if isSolanaMainnet(network) {
		primaryURL := configuredSolanaRPCURL(network, strings.TrimSpace(os.Getenv("ALCHEMY_API_KEY")))
		if explicit := strings.TrimSpace(os.Getenv("SOLANA_RPC_FALLBACK_URL")); explicit != "" && explicit != strings.TrimSpace(primaryURL) {
			return explicit
		}
		primaryHost := RPCProviderHost(primaryURL)
		provider := cfg.Web3Provider
		if provider == "auto" && cfg.SecurityProvider != "auto" {
			provider = cfg.SecurityProvider
		}
		candidates := []string{}
		for _, key := range preferredMainnetRPCKeys(provider) {
			candidates = append(candidates, strings.TrimSpace(os.Getenv(key)))
		}
		if key := strings.TrimSpace(os.Getenv("ALCHEMY_API_KEY")); key != "" {
			candidates = append(candidates, "https://solana-mainnet.g.alchemy.com/v2/"+key)
		}
		candidates = append(candidates, "https://api.mainnet-beta.solana.com")
		for _, candidate := range candidates {
			if candidate == "" || RPCProviderHost(candidate) == primaryHost {
				continue
			}
			return candidate
		}
		return "https://api.mainnet-beta.solana.com"
	}
	if value := strings.TrimSpace(os.Getenv("SOLANA_DEVNET_RPC_FALLBACK_URL")); value != "" {
		return value
	}
	return "https://api.devnet.solana.com"
}

func solanaRPCEndpointTimeout() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("SOLANA_RPC_ENDPOINT_TIMEOUT_MS")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value >= 50 && value <= 30000 {
			return time.Duration(value) * time.Millisecond
		}
	}
	return 6 * time.Second
}

func isSolanaMainnet(network string) bool {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "solana-mainnet", "mainnet", "mainnet-beta":
		return true
	default:
		return false
	}
}

func uniqueRPCURLs(values ...string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func (s *SolanaRPC) CacheKey(network, method string, params any) string {
	b, _ := json.Marshal(params)
	h := sha256.Sum256(b)
	return fmt.Sprintf("%s:solana:%s:rpc:%s:%s", s.KeyPrefix, network, method, hex.EncodeToString(h[:]))
}

func TTLFor(method string, params any) time.Duration {
	switch method {
	case "getTokenSupply":
		return time.Minute
	case "getTokenLargestAccounts":
		return 5 * time.Minute
	case "getTransaction":
		return 24 * time.Hour
	case "getSignaturesForAddress":
		return time.Minute
	case "getAccountInfo":
		return 30 * time.Second
	default:
		return 2 * time.Minute
	}
}

func (s *SolanaRPC) Call(ctx context.Context, network, method string, params any, target any, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = TTLFor(method, params)
	}
	key := s.CacheKey(network, method, params)
	if ok, err := s.Cache.GetJSON(ctx, key, target); err == nil && ok {
		return nil
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		LogRPCFailure(method, s.URL(network), 0, err)
		return err
	}
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}

	var lastErr error
	endpointTimeout := solanaRPCEndpointTimeout()
	for _, endpoint := range uniqueRPCURLs(s.URL(network), SolanaRPCFallbackURL(network)) {
		attemptCtx := ctx
		cancel := func() {}
		if endpointTimeout > 0 {
			attemptCtx, cancel = context.WithTimeout(ctx, endpointTimeout)
		}
		err := callSolanaRPC(attemptCtx, client, endpoint, method, body, target)
		cancel()
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		_ = s.Cache.SetJSON(ctx, key, target, ttl)
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("solana rpc endpoint unavailable")
	}
	return lastErr
}

func callSolanaRPC(ctx context.Context, client *http.Client, endpoint, method string, body []byte, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		LogRPCFailure(method, endpoint, 0, err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		LogRPCFailure(method, endpoint, 0, err)
		return err
	}
	defer resp.Body.Close()
	actualEndpoint := endpoint
	if resp.Request != nil && resp.Request.URL != nil {
		actualEndpoint = resp.Request.URL.String()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := fmt.Errorf("rpc status %d", resp.StatusCode)
		LogRPCFailure(method, actualEndpoint, resp.StatusCode, err)
		return err
	}
	var env solanaRPCEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		LogRPCFailure(method, actualEndpoint, resp.StatusCode, err)
		return err
	}
	if env.Error != nil {
		err := fmt.Errorf("rpc error: %s", env.Error.Message)
		LogRPCFailure(method, actualEndpoint, resp.StatusCode, err)
		return err
	}
	if len(env.Result) == 0 || string(env.Result) == "null" {
		err := fmt.Errorf("rpc result unavailable")
		LogRPCFailure(method, actualEndpoint, resp.StatusCode, err)
		return err
	}
	if err := json.Unmarshal(env.Result, target); err != nil {
		LogRPCFailure(method, actualEndpoint, resp.StatusCode, err)
		return err
	}
	return nil
}
