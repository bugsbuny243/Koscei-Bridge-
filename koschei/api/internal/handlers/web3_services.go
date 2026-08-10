package handlers

import (
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"koschei/api/internal/web3"
)

var (
	tokenServiceMu     sync.Mutex
	globalTokenService *web3.TokenService
)

func (h *Handler) tokenService() *web3.TokenService {
	if globalTokenService != nil {
		return globalTokenService
	}
	tokenServiceMu.Lock()
	defer tokenServiceMu.Unlock()
	if globalTokenService != nil {
		return globalTokenService
	}
	providers := configuredRPCProviders()
	globalTokenService = web3.NewTokenService(web3.NewRPCManager(&http.Client{Timeout: 12 * time.Second}, providers), web3.NewSmartCache(web3.NewMemoryCache()))
	return globalTokenService
}

func configuredRPCProviders() []web3.RPCProviderConfig {
	providers := []web3.RPCProviderConfig{}
	seenURLs := map[string]struct{}{}
	add := func(name, url string, priority int) {
		url = strings.TrimSpace(url)
		if url == "" {
			return
		}
		if _, exists := seenURLs[url]; exists {
			return
		}
		seenURLs[url] = struct{}{}
		providers = append(providers, web3.RPCProviderConfig{Name: name, URL: url, Priority: priority, Timeout: 8 * time.Second, Cooldown: time.Minute, MaxFailures: 5})
	}
	firstEnv := func(keys ...string) string {
		for _, key := range keys {
			if value := strings.TrimSpace(os.Getenv(key)); value != "" {
				return value
			}
		}
		return ""
	}

	// An explicitly configured canonical RPC is sovereign infrastructure from
	// the detector's point of view. It must win over commercial provider
	// fallbacks. This is the slot where a Koschei-owned Solana RPC is attached.
	add("solana_rpc", os.Getenv("SOLANA_RPC_URL"), 1)

	alchemyKey := strings.TrimSpace(os.Getenv("ALCHEMY_API_KEY"))
	alchemyURL := firstEnv("ALCHEMY_SOLANA_RPC_URL", "SOLANA_ALCHEMY_RPC_URL")
	if alchemyURL == "" && alchemyKey != "" {
		// Build the legacy provider fallback directly. Calling the canonical
		// resolver here would incorrectly relabel SOLANA_RPC_URL as Alchemy.
		alchemyURL = "https://solana-mainnet.g.alchemy.com/v2/" + alchemyKey
	}
	add("alchemy", alchemyURL, 10)
	add("helius", firstEnv("HELIUS_SOLANA_RPC_URL", "SOLANA_HELIUS_RPC_URL"), 20)
	add("quicknode", firstEnv("QUICKNODE_SOLANA_RPC_URL", "SOLANA_QUICKNODE_RPC_URL"), 30)

	if len(providers) == 0 {
		add("public", "https://api.mainnet-beta.solana.com", 100)
	}
	return providers
}
