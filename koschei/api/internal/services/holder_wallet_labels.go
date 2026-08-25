package services

// Helius Wallet Identity labeling for holder wallets.
//
// A resolved holder wallet may still be an exchange, market maker, or protocol
// treasury that on-chain program metadata alone cannot reveal (System Program
// ownership just means "a normal wallet", not "an unlabeled personal wallet").
// This module asks the Helius Wallet API whether an address maps to a known
// entity so evidence can distinguish positively-labeled exchange/protocol
// endpoints from unresolved wallets.
//
// Design rules honored:
//   - Reuses heliusEnhancedAPIKey; no new credentials.
//   - Helius documents identity and batch-identity as 100-credit paid-plan
//     Wallet API endpoints. Identity is therefore explicit opt-in through
//     HELIUS_WALLET_IDENTITY_ENABLED rather than a Free-plan default.
//   - When enabled, multiple addresses are resolved through batch-identity (up
//     to 100 inputs for the same 100-credit request) instead of one request per
//     holder/flow endpoint.
//   - A 401/403 opens a process-level capability circuit so a misconfigured or
//     Free-plan deployment cannot repeat an unavailable paid call for every
//     address in the same process.
//   - Never fabricates: only labels positively returned by Helius are surfaced.
//     Unknown/empty entries become cached unknowns, not safety claims.
//   - Missing provider configuration and transient/provider failures are not
//     cached as "unlabeled" evidence, so later healthy scans can retry.
//   - API keys are sent in the X-Api-Key header rather than credential-bearing
//     request URLs.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	heliusIdentityBaseURL   = "https://api.helius.xyz/v1/wallet"
	heliusIdentityBatchSize = 100
)

// WalletLabel is a positively-resolved entity label for an address.
type WalletLabel struct {
	Address  string   `json:"address"`
	Name     string   `json:"name,omitempty"`     // e.g. "Binance Hot Wallet 1"
	Entity   string   `json:"entity,omitempty"`   // canonical display entity/name
	Category string   `json:"category,omitempty"` // e.g. "Centralized Exchange"
	Labels   []string `json:"labels,omitempty"`   // compatibility taxonomy labels
	Tags     []string `json:"tags,omitempty"`
	Source   string   `json:"source"` // always "helius_identity" for provenance
}

type heliusIdentityResponse struct {
	Address     string   `json:"address"`
	Type        string   `json:"type"`
	Name        string   `json:"name"`
	Entity      string   `json:"entity"`
	Category    string   `json:"category"`
	Labels      []string `json:"labels"`
	Tags        []string `json:"tags"`
	InputDomain string   `json:"inputDomain"`
	Unresolved  bool     `json:"unresolved"`
}

var (
	walletLabelCache   = map[string]*WalletLabel{}
	walletLabelCacheMu sync.RWMutex

	heliusIdentityHTTPClient   = http.DefaultClient
	heliusIdentityHTTPClientMu sync.RWMutex
	heliusIdentityCapability   = struct {
		sync.RWMutex
		Unavailable bool
		StatusCode  int
	}{}
)

func heliusWalletIdentityEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("HELIUS_WALLET_IDENTITY_ENABLED"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func heliusWalletIdentityUnavailable() bool {
	heliusIdentityCapability.RLock()
	defer heliusIdentityCapability.RUnlock()
	return heliusIdentityCapability.Unavailable
}

func markHeliusWalletIdentityUnavailable(statusCode int) {
	heliusIdentityCapability.Lock()
	heliusIdentityCapability.Unavailable = true
	heliusIdentityCapability.StatusCode = statusCode
	heliusIdentityCapability.Unlock()
}

func currentHeliusIdentityHTTPClient() *http.Client {
	heliusIdentityHTTPClientMu.RLock()
	defer heliusIdentityHTTPClientMu.RUnlock()
	return heliusIdentityHTTPClient
}

func setHeliusIdentityHTTPClientForTest(client *http.Client) {
	if client == nil {
		client = http.DefaultClient
	}
	heliusIdentityHTTPClientMu.Lock()
	heliusIdentityHTTPClient = client
	heliusIdentityHTTPClientMu.Unlock()
}

// labelCacheGet returns a cached label. The bool distinguishes "cached as
// unlabeled" (present, nil value) from "never queried".
func labelCacheGet(address string) (*WalletLabel, bool) {
	walletLabelCacheMu.RLock()
	defer walletLabelCacheMu.RUnlock()
	label, ok := walletLabelCache[address]
	return label, ok
}

func labelCacheSet(address string, label *WalletLabel) {
	walletLabelCacheMu.Lock()
	defer walletLabelCacheMu.Unlock()
	walletLabelCache[address] = label
}

// ResolveWalletLabels resolves a bounded set of wallet identities using Helius'
// batch endpoint only when the paid identity capability is explicitly enabled.
func ResolveWalletLabels(ctx context.Context, rpcURL string, addresses []string) map[string]*WalletLabel {
	out := map[string]*WalletLabel{}
	clean := make([]string, 0, len(addresses))
	seen := map[string]bool{}
	for _, raw := range addresses {
		address := strings.TrimSpace(raw)
		if address == "" || seen[address] {
			continue
		}
		seen[address] = true
		if cached, ok := labelCacheGet(address); ok {
			out[address] = cached
			continue
		}
		clean = append(clean, address)
	}
	if len(clean) == 0 || ctx.Err() != nil || !heliusWalletIdentityEnabled() || heliusWalletIdentityUnavailable() {
		return out
	}

	apiKey := heliusEnhancedAPIKey(rpcURL)
	if apiKey == "" {
		// Provider configuration absence is not evidence that an address is
		// unlabeled. Do not negative-cache it.
		return out
	}

	for start := 0; start < len(clean) && ctx.Err() == nil && !heliusWalletIdentityUnavailable(); start += heliusIdentityBatchSize {
		end := start + heliusIdentityBatchSize
		if end > len(clean) {
			end = len(clean)
		}
		chunk := clean[start:end]
		rows, err := fetchHeliusIdentityBatch(ctx, apiKey, chunk)
		if err != nil {
			// Transient/auth/provider failure: preserve unknown. A 401/403 also
			// trips the capability circuit inside fetchHeliusIdentityBatch.
			continue
		}
		for index, requested := range chunk {
			if index >= len(rows) {
				// A short response is not a definitive unknown result.
				continue
			}
			label := walletLabelFromHeliusIdentity(requested, rows[index])
			labelCacheSet(requested, label)
			out[requested] = label
		}
	}
	return out
}

func fetchHeliusIdentityBatch(ctx context.Context, apiKey string, addresses []string) ([]heliusIdentityResponse, error) {
	if len(addresses) == 0 {
		return []heliusIdentityResponse{}, nil
	}
	payload, err := json.Marshal(map[string]any{"addresses": addresses})
	if err != nil {
		return nil, err
	}
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, heliusIdentityBaseURL+"/batch-identity", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", strings.TrimSpace(apiKey))

	res, err := currentHeliusIdentityHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		markHeliusWalletIdentityUnavailable(res.StatusCode)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("helius wallet identity batch status %d", res.StatusCode)
	}
	var decoded []heliusIdentityResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

func walletLabelFromHeliusIdentity(requested string, decoded heliusIdentityResponse) *WalletLabel {
	if decoded.Unresolved {
		return nil
	}
	name := strings.TrimSpace(decoded.Name)
	entity := strings.TrimSpace(decoded.Entity)
	if entity == "" {
		entity = name
	}
	normalizedType := strings.ToLower(strings.TrimSpace(decoded.Type))
	category := strings.TrimSpace(decoded.Category)
	if category == "" && normalizedType != "" && normalizedType != "unknown" && normalizedType != "wallet" {
		category = strings.TrimSpace(decoded.Type)
	}
	if category == "" && len(decoded.Labels) > 0 {
		category = strings.TrimSpace(decoded.Labels[0])
	}
	if name == "" && entity == "" && category == "" && len(decoded.Labels) == 0 && len(decoded.Tags) == 0 {
		return nil
	}
	address := strings.TrimSpace(decoded.Address)
	if address == "" {
		address = strings.TrimSpace(requested)
	}
	return &WalletLabel{
		Address:  address,
		Name:     name,
		Entity:   entity,
		Category: category,
		Labels:   append([]string{}, decoded.Labels...),
		Tags:     append([]string{}, decoded.Tags...),
		Source:   "helius_identity",
	}
}

// ResolveWalletLabel is the single-address compatibility wrapper. It still uses
// the batch endpoint internally so the provider behavior and cache semantics are
// identical to multi-address enrichment.
func ResolveWalletLabel(ctx context.Context, rpcURL, address string) *WalletLabel {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil
	}
	if cached, ok := labelCacheGet(address); ok {
		return cached
	}
	return ResolveWalletLabels(ctx, rpcURL, []string{address})[address]
}

func resetHeliusWalletIdentityStateForTest() {
	walletLabelCacheMu.Lock()
	walletLabelCache = map[string]*WalletLabel{}
	walletLabelCacheMu.Unlock()

	heliusIdentityCapability.Lock()
	heliusIdentityCapability.Unavailable = false
	heliusIdentityCapability.StatusCode = 0
	heliusIdentityCapability.Unlock()

	setHeliusIdentityHTTPClientForTest(http.DefaultClient)
}

// walletLabelDisplay renders a short human label for a holder row, or "" when
// unlabeled. Prefers entity ("Binance") over the full deposit-address name.
func walletLabelDisplay(label *WalletLabel) string {
	if label == nil {
		return ""
	}
	switch {
	case label.Entity != "":
		if label.Category != "" {
			return label.Entity + " · " + label.Category
		}
		return label.Entity
	case label.Name != "":
		return label.Name
	default:
		return label.Category
	}
}
