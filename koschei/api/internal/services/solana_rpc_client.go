package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"koschei/api/internal/web3"
)

type SolanaSignatureInfo struct {
	Signature string `json:"signature"`
	Slot      int64  `json:"slot"`
	Err       any    `json:"err"`
	BlockTime *int64 `json:"blockTime"`
}

type SolanaTokenAmount struct {
	Amount         string   `json:"amount"`
	Decimals       int      `json:"decimals"`
	UIAmount       *float64 `json:"uiAmount"`
	UIAmountString string   `json:"uiAmountString"`
}

type SolanaTokenSupplyResult struct {
	Value SolanaTokenAmount `json:"value"`
}

type SolanaLargestTokenAccount struct {
	Address string `json:"address"`
	SolanaTokenAmount
}

type SolanaLargestAccountsResult struct {
	Value []SolanaLargestTokenAccount `json:"value"`
}

type SolanaAccountInfoResult struct {
	Value *SolanaAccountInfo `json:"value"`
}

type SolanaAccountInfo struct {
	Data       any    `json:"data"`
	Executable bool   `json:"executable"`
	Lamports   int64  `json:"lamports"`
	Owner      string `json:"owner"`
	RentEpoch  any    `json:"rentEpoch"`
	Space      int64  `json:"space"`
}

type SolanaTransactionResult map[string]any

type solanaRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

type solanaRPCResponse[T any] struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  T               `json:"result"`
	Error   *solanaRPCError `json:"error"`
}

type solanaRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

var ErrSolanaTargetNotTokenMint = errors.New("solana target is not a token mint")

type solanaMintValidationEntry struct {
	IsMint    bool
	ExpiresAt time.Time
}

type solanaLargestAccountsCacheEntry struct {
	Result    SolanaLargestAccountsResult
	Err       error
	ExpiresAt time.Time
}

var solanaMintValidationCache = struct {
	sync.RWMutex
	Items map[string]solanaMintValidationEntry
}{Items: map[string]solanaMintValidationEntry{}}

var solanaLargestAccountsCache = struct {
	sync.RWMutex
	Items map[string]solanaLargestAccountsCacheEntry
}{Items: map[string]solanaLargestAccountsCacheEntry{}}

var solanaRPCRateLimiter = struct {
	sync.Mutex
	Next time.Time
}{}

var solanaRPCClient = &http.Client{Timeout: 12 * time.Second}

func SolanaGetSignaturesForAddress(ctx context.Context, rpcURL string, address string, limit int) ([]SolanaSignatureInfo, error) {
	rpcURL = strings.TrimSpace(rpcURL)
	address = strings.TrimSpace(address)
	if rpcURL == "" {
		return nil, fmt.Errorf("solana rpc url is empty")
	}
	if address == "" {
		return nil, fmt.Errorf("solana address is empty")
	}
	if limit <= 0 || limit > 1000 {
		limit = 10
	}
	return solanaRPCDo[[]SolanaSignatureInfo](ctx, rpcURL, "getSignaturesForAddress", []any{address, map[string]any{"limit": limit}})
}

func SolanaGetTokenSupply(ctx context.Context, rpcURL string, mint string) (SolanaTokenSupplyResult, error) {
	rpcURL = strings.TrimSpace(rpcURL)
	mint = strings.TrimSpace(mint)
	if err := ensureSolanaTokenMint(ctx, rpcURL, mint); err != nil {
		return SolanaTokenSupplyResult{}, err
	}
	return solanaRPCDo[SolanaTokenSupplyResult](ctx, rpcURL, "getTokenSupply", []any{mint})
}

func SolanaGetTokenLargestAccounts(ctx context.Context, rpcURL string, mint string) (SolanaLargestAccountsResult, error) {
	rpcURL = strings.TrimSpace(rpcURL)
	mint = strings.TrimSpace(mint)
	if err := ensureSolanaTokenMint(ctx, rpcURL, mint); err != nil {
		return SolanaLargestAccountsResult{}, err
	}
	key := solanaRPCCacheKey(rpcURL, mint)
	if cached, ok := cachedSolanaLargestAccounts(key); ok {
		return cached.Result, cached.Err
	}
	result, err := solanaRPCDo[SolanaLargestAccountsResult](ctx, rpcURL, "getTokenLargestAccounts", []any{mint})
	if err == nil {
		cacheSolanaLargestAccounts(key, result, nil, 2*time.Minute)
		return result, nil
	}
	if strings.Contains(err.Error(), "-32012") || strings.Contains(strings.ToLower(err.Error()), "scan aborted") {
		localErr := fmt.Errorf("getTokenLargestAccounts temporarily skipped after provider scan limit: %w", err)
		cacheSolanaLargestAccounts(key, SolanaLargestAccountsResult{}, localErr, 5*time.Minute)
		return SolanaLargestAccountsResult{}, localErr
	}
	return SolanaLargestAccountsResult{}, err
}

func SolanaGetAccountInfoJSONParsed(ctx context.Context, rpcURL string, address string) (SolanaAccountInfoResult, error) {
	rpcURL = strings.TrimSpace(rpcURL)
	address = strings.TrimSpace(address)
	result, err := solanaRPCDo[SolanaAccountInfoResult](ctx, rpcURL, "getAccountInfo", []any{address, map[string]any{"encoding": "jsonParsed"}})
	if err == nil {
		cacheSolanaMintValidation(rpcURL, address, result)
	}
	return result, err
}

func SolanaGetTransactionJSONParsed(ctx context.Context, rpcURL string, signature string) (SolanaTransactionResult, error) {
	return solanaGetTransactionJSONParsedSingleflight(ctx, rpcURL, signature)
}

func ensureSolanaTokenMint(ctx context.Context, rpcURL, address string) error {
	rpcURL = strings.TrimSpace(rpcURL)
	address = strings.TrimSpace(address)
	if rpcURL == "" {
		return fmt.Errorf("solana rpc url is empty")
	}
	if address == "" {
		return fmt.Errorf("solana token mint is empty")
	}
	key := solanaRPCCacheKey(rpcURL, address)
	if isMint, ok := cachedSolanaMintValidation(key); ok {
		if isMint {
			return nil
		}
		return fmt.Errorf("%w: %s", ErrSolanaTargetNotTokenMint, address)
	}
	account, err := SolanaGetAccountInfoJSONParsed(ctx, rpcURL, address)
	if err != nil {
		return err
	}
	if account.Value == nil || !isParsedSolanaMint(account.Value.Data) {
		return fmt.Errorf("%w: %s", ErrSolanaTargetNotTokenMint, address)
	}
	return nil
}

func cacheSolanaMintValidation(rpcURL, address string, result SolanaAccountInfoResult) {
	key := solanaRPCCacheKey(rpcURL, address)
	if key == "|" {
		return
	}
	isMint := result.Value != nil && isParsedSolanaMint(result.Value.Data)
	ttl := 5 * time.Minute
	if !isMint {
		ttl = 30 * time.Second
	}
	solanaMintValidationCache.Lock()
	solanaMintValidationCache.Items[key] = solanaMintValidationEntry{IsMint: isMint, ExpiresAt: time.Now().Add(ttl)}
	solanaMintValidationCache.Unlock()
}

func cachedSolanaMintValidation(key string) (bool, bool) {
	solanaMintValidationCache.RLock()
	entry, ok := solanaMintValidationCache.Items[key]
	solanaMintValidationCache.RUnlock()
	if !ok {
		return false, false
	}
	if time.Now().After(entry.ExpiresAt) {
		solanaMintValidationCache.Lock()
		delete(solanaMintValidationCache.Items, key)
		solanaMintValidationCache.Unlock()
		return false, false
	}
	return entry.IsMint, true
}

func isParsedSolanaMint(raw any) bool {
	data, ok := raw.(map[string]any)
	if !ok {
		return false
	}
	parsed, ok := data["parsed"].(map[string]any)
	if !ok {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(anyString(parsed["type"])), "mint")
}

func solanaRPCCacheKey(rpcURL, address string) string {
	return strings.TrimSpace(rpcURL) + "|" + strings.TrimSpace(address)
}

func cachedSolanaLargestAccounts(key string) (SolanaLargestAccountsResult, bool) {
	solanaLargestAccountsCache.RLock()
	entry, ok := solanaLargestAccountsCache.Items[key]
	solanaLargestAccountsCache.RUnlock()
	if !ok {
		return SolanaLargestAccountsResult{}, false
	}
	if time.Now().After(entry.ExpiresAt) {
		solanaLargestAccountsCache.Lock()
		delete(solanaLargestAccountsCache.Items, key)
		solanaLargestAccountsCache.Unlock()
		return SolanaLargestAccountsResult{}, false
	}
	return entry.Result, true
}

func cacheSolanaLargestAccounts(key string, result SolanaLargestAccountsResult, err error, ttl time.Duration) {
	if key == "|" || ttl <= 0 {
		return
	}
	solanaLargestAccountsCache.Lock()
	solanaLargestAccountsCache.Items[key] = solanaLargestAccountsCacheEntry{Result: result, Err: err, ExpiresAt: time.Now().Add(ttl)}
	solanaLargestAccountsCache.Unlock()
}

func resetSolanaRPCCachesForTest() {
	solanaMintValidationCache.Lock()
	solanaMintValidationCache.Items = map[string]solanaMintValidationEntry{}
	solanaMintValidationCache.Unlock()
	solanaLargestAccountsCache.Lock()
	solanaLargestAccountsCache.Items = map[string]solanaLargestAccountsCacheEntry{}
	solanaLargestAccountsCache.Unlock()
	solanaRPCRateLimiter.Lock()
	solanaRPCRateLimiter.Next = time.Time{}
	solanaRPCRateLimiter.Unlock()
}

func isParsedSolanaTokenAccount(raw any) bool {
	data, ok := raw.(map[string]any)
	if !ok {
		return false
	}
	parsed, ok := data["parsed"].(map[string]any)
	if !ok {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(anyString(parsed["type"])), "account")
}

func solanaRPCDo[T any](ctx context.Context, rpcURL, method string, params any) (T, error) {
	var zero T
	if strings.TrimSpace(rpcURL) == "" {
		return zero, fmt.Errorf("solana rpc url is empty")
	}
	if err := reserveSolanaRPCBudget(ctx, method); err != nil {
		web3.LogRPCFailure(method, rpcURL, 0, err)
		return zero, err
	}
	payload, err := json.Marshal(solanaRPCRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	if err != nil {
		web3.LogRPCFailure(method, rpcURL, 0, err)
		return zero, err
	}
	maxRetries := solanaRPCMax429Retries()
	for attempt := 0; ; attempt++ {
		if err := waitForSolanaRPCSlot(ctx); err != nil {
			web3.LogRPCFailure(method, rpcURL, 0, err)
			return zero, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, rpcURL, bytes.NewReader(payload))
		if err != nil {
			web3.LogRPCFailure(method, rpcURL, 0, err)
			return zero, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Koschei-RPC-Method", method)
		res, err := solanaRPCClient.Do(req)
		if err != nil {
			return zero, err
		}
		body, readErr := io.ReadAll(io.LimitReader(res.Body, 8<<20))
		res.Body.Close()
		actualEndpoint := rpcURL
		if res.Request != nil && res.Request.URL != nil {
			actualEndpoint = res.Request.URL.String()
		}
		if readErr != nil {
			web3.LogRPCFailure(method, actualEndpoint, res.StatusCode, readErr)
			return zero, readErr
		}
		if res.StatusCode == http.StatusTooManyRequests {
			delay := maxDuration(solanaRPC429Delay(attempt, res.Header.Get("Retry-After")), solanaRPC429Cooldown())
			deferSolanaRPCRequests(delay)
			if attempt < maxRetries {
				continue
			}
			return zero, fmt.Errorf("solana rpc http status %d: %s", res.StatusCode, compactSolanaBatchBody(body))
		}
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return zero, fmt.Errorf("solana rpc http status %d: %s", res.StatusCode, compactSolanaBatchBody(body))
		}
		var decoded solanaRPCResponse[T]
		if err := json.Unmarshal(body, &decoded); err != nil {
			wrapped := fmt.Errorf("decode solana rpc response: %w", err)
			web3.LogRPCFailure(method, actualEndpoint, res.StatusCode, wrapped)
			return zero, wrapped
		}
		if decoded.Error != nil {
			wrapped := fmt.Errorf("solana rpc error %d: %s", decoded.Error.Code, decoded.Error.Message)
			web3.LogRPCFailure(method, actualEndpoint, res.StatusCode, wrapped)
			return zero, wrapped
		}
		return decoded.Result, nil
	}
}

func waitForSolanaRPCSlot(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	interval := solanaRPCMinInterval()
	if interval <= 0 {
		return ctx.Err()
	}
	solanaRPCRateLimiter.Lock()
	now := time.Now()
	waitUntil := solanaRPCRateLimiter.Next
	if waitUntil.Before(now) {
		waitUntil = now
	}
	solanaRPCRateLimiter.Next = waitUntil.Add(interval)
	solanaRPCRateLimiter.Unlock()
	if wait := time.Until(waitUntil); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	return ctx.Err()
}

func solanaRPCMinInterval() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("SOLANA_RPC_MIN_INTERVAL_MS")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value >= 0 && value <= 5000 {
			return time.Duration(value) * time.Millisecond
		}
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("APP_ENV")), "production") {
		return 500 * time.Millisecond
	}
	return 0
}

func solanaRPC429Cooldown() time.Duration {
	seconds := 60
	if raw := strings.TrimSpace(os.Getenv("SOLANA_RPC_429_COOLDOWN_SECONDS")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value >= 1 && value <= 3600 {
			seconds = value
		}
	}
	return time.Duration(seconds) * time.Second
}

func solanaRPC429Delay(attempt int, retryAfter string) time.Duration {
	if seconds, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	delay := 750 * time.Millisecond
	for i := 0; i < attempt && delay < 4*time.Second; i++ {
		delay *= 2
	}
	if delay > 4*time.Second {
		delay = 4 * time.Second
	}
	return delay
}

func solanaRPCMax429Retries() int {
	fallback := 0
	if strings.EqualFold(strings.TrimSpace(os.Getenv("APP_ENV")), "production") {
		fallback = 1
	}
	if raw := strings.TrimSpace(os.Getenv("SOLANA_RPC_MAX_429_RETRIES")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value >= 0 && value <= 4 {
			return value
		}
	}
	return fallback
}
