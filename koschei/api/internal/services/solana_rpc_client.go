package services

import (
	"bytes"
	"context"
	"crypto/sha256"
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

	"koschei/api/internal/singleflight"
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

var solanaTransactionSingleflight singleflight.Group

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
	rpcURL = strings.TrimSpace(rpcURL)
	signature = strings.TrimSpace(signature)
	key := solanaTransactionSingleflightKey(rpcURL, signature)
	value, err, _ := solanaTransactionSingleflight.DoContext(ctx, key, func() (interface{}, error) {
		result, err := solanaRPCDo[SolanaTransactionResult](ctx, rpcURL, "getTransaction", []any{signature, map[string]any{"encoding": "jsonParsed", "commitment": "confirmed", "maxSupportedTransactionVersion": 0}})
		if err != nil {
			return nil, err
		}
		if result == nil {
			return []byte(nil), nil
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("solana getTransaction canonical encode: %w", err)
		}
		return encoded, nil
	})
	if err != nil {
		return nil, err
	}
	encoded, ok := value.([]byte)
	if !ok {
		return nil, fmt.Errorf("solana getTransaction singleflight returned unexpected payload type")
	}
	if len(encoded) == 0 {
		return nil, nil
	}
	var result SolanaTransactionResult
	if err := json.Unmarshal(encoded, &result); err != nil {
		return nil, fmt.Errorf("solana getTransaction canonical decode: %w", err)
	}
	return result, nil
}

func solanaTransactionSingleflightKey(rpcURL, signature string) string {
	digest := sha256.Sum256([]byte("solana:getTransaction:jsonParsed:confirmed:v0|" + strings.TrimSpace(rpcURL) + "|" + strings.TrimSpace(signature)))
	return fmt.Sprintf("%x", digest[:])
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

func cachedSolanaLargestAccounts(key string) (solanaLargestAccountsCacheEntry, bool) {
	solanaLargestAccountsCache.RLock()
	entry, ok := solanaLargestAccountsCache.Items[key]
	solanaLargestAccountsCache.RUnlock()
	if !ok {
		return solanaLargestAccountsCacheEntry{}, false
	}
	if time.Now().After(entry.ExpiresAt) {
		solanaLargestAccountsCache.Lock()
		delete(solanaLargestAccountsCache.Items, key)
		solanaLargestAccountsCache.Unlock()
		return solanaLargestAccountsCacheEntry{}, false
	}
	return entry, true
}

func cacheSolanaLargestAccounts(key string, result SolanaLargestAccountsResult, err error, ttl time.Duration) {
	solanaLargestAccountsCache.Lock()
	solanaLargestAccountsCache.Items[key] = solanaLargestAccountsCacheEntry{Result: result, Err: err, ExpiresAt: time.Now().Add(ttl)}
	solanaLargestAccountsCache.Unlock()
}

func solanaRPCCacheKey(rpcURL, address string) string {
	return strings.TrimSpace(rpcURL) + "|" + strings.TrimSpace(address)
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
	solanaTransactionSingleflight = singleflight.Group{}
	resetSolanaRPCBudgetForTest()
}

func solanaRPCDo[T any](ctx context.Context, rpcURL, method string, params any) (T, error) {
	var zero T
	rpcURL = strings.TrimSpace(rpcURL)
	if rpcURL == "" {
		return zero, fmt.Errorf("solana rpc url is empty")
	}
	payload, err := json.Marshal(solanaRPCRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	if err != nil {
		web3.LogRPCFailure(method, rpcURL, 0, err)
		return zero, err
	}

	maxRetries := solanaRPCMax429Retries()
	for attempt := 0; ; attempt++ {
		if err := reserveSolanaRPCBudget(ctx, method); err != nil {
			web3.LogRPCFailure(method, rpcURL, 0, err)
			return zero, err
		}
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
			return zero, fmt.Errorf("solana rpc http status %d: %s", res.StatusCode, string(body))
		}
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return zero, fmt.Errorf("solana rpc http status %d: %s", res.StatusCode, string(body))
		}

		var out solanaRPCResponse[T]
		if err := json.Unmarshal(body, &out); err != nil {
			wrapped := fmt.Errorf("solana rpc malformed response: %w", err)
			web3.LogRPCFailure(method, actualEndpoint, res.StatusCode, wrapped)
			return zero, wrapped
		}
		if out.Error != nil && out.Error.Code == http.StatusTooManyRequests {
			rpcErr := fmt.Errorf("solana rpc error %d: %s", out.Error.Code, out.Error.Message)
			web3.LogRPCFailure(method, actualEndpoint, res.StatusCode, rpcErr)
			delay := maxDuration(solanaRPC429Delay(attempt, ""), solanaRPC429Cooldown())
			deferSolanaRPCRequests(delay)
			if attempt < maxRetries {
				continue
			}
		}
		if out.Error != nil {
			err := fmt.Errorf("solana rpc error %d: %s", out.Error.Code, out.Error.Message)
			if out.Error.Code != http.StatusTooManyRequests {
				web3.LogRPCFailure(method, actualEndpoint, res.StatusCode, err)
			}
			return zero, err
		}
		return out.Result, nil
	}
}

func waitForSolanaRPCSlot(ctx context.Context) error {
	interval := solanaRPCMinInterval()
	for {
		now := time.Now()
		solanaRPCRateLimiter.Lock()
		next := solanaRPCRateLimiter.Next
		if !next.After(now) {
			solanaRPCRateLimiter.Next = now.Add(interval)
			solanaRPCRateLimiter.Unlock()
			return nil
		}
		delay := time.Until(next)
		solanaRPCRateLimiter.Unlock()
		if err := waitForSolanaRPCRetry(ctx, delay); err != nil {
			return err
		}
	}
}

func deferSolanaRPCRequests(delay time.Duration) {
	if delay <= 0 {
		return
	}
	until := time.Now().Add(delay)
	solanaRPCRateLimiter.Lock()
	if until.After(solanaRPCRateLimiter.Next) {
		solanaRPCRateLimiter.Next = until
	}
	solanaRPCRateLimiter.Unlock()
}

func waitForSolanaRPCRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
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

func solanaRPCMax429Retries() int {
	if raw := strings.TrimSpace(os.Getenv("SOLANA_RPC_MAX_429_RETRIES")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value >= 0 && value <= 5 {
			return value
		}
	}
	return 2
}

func solanaRPC429Delay(attempt int, retryAfter string) time.Duration {
	retryAfter = strings.TrimSpace(retryAfter)
	if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(retryAfter); err == nil {
		if delay := time.Until(when); delay > 0 {
			return delay
		}
	}
	base := 1000
	if raw := strings.TrimSpace(os.Getenv("SOLANA_RPC_429_BACKOFF_MS")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value >= 0 && value <= 10000 {
			base = value
		}
	}
	if attempt < 0 {
		attempt = 0
	}
	if attempt > 4 {
		attempt = 4
	}
	return time.Duration(base*(1<<attempt)) * time.Millisecond
}

func solanaTokenFloat(amount SolanaTokenAmount) float64 {
	if amount.UIAmount != nil {
		return *amount.UIAmount
	}
	if strings.TrimSpace(amount.UIAmountString) != "" {
		if value, err := strconv.ParseFloat(strings.TrimSpace(amount.UIAmountString), 64); err == nil {
			return value
		}
	}
	if strings.TrimSpace(amount.Amount) == "" {
		return 0
	}
	raw, err := strconv.ParseFloat(strings.TrimSpace(amount.Amount), 64)
	if err != nil {
		return 0
	}
	if amount.Decimals <= 0 {
		return raw
	}
	divisor := 1.0
	for i := 0; i < amount.Decimals; i++ {
		divisor *= 10
	}
	if divisor <= 0 {
		return raw
	}
	return raw / divisor
}
