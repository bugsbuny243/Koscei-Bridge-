package services

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"koschei/api/internal/web3"
)

const guardedSolanaSignatureMethod = "getSignaturesForAddress"

type solanaRPCSignaturePressureTransport struct {
	base http.RoundTripper
}

var solanaRPCSignaturePressure = struct {
	sync.Mutex
	cooldowns map[string]time.Time
	gate      chan struct{}
}{
	cooldowns: map[string]time.Time{},
	gate:      make(chan struct{}, 1),
}

func init() {
	base := solanaRPCClient.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	solanaRPCClient.Transport = &solanaRPCSignaturePressureTransport{base: base}
}

func (t *solanaRPCSignaturePressureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil || t.base == nil {
		return nil, fmt.Errorf("solana rpc transport unavailable")
	}
	if !solanaRPCSignaturePressureGuardEnabled(req) {
		return t.base.RoundTrip(req)
	}
	if err := acquireSolanaRPCSignatureGate(req.Context()); err != nil {
		return nil, err
	}
	defer releaseSolanaRPCSignatureGate()

	primary := req.URL.String()
	fallback := strings.TrimSpace(web3.SolanaRPCFallbackURL("solana-mainnet"))
	if sameSolanaRPCEndpoint(primary, fallback) {
		fallback = ""
	}

	if _, cooling := solanaRPCSignatureEndpointCooldown(primary); cooling {
		if fallback == "" {
			return nil, fmt.Errorf("solana signature rpc primary cooling down")
		}
		if _, fallbackCooling := solanaRPCSignatureEndpointCooldown(fallback); fallbackCooling {
			return nil, fmt.Errorf("solana signature rpc providers cooling down")
		}
		fallbackResponse, fallbackErr := t.roundTripEndpoint(req, fallback, 0)
		if fallbackResponse != nil && fallbackResponse.StatusCode == http.StatusTooManyRequests {
			deferSolanaRPCSignatureEndpoint(fallback, solanaRPCSignatureCooldown(fallbackResponse.Header.Get("Retry-After")))
		}
		return fallbackResponse, fallbackErr
	}

	primaryTimeout := solanaRPCSignaturePrimaryTimeout(req.Context())
	response, err := t.roundTripEndpoint(req, primary, primaryTimeout)
	if err == nil && response != nil && response.StatusCode != http.StatusTooManyRequests {
		return response, nil
	}

	if response != nil && response.StatusCode == http.StatusTooManyRequests {
		deferSolanaRPCSignatureEndpoint(primary, solanaRPCSignatureCooldown(response.Header.Get("Retry-After")))
		if fallback == "" {
			return response, nil
		}
		drainAndCloseSolanaRPCResponse(response)
	} else if err != nil {
		if req.Context().Err() != nil {
			return nil, req.Context().Err()
		}
		deferSolanaRPCSignatureEndpoint(primary, solanaRPCSignatureTimeoutCooldown())
		if fallback == "" {
			return nil, err
		}
	}

	if _, cooling := solanaRPCSignatureEndpointCooldown(fallback); cooling {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("solana signature rpc fallback cooling down")
	}
	fallbackResponse, fallbackErr := t.roundTripEndpoint(req, fallback, 0)
	if fallbackResponse != nil && fallbackResponse.StatusCode == http.StatusTooManyRequests {
		deferSolanaRPCSignatureEndpoint(fallback, solanaRPCSignatureCooldown(fallbackResponse.Header.Get("Retry-After")))
	}
	return fallbackResponse, fallbackErr
}

func (t *solanaRPCSignaturePressureTransport) roundTripEndpoint(req *http.Request, endpoint string, timeout time.Duration) (*http.Response, error) {
	attemptCtx := req.Context()
	cancel := func() {}
	if timeout > 0 {
		attemptCtx, cancel = context.WithTimeout(req.Context(), timeout)
	}
	defer cancel()

	clone, err := cloneSolanaRPCRequestForEndpoint(req, endpoint, attemptCtx)
	if err != nil {
		return nil, err
	}
	return t.base.RoundTrip(clone)
}

func cloneSolanaRPCRequestForEndpoint(req *http.Request, endpoint string, ctx context.Context) (*http.Request, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid solana rpc endpoint")
	}
	clone := req.Clone(ctx)
	clone.URL = parsed
	clone.Host = ""
	if req.Body != nil {
		if req.GetBody == nil {
			return nil, fmt.Errorf("solana rpc request body cannot be replayed")
		}
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		clone.Body = body
	}
	return clone, nil
}

func solanaRPCSignaturePressureGuardEnabled(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("APP_ENV")), "production") {
		return false
	}
	if raw := strings.TrimSpace(os.Getenv("SOLANA_RPC_SIGNATURE_GUARD_ENABLED")); raw != "" {
		enabled, err := strconv.ParseBool(raw)
		if err == nil && !enabled {
			return false
		}
	}
	return strings.EqualFold(strings.TrimSpace(req.Header.Get("X-Koschei-RPC-Method")), guardedSolanaSignatureMethod)
}

func acquireSolanaRPCSignatureGate(ctx context.Context) error {
	select {
	case solanaRPCSignaturePressure.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func releaseSolanaRPCSignatureGate() {
	select {
	case <-solanaRPCSignaturePressure.gate:
	default:
	}
}

func solanaRPCSignaturePrimaryTimeout(ctx context.Context) time.Duration {
	timeout := 3 * time.Second
	if raw := strings.TrimSpace(os.Getenv("SOLANA_RPC_SIGNATURE_PRIMARY_TIMEOUT_MS")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value >= 50 && value <= 5000 {
			timeout = time.Duration(value) * time.Millisecond
		}
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0
		}
		fairShare := remaining / 2
		if fairShare > 0 && fairShare < timeout {
			timeout = fairShare
		}
	}
	return timeout
}

func solanaRPCSignatureCooldown(retryAfter string) time.Duration {
	delay := maxDuration(solanaRPC429Delay(0, retryAfter), solanaRPC429Cooldown())
	if strings.EqualFold(strings.TrimSpace(os.Getenv("APP_ENV")), "production") && delay < 5*time.Minute {
		delay = 5 * time.Minute
	}
	return delay
}

func solanaRPCSignatureTimeoutCooldown() time.Duration {
	seconds := 15
	if raw := strings.TrimSpace(os.Getenv("SOLANA_RPC_TIMEOUT_COOLDOWN_SECONDS")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value >= 1 && value <= 300 {
			seconds = value
		}
	}
	return time.Duration(seconds) * time.Second
}

func solanaRPCSignatureEndpointCooldown(endpoint string) (time.Time, bool) {
	key := solanaRPCSignatureEndpointKey(endpoint)
	if key == "" {
		return time.Time{}, false
	}
	now := time.Now()
	solanaRPCSignaturePressure.Lock()
	defer solanaRPCSignaturePressure.Unlock()
	until, ok := solanaRPCSignaturePressure.cooldowns[key]
	if !ok {
		return time.Time{}, false
	}
	if !until.After(now) {
		delete(solanaRPCSignaturePressure.cooldowns, key)
		return time.Time{}, false
	}
	return until, true
}

func deferSolanaRPCSignatureEndpoint(endpoint string, delay time.Duration) {
	key := solanaRPCSignatureEndpointKey(endpoint)
	if key == "" || delay <= 0 {
		return
	}
	until := time.Now().Add(delay)
	solanaRPCSignaturePressure.Lock()
	if current := solanaRPCSignaturePressure.cooldowns[key]; until.After(current) {
		solanaRPCSignaturePressure.cooldowns[key] = until
	}
	solanaRPCSignaturePressure.Unlock()
}

func solanaRPCSignatureEndpointKey(endpoint string) string {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Host == "" {
		return ""
	}
	return strings.ToLower(parsed.Host)
}

func sameSolanaRPCEndpoint(a, b string) bool {
	aKey := solanaRPCSignatureEndpointKey(a)
	bKey := solanaRPCSignatureEndpointKey(b)
	return aKey != "" && aKey == bKey
}

func drainAndCloseSolanaRPCResponse(response *http.Response) {
	if response == nil || response.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	_ = response.Body.Close()
}

func resetSolanaRPCSignaturePressureForTest() {
	solanaRPCSignaturePressure.Lock()
	solanaRPCSignaturePressure.cooldowns = map[string]time.Time{}
	solanaRPCSignaturePressure.Unlock()
	for {
		select {
		case <-solanaRPCSignaturePressure.gate:
		default:
			return
		}
	}
}
