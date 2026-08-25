package web3

import (
	"context"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const guardedSolanaSignatureMethod = "getSignaturesForAddress"

var solanaRPCSignaturePressure = struct {
	sync.Mutex
	cooldowns map[string]time.Time
	gate      chan struct{}
}{
	cooldowns: map[string]time.Time{},
	gate:      make(chan struct{}, 1),
}

func solanaRPCSignaturePressureEnabled(method string) bool {
	if !strings.EqualFold(strings.TrimSpace(method), guardedSolanaSignatureMethod) {
		return false
	}
	if raw := strings.TrimSpace(os.Getenv("SOLANA_RPC_SIGNATURE_GUARD_ENABLED")); raw != "" {
		enabled, err := strconv.ParseBool(raw)
		if err == nil {
			return enabled
		}
	}
	return strings.EqualFold(strings.TrimSpace(os.Getenv("APP_ENV")), "production")
}

func acquireSolanaRPCSignaturePressure(ctx context.Context) error {
	select {
	case solanaRPCSignaturePressure.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func releaseSolanaRPCSignaturePressure() {
	select {
	case <-solanaRPCSignaturePressure.gate:
	default:
	}
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

func solanaRPCSignature429Cooldown(retryAfter string) time.Duration {
	delay := solanaRPC429Cooldown(retryAfter)
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
