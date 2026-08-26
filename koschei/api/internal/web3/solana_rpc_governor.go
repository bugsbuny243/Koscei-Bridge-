package web3

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

type solanaRPCProviderGovernorState struct {
	NextRequestAt time.Time
	CooldownUntil time.Time
}

var solanaRPCProviderGovernor = struct {
	sync.Mutex
	providers map[string]solanaRPCProviderGovernorState
}{providers: map[string]solanaRPCProviderGovernorState{}}

// WaitForSolanaRPCProviderSlot applies one process-wide pacing clock per
// provider host. Every Solana client layer should pass through this gate before
// making an upstream request so independent modules cannot each consume the
// same provider's rate limit as if they were alone.
func WaitForSolanaRPCProviderSlot(ctx context.Context, endpoint string) error {
	key := solanaRPCGovernorProviderKey(endpoint)
	if key == "" {
		return fmt.Errorf("solana rpc governor endpoint is invalid")
	}
	interval := solanaRPCMinInterval()
	for {
		now := time.Now()
		solanaRPCProviderGovernor.Lock()
		state := solanaRPCProviderGovernor.providers[key]
		readyAt := state.NextRequestAt
		if state.CooldownUntil.After(readyAt) {
			readyAt = state.CooldownUntil
		}
		if !readyAt.After(now) {
			state.NextRequestAt = now.Add(interval)
			if !state.CooldownUntil.After(now) {
				state.CooldownUntil = time.Time{}
			}
			solanaRPCProviderGovernor.providers[key] = state
			solanaRPCProviderGovernor.Unlock()
			return nil
		}
		delay := time.Until(readyAt)
		solanaRPCProviderGovernor.Unlock()
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// SolanaRPCProviderCooldown returns the shared cooldown for a provider host.
// It is intentionally host-scoped rather than URL-scoped so clients using
// different API-key paths for the same provider still share pressure state.
func SolanaRPCProviderCooldown(endpoint string) (time.Time, bool) {
	key := solanaRPCGovernorProviderKey(endpoint)
	if key == "" {
		return time.Time{}, false
	}
	now := time.Now()
	solanaRPCProviderGovernor.Lock()
	defer solanaRPCProviderGovernor.Unlock()
	state, ok := solanaRPCProviderGovernor.providers[key]
	if !ok || !state.CooldownUntil.After(now) {
		if ok && !state.NextRequestAt.After(now) {
			delete(solanaRPCProviderGovernor.providers, key)
		}
		return time.Time{}, false
	}
	return state.CooldownUntil, true
}

// DeferSolanaRPCProvider publishes provider pressure to every Solana client in
// this process. A 429 learned by one ARVIS surface therefore prevents another
// surface from immediately retrying the same provider unaware of that signal.
func DeferSolanaRPCProvider(endpoint string, delay time.Duration) {
	key := solanaRPCGovernorProviderKey(endpoint)
	if key == "" || delay <= 0 {
		return
	}
	until := time.Now().Add(delay)
	solanaRPCProviderGovernor.Lock()
	state := solanaRPCProviderGovernor.providers[key]
	if until.After(state.CooldownUntil) {
		state.CooldownUntil = until
	}
	if until.After(state.NextRequestAt) {
		state.NextRequestAt = until
	}
	solanaRPCProviderGovernor.providers[key] = state
	solanaRPCProviderGovernor.Unlock()
}

func solanaRPCGovernorProviderKey(endpoint string) string {
	host := strings.TrimSpace(RPCProviderHost(endpoint))
	if host == "" || host == "unconfigured" || host == "invalid-host" {
		return ""
	}
	return strings.ToLower(host)
}

// ResetSolanaRPCProviderGovernorForTest is exported because the services layer
// also participates in this process-wide state and must be able to isolate its
// package tests without maintaining a second governor implementation.
func ResetSolanaRPCProviderGovernorForTest() {
	solanaRPCProviderGovernor.Lock()
	solanaRPCProviderGovernor.providers = map[string]solanaRPCProviderGovernorState{}
	solanaRPCProviderGovernor.Unlock()
}
