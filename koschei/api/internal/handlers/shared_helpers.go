package handlers

import (
	"crypto/rand"
	"fmt"
	"os"
	"strings"

	"koschei/api/internal/web3"
)

// solanaRPCURL is intentionally provider-neutral. Handler collectors must use
// the same canonical transport resolver as the rest of Koschei so an explicit
// SOLANA_RPC_URL (including a future Koschei-owned RPC) wins without detector
// changes. The legacy apiKey argument remains only as a compatibility fallback
// for deployments that have not migrated away from ALCHEMY_API_KEY yet.
func solanaRPCURL(network string, apiKey string) string {
	return web3.SolanaRPCURL(network, strings.TrimSpace(apiKey))
}

func aiProviderConfigured() bool {
	return strings.TrimSpace(os.Getenv("OPENAI_API_KEY")) != "" ||
		strings.TrimSpace(os.Getenv("TOGETHER_API_KEY")) != ""
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// normalizePackageID is retained as a narrow compatibility name for stored
// plan aliases and older callers. The canonical authority is the SaaS plan
// vocabulary, not a package/payment product catalog.
func normalizePackageID(value string) string {
	return canonicalSaaSPlan(value)
}

func normalizePlanTier(planTier string) string {
	return canonicalSaaSPlan(planTier)
}
