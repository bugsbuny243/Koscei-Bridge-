package services

import (
	"os"
	"strings"
)

// providerFromSolanaRPCURL classifies provenance from the endpoint that was
// actually used/configured. Unknown/private endpoints deliberately collapse to
// solana_rpc instead of being mislabeled as a commercial provider.
func providerFromSolanaRPCURL(raw string) string {
	rpcURL := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.Contains(rpcURL, "alchemy"):
		return "alchemy"
	case strings.Contains(rpcURL, "helius"):
		return "helius"
	case strings.Contains(rpcURL, "quicknode"):
		return "quicknode"
	case strings.Contains(rpcURL, "triton"):
		return "triton"
	case rpcURL != "":
		return "solana_rpc"
	default:
		return "unconfigured"
	}
}

func resolvedArvisProvider() string {
	return providerFromSolanaRPCURL(os.Getenv("SOLANA_RPC_URL"))
}

func applyResolvedArvisProvider(bundle SecurityRadarBundle) SecurityRadarBundle {
	rpcProvider := resolvedArvisProvider()
	arms := ArvisArmsFromBundle(bundle)
	hasOnchain := false
	hasOffchain := false
	for _, arm := range arms {
		if arm.Signals == nil {
			continue
		}
		if value, _ := arm.Signals["real_onchain_evidence"].(bool); value && arm.Signed {
			hasOnchain = true
		}
		if value, _ := arm.Signals["real_offchain_evidence"].(bool); value && arm.Signed {
			hasOffchain = true
		}
	}

	provider := rpcProvider
	switch {
	case hasOnchain && hasOffchain:
		provider = "hybrid:" + rpcProvider + "+url_parser"
	case hasOffchain:
		provider = "url_parser"
	case hasOnchain:
		provider = rpcProvider
	}
	bundle.Provider = provider
	if bundle.Metadata == nil {
		bundle.Metadata = map[string]any{}
	}
	bundle.Metadata["provider"] = provider
	bundle.Metadata["rpc_provider"] = rpcProvider
	bundle.Metadata["has_onchain_evidence"] = hasOnchain
	bundle.Metadata["has_offchain_evidence"] = hasOffchain

	if len(arms) > 0 {
		for i := range arms {
			if arms[i].Signals == nil {
				arms[i].Signals = map[string]any{}
			}
			arms[i].Signals["provider"] = providerForArvisArm(arms[i], rpcProvider)
		}
		bundle.Metadata["arvis_arms"] = arms
	}
	bundle.PumpSybilRadar.Signals = withArvisProvider(bundle.PumpSybilRadar.Signals, providerForSignals(bundle.PumpSybilRadar.Signals, rpcProvider))
	bundle.RaydiumPoolGuardian.Signals = withArvisProvider(bundle.RaydiumPoolGuardian.Signals, providerForSignals(bundle.RaydiumPoolGuardian.Signals, rpcProvider))
	bundle.WalletlessClaimShield.Signals = withArvisProvider(bundle.WalletlessClaimShield.Signals, providerForSignals(bundle.WalletlessClaimShield.Signals, rpcProvider))
	return bundle
}

func providerForArvisArm(arm SecurityRadarVerdict, rpcProvider string) string {
	return providerForSignals(arm.Signals, rpcProvider)
}

func providerForSignals(signals map[string]any, rpcProvider string) string {
	if signals == nil {
		return "none"
	}
	onchain, _ := signals["real_onchain_evidence"].(bool)
	offchain, _ := signals["real_offchain_evidence"].(bool)
	switch {
	case onchain && offchain:
		return "hybrid:" + rpcProvider + "+url_parser"
	case offchain:
		return "url_parser"
	case onchain:
		return rpcProvider
	default:
		return "none"
	}
}

func withArvisProvider(signals map[string]any, provider string) map[string]any {
	if signals == nil {
		signals = map[string]any{}
	}
	signals["provider"] = provider
	return signals
}
