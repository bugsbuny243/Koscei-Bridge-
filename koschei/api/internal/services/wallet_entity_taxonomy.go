package services

import "strings"

const (
	WalletEntityKindUnknown     = "UNKNOWN"
	WalletEntityKindKnown       = "KNOWN_ENTITY"
	WalletEntityKindCEX         = "CEX"
	WalletEntityKindDEX         = "DEX"
	WalletEntityKindBridge      = "BRIDGE"
	WalletEntityKindMixer       = "MIXER"
	WalletEntityKindDrainer     = "DRAINER"
	WalletEntityKindProtocol    = "PROTOCOL"
	WalletEntityRiskSuspicious  = "SUSPICIOUS"
)

// WalletEntityClassification is a normalized projection of positively-resolved
// provider taxonomy. It never infers identity or activity type from transfer
// behavior alone. MatchedTaxonomy contains the provider values that supported
// the classification so downstream evidence can explain why a label was used.
type WalletEntityClassification struct {
	Kind            string   `json:"kind"`
	RiskFlag        string   `json:"risk_flag,omitempty"`
	MatchedTaxonomy []string `json:"matched_taxonomy,omitempty"`
	Source          string   `json:"source,omitempty"`
}

func ClassifyWalletLabel(label *WalletLabel) WalletEntityClassification {
	out := WalletEntityClassification{Kind: WalletEntityKindUnknown}
	if label == nil {
		return out
	}
	out.Kind = WalletEntityKindKnown
	out.Source = strings.TrimSpace(label.Source)
	values := walletEntityTaxonomyValues(label)

	if matched := walletEntityMatchedTaxonomy(values, []string{"drainer", "wallet drainer", "drain service"}); len(matched) > 0 {
		out.Kind = WalletEntityKindDrainer
		out.RiskFlag = "DRAINER"
		out.MatchedTaxonomy = matched
		return out
	}
	if matched := walletEntityMatchedTaxonomy(values, []string{"mixer", "tumbler", "coinjoin", "tornado cash"}); len(matched) > 0 {
		out.Kind = WalletEntityKindMixer
		out.RiskFlag = "MIXER"
		out.MatchedTaxonomy = matched
		return out
	}
	if matched := walletEntityMatchedTaxonomy(values, []string{"cex", "centralized exchange", "centralised exchange", "exchange deposit", "exchange hot wallet", "exchange cold wallet"}); len(matched) > 0 {
		out.Kind = WalletEntityKindCEX
		out.MatchedTaxonomy = matched
	} else if walletEntityKnownCEX(label.Entity) || walletEntityKnownCEX(label.Name) {
		out.Kind = WalletEntityKindCEX
		out.MatchedTaxonomy = []string{"provider_entity:" + firstNonEmptyWalletEntityValue(label.Entity, label.Name)}
	} else if matched := walletEntityMatchedTaxonomy(values, []string{"decentralized exchange", "decentralised exchange", "dex", "automated market maker", "amm"}); len(matched) > 0 {
		out.Kind = WalletEntityKindDEX
		out.MatchedTaxonomy = matched
	} else if matched := walletEntityMatchedTaxonomy(values, []string{"cross chain bridge", "cross-chain bridge", "crosschain bridge", "token bridge", "bridge protocol", "bridge"}); len(matched) > 0 {
		out.Kind = WalletEntityKindBridge
		out.MatchedTaxonomy = matched
	} else if matched := walletEntityMatchedTaxonomy(values, []string{"defi protocol", "protocol treasury", "protocol"}); len(matched) > 0 {
		out.Kind = WalletEntityKindProtocol
		out.MatchedTaxonomy = matched
	}

	if matched := walletEntityMatchedTaxonomy(values, []string{
		"suspicious", "scam", "phishing", "malicious", "exploit", "exploiter",
		"hacker", "fraud", "sanctioned", "stolen funds", "illicit",
	}); len(matched) > 0 {
		out.RiskFlag = WalletEntityRiskSuspicious
		if len(out.MatchedTaxonomy) == 0 {
			out.MatchedTaxonomy = matched
		} else {
			out.MatchedTaxonomy = appendUniqueWalletEntityTaxonomy(out.MatchedTaxonomy, matched...)
		}
	}
	return out
}

func walletEntityTaxonomyValues(label *WalletLabel) []string {
	if label == nil {
		return nil
	}
	out := []string{label.Category}
	out = append(out, label.Labels...)
	out = append(out, label.Tags...)
	return out
}

func walletEntityMatchedTaxonomy(values, candidates []string) []string {
	matched := []string{}
	for _, raw := range values {
		normalized := normalizeWalletEntityTaxonomy(raw)
		if normalized == "" {
			continue
		}
		for _, candidate := range candidates {
			candidate = normalizeWalletEntityTaxonomy(candidate)
			if normalized == candidate || strings.Contains(" "+normalized+" ", " "+candidate+" ") {
				matched = appendUniqueWalletEntityTaxonomy(matched, strings.TrimSpace(raw))
				break
			}
		}
	}
	return matched
}

func normalizeWalletEntityTaxonomy(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer("_", " ", "-", " ", "/", " ", ".", " ", ":", " ")
	return strings.Join(strings.Fields(replacer.Replace(value)), " ")
}

func walletEntityKnownCEX(value string) bool {
	normalized := normalizeWalletEntityTaxonomy(value)
	known := map[string]bool{
		"binance": true, "coinbase": true, "okx": true, "kraken": true,
		"bybit": true, "kucoin": true, "mexc": true, "bitget": true,
		"gate io": true, "crypto com": true, "htx": true, "upbit": true,
		"bithumb": true, "gemini": true,
	}
	return known[normalized]
}

func appendUniqueWalletEntityTaxonomy(values []string, candidates ...string) []string {
	seen := make(map[string]bool, len(values)+len(candidates))
	for _, value := range values {
		seen[value] = true
	}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || seen[candidate] {
			continue
		}
		seen[candidate] = true
		values = append(values, candidate)
	}
	return values
}

func firstNonEmptyWalletEntityValue(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return "known_cex"
}
