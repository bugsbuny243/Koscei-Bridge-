package services

import "testing"

func TestClassifyWalletLabelFunctionalTaxonomy(t *testing.T) {
	tests := []struct {
		name     string
		label    *WalletLabel
		wantKind string
		wantRisk string
	}{
		{name: "cex", label: &WalletLabel{Category: "Centralized Exchange", Source: "helius_identity"}, wantKind: WalletEntityKindCEX},
		{name: "known cex entity", label: &WalletLabel{Entity: "Binance", Source: "helius_identity"}, wantKind: WalletEntityKindCEX},
		{name: "dex", label: &WalletLabel{Category: "Decentralized Exchange", Source: "helius_identity"}, wantKind: WalletEntityKindDEX},
		{name: "bridge", label: &WalletLabel{Labels: []string{"Cross-chain Bridge"}, Source: "helius_identity"}, wantKind: WalletEntityKindBridge},
		{name: "mixer", label: &WalletLabel{Tags: []string{"Mixer"}, Source: "helius_identity"}, wantKind: WalletEntityKindMixer, wantRisk: "MIXER"},
		{name: "drainer", label: &WalletLabel{Labels: []string{"Wallet Drainer"}, Source: "helius_identity"}, wantKind: WalletEntityKindDrainer, wantRisk: "DRAINER"},
		{name: "protocol", label: &WalletLabel{Category: "DeFi Protocol", Source: "helius_identity"}, wantKind: WalletEntityKindProtocol},
		{name: "known without taxonomy", label: &WalletLabel{Name: "Known Treasury", Source: "helius_identity"}, wantKind: WalletEntityKindKnown},
		{name: "nil", label: nil, wantKind: WalletEntityKindUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := ClassifyWalletLabel(test.label)
			if got.Kind != test.wantKind {
				t.Fatalf("kind=%q want %q", got.Kind, test.wantKind)
			}
			if got.RiskFlag != test.wantRisk {
				t.Fatalf("risk_flag=%q want %q", got.RiskFlag, test.wantRisk)
			}
			if test.label != nil && got.Source != "helius_identity" {
				t.Fatalf("source=%q want helius_identity", got.Source)
			}
		})
	}
}

func TestClassifyWalletLabelPreservesFunctionalKindWithSuspiciousRisk(t *testing.T) {
	got := ClassifyWalletLabel(&WalletLabel{
		Category: "Centralized Exchange",
		Labels:   []string{"Suspicious"},
		Source:   "helius_identity",
	})
	if got.Kind != WalletEntityKindCEX {
		t.Fatalf("kind=%q want CEX", got.Kind)
	}
	if got.RiskFlag != WalletEntityRiskSuspicious {
		t.Fatalf("risk_flag=%q want SUSPICIOUS", got.RiskFlag)
	}
	if len(got.MatchedTaxonomy) < 2 {
		t.Fatalf("matched taxonomy should explain function and risk: %#v", got.MatchedTaxonomy)
	}
}

func TestClassifyWalletLabelDoesNotGuessFromNameExceptKnownCEX(t *testing.T) {
	got := ClassifyWalletLabel(&WalletLabel{Name: "Totally A Bridge Maybe", Source: "helius_identity"})
	if got.Kind != WalletEntityKindKnown {
		t.Fatalf("kind=%q want KNOWN_ENTITY", got.Kind)
	}
	if got.RiskFlag != "" {
		t.Fatalf("risk_flag=%q want empty", got.RiskFlag)
	}
}
