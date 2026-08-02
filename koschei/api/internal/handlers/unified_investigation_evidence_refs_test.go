package handlers

import (
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestBuildUnifiedEvidenceReferencesPopulatesTechnicalRows(t *testing.T) {
	core := holderIntelligenceCoreResult{
		Request: services.SecurityRadarRequest{Target: "Mint111", Network: "solana-mainnet"},
		Intelligence: services.HolderIntelligence{
			Available:               true,
			OwnerAggregationApplied: true,
			CirculatingSupply:       1_000_000,
			TopOwnerPercentage:      72,
			Rows: []services.HolderIntelligenceRow{
				{
					Rank:                   1,
					OwnerWallet:            "Owner111",
					OwnerResolved:          true,
					RiskBearing:            true,
					ExcludedFromHolderRisk: false,
					TokenAccounts:          []string{"OwnerTokenAccount111"},
				},
			},
		},
		LaunchForensics: services.LaunchForensicsAnalysis{
			Available:  true,
			LaunchSlot: 100,
			Profiles: []services.LaunchActorProfile{
				{OwnerWallet: "Sniper111", TokenAccounts: []string{"SniperATA111"}, FirstBuySlot: 101, Sniper: true},
				{OwnerWallet: "Linked111", TokenAccounts: []string{"LinkedATA111"}, FirstBuySlot: 102, CreatorLinked: true},
			},
		},
		LPControl: services.LPControlEvidence{
			Available:    true,
			PoolAddress:  "Pool111",
			LPMint:       "LPMint111",
			TokenVault:   "TokenVault111",
			QuoteVault:   "QuoteVault111",
			ReadSlot:     200,
			EvidenceKeys: []string{"pool:Pool111@200"},
		},
		JupiterContext: services.JupiterMarketContext{QuoteContextSlot: 201},
	}
	transactions := []unifiedTransactionEvidence{
		{Signature: "CreatorSellSig", Slot: 300, Trader: "Creator111", Direction: "sell"},
		{Signature: "OwnerExitSig", Slot: 301, Trader: "Owner111", Direction: "sell"},
		{Signature: "BuySig", Slot: 302, Trader: "Buyer111", Direction: "buy"},
	}
	behavior := services.UnifiedRadarBehaviorReport{
		Signals: []services.UnifiedRadarSignal{
			{RuleID: services.UnifiedRuleCreatorSellAcceleration, Signatures: []string{"CreatorSellSig"}, EvidenceKeys: []string{"creator-sell:CreatorSellSig"}},
			{RuleID: services.UnifiedRuleDominantHolderFirstExit, Signatures: []string{"OwnerExitSig"}, EvidenceKeys: []string{"holder-exit:OwnerExitSig"}},
			{RuleID: services.UnifiedRuleOwnerConcentration, EvidenceKeys: []string{"owner:Owner111"}},
		},
	}
	final := services.UnifiedRadarVerdict{Signed: true, Signature: "VerdictSignature111"}

	refs := buildUnifiedEvidenceReferences(core, "Creator111", transactions, behavior, final)
	for _, id := range unifiedVerdictCardRowIDs {
		if !unifiedEvidenceReferencePresent(refs[id]) {
			t.Fatalf("row %q has no evidence reference: %#v", id, refs[id])
		}
	}
	assertContainsString(t, refs["concentration"].Wallets, "Owner111")
	assertContainsString(t, refs["concentration"].Accounts, "OwnerTokenAccount111")
	assertContainsString(t, refs["concentration"].EvidenceKeys, "owner:Owner111")
	assertContainsInt64(t, refs["concentration"].Slots, 201)
	assertContainsString(t, refs["liquidity"].Accounts, "Pool111")
	assertContainsString(t, refs["liquidity"].Accounts, "TokenVault111")
	assertContainsString(t, refs["liquidity"].EvidenceKeys, "pool:Pool111@200")
	assertContainsInt64(t, refs["liquidity"].Slots, 200)
	assertContainsString(t, refs["creator-sell"].Signatures, "CreatorSellSig")
	assertContainsString(t, refs["dominant-exit"].Signatures, "OwnerExitSig")
	assertContainsString(t, refs["sniper"].Wallets, "Sniper111")
	assertContainsString(t, refs["first-buyer"].Wallets, "Linked111")
	assertContainsString(t, refs["signed"].Signatures, "VerdictSignature111")
}

func TestBuildUnifiedEvidenceReferencesDoesNotInventTransactionEvidence(t *testing.T) {
	core := holderIntelligenceCoreResult{Request: services.SecurityRadarRequest{Target: "MintOnly"}}
	refs := buildUnifiedEvidenceReferences(core, "", nil, services.UnifiedRadarBehaviorReport{}, services.UnifiedRadarVerdict{})
	if len(refs["wash"].Signatures) != 0 || len(refs["wash"].Slots) != 0 {
		t.Fatalf("invented transaction references: %#v", refs["wash"])
	}
	if len(refs["wash"].Accounts) != 1 || refs["wash"].Accounts[0] != "MintOnly" {
		t.Fatalf("target account reference missing: %#v", refs["wash"])
	}
}

func TestUnifiedTransactionEvidenceKeepsProviderTimestamp(t *testing.T) {
	observed := time.Date(2026, 7, 17, 7, 0, 0, 0, time.UTC)
	item := unifiedTransactionEvidence{Signature: "sig", Slot: 1, BlockTime: &observed}
	if item.BlockTime == nil || !item.BlockTime.Equal(observed) {
		t.Fatalf("timestamp=%v", item.BlockTime)
	}
}

func assertContainsString(t *testing.T, values []string, want string) {
	t.Helper()
	for _, value := range values {
		if value == want {
			return
		}
	}
	t.Fatalf("%q not found in %v", want, values)
}

func assertContainsInt64(t *testing.T, values []int64, want int64) {
	t.Helper()
	for _, value := range values {
		if value == want {
			return
		}
	}
	t.Fatalf("%d not found in %v", want, values)
}
