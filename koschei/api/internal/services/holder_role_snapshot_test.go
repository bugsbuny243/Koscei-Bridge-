package services

import "testing"

func TestAnalyzeSolanaHolderRolesSnapshotIsProviderNeutral(t *testing.T) {
	largest := []SolanaLargestTokenAccount{
		{Address: "TokenAccountA", SolanaTokenAmount: SolanaTokenAmount{UIAmountString: "500"}},
		{Address: "TokenAccountB", SolanaTokenAmount: SolanaTokenAmount{UIAmountString: "300"}},
	}
	tokenAccounts := []*SolanaAccountInfo{
		{Data: map[string]any{"parsed": map[string]any{"info": map[string]any{"owner": "WalletA"}}}},
		{Data: map[string]any{"parsed": map[string]any{"info": map[string]any{"owner": solanaIncineratorAddress}}}},
	}
	owners := map[string]*SolanaAccountInfo{
		"WalletA": {Owner: solanaSystemProgramID},
	}
	got := AnalyzeSolanaHolderRolesSnapshot(HolderRoleSnapshotInput{
		TotalSupply: 1000, Largest: largest, TokenAccounts: tokenAccounts,
		OwnerAccounts: owners, OwnerMetadataComplete: true,
	})
	if !got.Available {
		t.Fatalf("expected available snapshot, got %#v", got)
	}
	if got.RawTop1Percentage != 50 || got.RawTop3Percentage != 80 {
		t.Fatalf("unexpected raw concentration: top1=%v top3=%v", got.RawTop1Percentage, got.RawTop3Percentage)
	}
	if got.BurnPercentage != 30 || got.CirculatingSupply != 700 {
		t.Fatalf("expected burn exclusion without third-party labels: burn=%v circulating=%v", got.BurnPercentage, got.CirculatingSupply)
	}
	if len(got.Accounts) != 2 || got.Accounts[0].OwnerWallet != "WalletA" {
		t.Fatalf("unexpected accounts: %#v", got.Accounts)
	}
	for _, row := range got.Accounts {
		if row.Label != "" || row.LabelEntity != "" || row.LabelSource != "" {
			t.Fatalf("core snapshot analysis must not perform identity enrichment: %#v", row)
		}
	}
}

func TestSolanaHolderOwnerAddressesPreservesExactCaseAndOrder(t *testing.T) {
	infos := []*SolanaAccountInfo{
		{Data: map[string]any{"parsed": map[string]any{"info": map[string]any{"owner": "AbC111"}}}},
		{Data: map[string]any{"parsed": map[string]any{"info": map[string]any{"owner": "aBc111"}}}},
		{Data: map[string]any{"parsed": map[string]any{"info": map[string]any{"owner": "AbC111"}}}},
	}
	got := SolanaHolderOwnerAddresses(infos)
	if len(got) != 2 || got[0] != "AbC111" || got[1] != "aBc111" {
		t.Fatalf("Solana addresses must remain case-sensitive and ordered, got %#v", got)
	}
}

func TestAnalyzeSolanaHolderRolesSnapshotFailsClosedWhenDominantOwnerMetadataMissing(t *testing.T) {
	largest := []SolanaLargestTokenAccount{
		{Address: "TokenAccountA", SolanaTokenAmount: SolanaTokenAmount{UIAmountString: "600"}},
	}
	tokenAccounts := []*SolanaAccountInfo{
		{Data: map[string]any{"parsed": map[string]any{"info": map[string]any{"owner": "WalletUnknown"}}}},
	}
	got := AnalyzeSolanaHolderRolesSnapshot(HolderRoleSnapshotInput{
		TotalSupply: 1000, Largest: largest, TokenAccounts: tokenAccounts,
		OwnerAccounts: map[string]*SolanaAccountInfo{}, OwnerMetadataComplete: false,
	})
	if !got.Available || !got.BlockingEvidenceGap {
		t.Fatalf("dominant unresolved owner must remain blocking, got %#v", got)
	}
	if got.Status != "dominant_holder_role_unresolved" {
		t.Fatalf("unexpected status %q", got.Status)
	}
}
