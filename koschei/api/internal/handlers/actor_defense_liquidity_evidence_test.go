package handlers

import "testing"

func TestActorDefenseLiquidityEvidenceRequiresExplicitPoolAndProgram(t *testing.T) {
	complete := actorDefenseLiquidityEvidence(map[string]any{
		"instructions": []any{map[string]any{
			"programId": "RaydiumProgram111111111111111111111111111",
			"parsed": map[string]any{
				"type": "removeLiquidity",
				"info": map[string]any{"poolAccount": "Pool111111111111111111111111111111111111"},
			},
		}},
	}, map[string]any{})
	if !complete.Complete() {
		t.Fatalf("complete evidence was rejected: %#v", complete)
	}
	if complete.Program == "" || complete.PoolWallet == "" {
		t.Fatalf("missing canonical evidence fields: %#v", complete)
	}

	missingPool := actorDefenseLiquidityEvidence(map[string]any{
		"instructions": []any{map[string]any{
			"programId": "RaydiumProgram111111111111111111111111111",
			"parsed":    map[string]any{"type": "removeLiquidity", "info": map[string]any{}},
		}},
	}, map[string]any{})
	if !missingPool.Found || !missingPool.Parsed {
		t.Fatalf("parsed observation disappeared: %#v", missingPool)
	}
	if missingPool.Complete() {
		t.Fatalf("missing pool must not satisfy VERIFIED boundary: %#v", missingPool)
	}
}

func TestActorDefenseLiquidityEvidenceLogOnlyRemainsIncomplete(t *testing.T) {
	line := actorDefenseLiquidityEvidence(map[string]any{}, map[string]any{
		"logMessages": []any{"Program log: remove_liquidity"},
	})
	if !line.Found {
		t.Fatal("expected log observation")
	}
	if line.Parsed || line.Complete() {
		t.Fatalf("log-only observation crossed VERIFIED boundary: %#v", line)
	}
}

func TestActorDefenseLiquidityEvidenceDoesNotGuessPoolFromAccounts(t *testing.T) {
	line := actorDefenseLiquidityEvidence(map[string]any{
		"instructions": []any{map[string]any{
			"programId": "RaydiumProgram111111111111111111111111111",
			"accounts":  []any{"Actor111", "MaybePoolButUnknown111"},
			"parsed":    map[string]any{"type": "removeLiquidity", "info": map[string]any{}},
		}},
	}, map[string]any{})
	if line.PoolWallet != "" || line.Complete() {
		t.Fatalf("opaque account position was incorrectly labelled as pool: %#v", line)
	}
}
