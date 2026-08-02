package handlers

import "testing"

func TestActorAcceptanceLiquidityActionRecognizesExplicitAddAndRemove(t *testing.T) {
	cases := map[string]string{
		"addLiquidity":          "add",
		"increase_liquidity_v2": "add",
		"depositAllTokenTypes":  "add",
		"removeLiquidity":       "remove",
		"decrease_liquidity_v2": "remove",
		"withdrawAllTokenTypes": "remove",
	}
	for input, expected := range cases {
		if got := actorAcceptanceLiquidityAction(input); got != expected {
			t.Fatalf("action %q=%q, want %q", input, got, expected)
		}
	}
	for _, input := range []string{"swap", "transfer", "deposit", "withdraw", "closePosition"} {
		if got := actorAcceptanceLiquidityAction(input); got != "" {
			t.Fatalf("generic instruction %q must not become liquidity evidence: %q", input, got)
		}
	}
}

func TestActorAcceptanceParsedLiquidityLineRequiresPoolAndProgram(t *testing.T) {
	base := map[string]any{
		"programId": "raydium-program",
		"parsed": map[string]any{
			"type": "increaseLiquidityV2",
			"info": map[string]any{
				"poolState": "pool-wallet",
				"authority": "creator-wallet",
			},
		},
	}
	line, ok := actorAcceptanceParsedLiquidityLine(base, "creator-wallet")
	if !ok || line.Action != "add" || line.Program != "raydium-program" || line.PoolWallet != "pool-wallet" || line.Authority != "creator-wallet" {
		t.Fatalf("explicit liquidity line not parsed: ok=%v line=%+v", ok, line)
	}

	withoutPool := map[string]any{
		"programId": "raydium-program",
		"parsed":    map[string]any{"type": "increaseLiquidityV2", "info": map[string]any{"authority": "creator-wallet"}},
	}
	if _, ok := actorAcceptanceParsedLiquidityLine(withoutPool, "creator-wallet"); ok {
		t.Fatal("instruction without explicit pool must fail closed")
	}

	withoutProgram := map[string]any{
		"parsed": map[string]any{"type": "removeLiquidity", "info": map[string]any{"pool": "pool-wallet", "authority": "creator-wallet"}},
	}
	if _, ok := actorAcceptanceParsedLiquidityLine(withoutProgram, "creator-wallet"); ok {
		t.Fatal("instruction without explicit program must fail closed")
	}
}

func TestActorAcceptanceParsedLiquidityLineRejectsDifferentAuthority(t *testing.T) {
	instruction := map[string]any{
		"programId": "orca-program",
		"parsed": map[string]any{
			"type": "decreaseLiquidity",
			"info": map[string]any{
				"pool":          "pool-wallet",
				"positionOwner": "other-wallet",
			},
		},
	}
	if _, ok := actorAcceptanceParsedLiquidityLine(instruction, "creator-wallet"); ok {
		t.Fatal("actor-signed fee payer must not claim another authority's liquidity action")
	}
}

func TestActorAcceptanceParsedLiquidityLineAllowsObservedAuthorityOmission(t *testing.T) {
	instruction := map[string]any{
		"programId": "meteora-program",
		"parsed": map[string]any{
			"type": "addLiquidity",
			"info": map[string]any{"poolAccount": "pool-wallet"},
		},
	}
	line, ok := actorAcceptanceParsedLiquidityLine(instruction, "creator-wallet")
	if !ok || line.Authority != "" {
		t.Fatalf("explicit pool/program line without authority should remain OBSERVED, got ok=%v line=%+v", ok, line)
	}
}
