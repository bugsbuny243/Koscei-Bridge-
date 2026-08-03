package handlers

import "testing"

func TestTransactionFirewallPolicyDefaultsToShadowOutsideProduction(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv("KOSCHEI_TRANSACTION_FIREWALL_MODE", "")
	policy := currentTransactionFirewallPolicy()
	if policy.Mode != transactionFirewallShadowMode || policy.EnforcementEnabled {
		t.Fatalf("expected shadow policy outside production, got %+v", policy)
	}
}

func TestTransactionFirewallPolicyDefaultsToEnforceInProduction(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("KOSCHEI_TRANSACTION_FIREWALL_MODE", "")
	policy := currentTransactionFirewallPolicy()
	if policy.Mode != transactionFirewallEnforceMode || !policy.EnforcementEnabled {
		t.Fatalf("expected enforce policy in production, got %+v", policy)
	}
}

func TestTransactionFirewallExplicitShadowOverridesProduction(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("KOSCHEI_TRANSACTION_FIREWALL_MODE", "shadow")
	policy := currentTransactionFirewallPolicy()
	if policy.Mode != transactionFirewallShadowMode || policy.EnforcementEnabled {
		t.Fatalf("expected explicit shadow override, got %+v", policy)
	}
}

func TestTransactionFirewallEnforcementBlocksOnlyBlockAndWithhold(t *testing.T) {
	policy := transactionFirewallPolicy{Mode: transactionFirewallEnforceMode, EnforcementEnabled: true}
	for _, action := range []string{"block", "withhold"} {
		if !firewallPolicyBlocks(policy, action) {
			t.Fatalf("expected action %q to be blocked", action)
		}
	}
	for _, action := range []string{"allow", "warn", ""} {
		if firewallPolicyBlocks(policy, action) {
			t.Fatalf("did not expect action %q to be blocked", action)
		}
	}
}

func TestTransactionFirewallShadowNeverEnforces(t *testing.T) {
	policy := transactionFirewallPolicy{Mode: transactionFirewallShadowMode, EnforcementEnabled: false}
	if firewallPolicyBlocks(policy, "block") {
		t.Fatal("shadow policy must never enforce a block")
	}
	if got := firewallPolicyOutcome(policy, "block"); got != "observed" {
		t.Fatalf("expected observed outcome, got %q", got)
	}
}
