package handlers

import "testing"

func TestActorWalletPersistentClassificationAcceptsExactKnownWalletAfterRPCFailure(t *testing.T) {
	original := radarTargetClassification{
		Type: radarTargetUnknown, Status: "lookup_failed",
		Evidence: "Solana account lookup failed: rpc budget exceeded",
	}
	resolved, ok := actorWalletPersistentClassification(
		original,
		"yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe",
		"verified",
	)
	if !ok {
		t.Fatal("known persistent wallet was not accepted")
	}
	if resolved.Type != radarTargetWallet || resolved.Status != "verified_persistent_actor_index" || resolved.Executable {
		t.Fatalf("resolved=%#v", resolved)
	}
	if resolved.Evidence == "" || resolved.Evidence == original.Evidence {
		t.Fatalf("persistent boundary was not explained: %#v", resolved)
	}
}

func TestActorWalletPersistentClassificationRejectsUnknownOrUnverifiedTarget(t *testing.T) {
	for _, test := range []struct {
		name           string
		classification radarTargetClassification
		target         string
		state          string
	}{
		{
			name: "account not found is not an RPC outage",
			classification: radarTargetClassification{Type: radarTargetUnknown, Status: "account_not_found"},
			target: "yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe", state: "verified",
		},
		{
			name: "invalid Base58 target",
			classification: radarTargetClassification{Type: radarTargetUnknown, Status: "lookup_failed"},
			target: "not-a-solana-wallet", state: "verified",
		},
		{
			name: "unknown persistent state",
			classification: radarTargetClassification{Type: radarTargetUnknown, Status: "lookup_failed"},
			target: "yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe", state: "",
		},
		{
			name: "program classification cannot be overwritten",
			classification: radarTargetClassification{Type: radarTargetProgram, Status: "verified_rpc_observation", Executable: true},
			target: "yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe", state: "verified",
		},
	}
	for _, test := range test {
		t.Run(test.name, func(t *testing.T) {
			resolved, ok := actorWalletPersistentClassification(test.classification, test.target, test.state)
			if ok || resolved != test.classification {
				t.Fatalf("unsafe fallback accepted: ok=%v resolved=%#v", ok, resolved)
			}
		})
	}
}

func TestActorWalletPersistentStateIsExplicitlyBounded(t *testing.T) {
	for _, state := range []string{"detected", "tracked", "correlated", "verified", "alerted"} {
		if !actorWalletPersistentState(state) {
			t.Fatalf("expected state %q to be accepted", state)
		}
	}
	for _, state := range []string{"", "unknown", "token", "deleted"} {
		if actorWalletPersistentState(state) {
			t.Fatalf("unexpected state %q accepted", state)
		}
	}
}
