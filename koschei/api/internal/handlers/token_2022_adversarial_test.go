package handlers

import "testing"

func TestToken2022AdversarialTransferHookCannotRemainAllow(t *testing.T) {
	info := map[string]any{
		"extensions": []any{
			map[string]any{
				"extension": "TransferHook",
				"state": map[string]any{
					"programId": "HookProg11111111111111111111111111111111",
				},
			},
		},
	}

	extensions := parseToken2022Extensions(info)
	if len(extensions) != 1 {
		t.Fatalf("parsed extensions=%d want=1", len(extensions))
	}
	if extensions[0].Severity != "high" || extensions[0].RiskPenalty != 30 {
		t.Fatalf("transfer hook assessment=%#v", extensions[0])
	}

	penalty, behavior, visibility, compatibility := summarizeToken2022Extensions(extensions)
	if penalty != 30 {
		t.Fatalf("transfer hook penalty=%d want=30", penalty)
	}
	if got, _ := behavior["transfer_hook"].(bool); !got {
		t.Fatal("transfer hook must be projected as active behavior")
	}
	if got, _ := behavior["standard_transfer"].(bool); got {
		t.Fatal("transfer hook must invalidate standard-transfer assumption")
	}
	if got := behavior["transfer_hook_program"]; got != "HookProg11111111111111111111111111111111" {
		t.Fatalf("transfer hook program=%v", got)
	}
	if len(visibility) != 0 {
		t.Fatalf("unexpected visibility limitation=%#v", visibility)
	}
	if len(compatibility) == 0 {
		t.Fatal("transfer hook must emit compatibility evidence")
	}
	if policy := token2022FinalPolicy(100, extensions, visibility, true); policy != "warn" {
		t.Fatalf("high-score transfer-hook token policy=%q want=warn", policy)
	}
}

func TestToken2022AdversarialUnresolvedTLVMustWithhold(t *testing.T) {
	status, complete := token2022ExtensionResolution(true, 256, nil)
	if status != "token_2022_extensions_unresolved" {
		t.Fatalf("resolution status=%q", status)
	}
	if complete {
		t.Fatal("Token-2022 mint with extra account space but no parsed extensions must be incomplete")
	}
	if policy := token2022FinalPolicy(100, nil, nil, complete); policy != "withhold" {
		t.Fatalf("incomplete Token-2022 evidence policy=%q want=withhold", policy)
	}
}
