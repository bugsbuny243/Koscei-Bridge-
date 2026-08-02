package handlers

import "testing"

func TestToken2022ExtensionResolutionWithholdsUnparsedTLVState(t *testing.T) {
	status, complete := token2022ExtensionResolution(true, 234, nil)
	if status != "token_2022_extensions_unresolved" || complete {
		t.Fatalf("resolution=(%q,%t), want unresolved,false", status, complete)
	}
	if policy := token2022FinalPolicy(100, nil, nil, complete); policy != "withhold" {
		t.Fatalf("policy=%q, want withhold", policy)
	}
}

func TestToken2022ExtensionResolutionAcceptsResolvedEmptyClassicMintSpace(t *testing.T) {
	status, complete := token2022ExtensionResolution(true, 82, nil)
	if status != "resolved_empty" || !complete {
		t.Fatalf("resolution=(%q,%t), want resolved_empty,true", status, complete)
	}
}
