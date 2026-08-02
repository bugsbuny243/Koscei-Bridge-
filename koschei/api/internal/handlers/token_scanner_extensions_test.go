package handlers

import (
	"reflect"
	"testing"
)

func TestParseToken2022Extensions(t *testing.T) {
	info := map[string]any{
		"extensions": []any{
			map[string]any{
				"extension": "permanentDelegate",
				"state":     map[string]any{"delegate": "Delegate11111111111111111111111111111111"},
			},
			map[string]any{
				"extension": "transferFeeConfig",
				"state": map[string]any{
					"newerTransferFee": map[string]any{"transferFeeBasisPoints": float64(1200), "maximumFee": "500000"},
				},
			},
		},
	}

	extensions := parseToken2022Extensions(info)
	if len(extensions) != 2 {
		t.Fatalf("expected 2 extensions, got %d", len(extensions))
	}
	if extensions[0].Severity != "critical" || extensions[0].RiskPenalty != 50 {
		t.Fatalf("unexpected permanent delegate assessment: %#v", extensions[0])
	}
	if extensions[1].Severity != "high" || extensions[1].RiskPenalty != 30 {
		t.Fatalf("unexpected transfer fee assessment: %#v", extensions[1])
	}
}

func TestSummarizeToken2022Extensions(t *testing.T) {
	extensions := []tokenExtensionAssessment{
		assessToken2022Extension("transferHook", map[string]any{"programId": "Hook111111111111111111111111111111111"}),
		assessToken2022Extension("confidentialTransferMint", map[string]any{}),
		assessToken2022Extension("scaledUiAmountConfig", map[string]any{}),
	}

	penalty, behavior, visibility, compatibility := summarizeToken2022Extensions(extensions)
	if penalty != 63 {
		t.Fatalf("expected penalty 63, got %d", penalty)
	}
	if behavior["transfer_hook"] != true || behavior["standard_transfer"] != false {
		t.Fatalf("unexpected transfer behavior: %#v", behavior)
	}
	if len(visibility) != 1 {
		t.Fatalf("expected one visibility limitation, got %#v", visibility)
	}
	if len(compatibility) != 2 {
		t.Fatalf("expected two compatibility warnings, got %#v", compatibility)
	}
}

func TestTokenFinalPolicy(t *testing.T) {
	critical := []tokenExtensionAssessment{assessToken2022Extension("permanentDelegate", map[string]any{})}
	if got := tokenFinalPolicy(90, critical, nil); got != "block" {
		t.Fatalf("expected block, got %s", got)
	}

	medium := []tokenExtensionAssessment{assessToken2022Extension("nonTransferable", map[string]any{})}
	if got := tokenFinalPolicy(80, medium, nil); got != "warn" {
		t.Fatalf("expected warn, got %s", got)
	}

	if got := tokenFinalPolicy(90, nil, nil); got != "allow" {
		t.Fatalf("expected allow, got %s", got)
	}
	if got := tokenFinalPolicy(30, nil, nil); got != "block" {
		t.Fatalf("expected block for low safety score, got %s", got)
	}
}

func TestNestedExtensionValues(t *testing.T) {
	value := map[string]any{
		"olderTransferFee": map[string]any{"transferFeeBasisPoints": float64(100)},
		"newerTransferFee": map[string]any{"maximumFee": "900"},
	}
	if got := token2022NestedNumber(value, "transferFeeBasisPoints"); got != 100 {
		t.Fatalf("expected 100 bps, got %v", got)
	}
	if got := token2022NestedString(value, "maximumFee"); got != "900" {
		t.Fatalf("expected maximum fee 900, got %q", got)
	}
}

func TestNormalizeExtensionName(t *testing.T) {
	cases := map[string]string{
		"PermanentDelegate":       "permanentdelegate",
		"transfer_fee_config":     "transferfeeconfig",
		"Scaled UI Amount Config": "scaleduiamountconfig",
	}
	for input, want := range cases {
		if got := normalizeExtensionName(input); got != want {
			t.Fatalf("normalizeExtensionName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestAppendUnique(t *testing.T) {
	values := []string{}
	seen := map[string]struct{}{}
	appendUnique(&values, seen, "warning")
	appendUnique(&values, seen, "warning")
	if !reflect.DeepEqual(values, []string{"warning"}) {
		t.Fatalf("unexpected values: %#v", values)
	}
}
