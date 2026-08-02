package handlers

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTransactionGuardAccountDeltaLabelsDeclaredDecimals(t *testing.T) {
	decimals := 6
	encoded, err := json.Marshal(transactionGuardAccountDelta{
		Address: "33333333333333333333333333333333",
		Role:    "observe", Decimals: &decimals,
		PolicyStatus: "pass", EvidenceStatus: "verified_rpc_simulation",
	})
	if err != nil {
		t.Fatalf("marshal account delta: %v", err)
	}
	text := string(encoded)
	if !strings.Contains(text, `"declared_decimals":6`) || !strings.Contains(text, `"decimals_verified":false`) {
		t.Fatalf("declared decimals labels are missing: %s", text)
	}
	if strings.Contains(text, `"decimals":6`) {
		t.Fatalf("unverified decimals were serialized through an ambiguous field: %s", text)
	}
}
