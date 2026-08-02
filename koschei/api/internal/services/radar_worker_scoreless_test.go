package services

import (
	"os"
	"strings"
	"testing"
)

func TestBackgroundWorkersDoNotCallLegacyNumericRadarEngine(t *testing.T) {
	for _, path := range []string{"security_radar_worker.go", "security_radar_stream_worker.go"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "AnalyzeSecurityRadars(") {
			t.Fatalf("%s still calls the legacy numeric radar engine", path)
		}
	}
}

func TestStreamPublicationUsesVerifiedEvidenceNotRiskIndex(t *testing.T) {
	verdict := SecurityRadarVerdict{
		ModuleID:  ModulePumpSybilRadar,
		Signed:    true,
		Grade:     "-",
		RiskIndex: 0,
		Signals: map[string]any{
			"real_onchain_evidence": true,
			"data_quality":          "live_rpc_evidence",
			"is_token_mint":         true,
		},
	}
	event := SecurityRadarStreamEventRecord{
		Target:          "Mint111111111111111111111111111111111111",
		Signature:       "Signature111111111111111111111111111111",
		EvidenceQuality: "decoded_stream_hint",
	}
	if !shouldPublishSBX1CustomerVerdict(event, verdict, verdict.Signals) {
		t.Fatal("verified evidence was withheld merely because its compatibility risk index is zero")
	}
}
