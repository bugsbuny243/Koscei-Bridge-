package securityevidence

import "testing"

func TestBuildRadarEventBindsExactReportBytes(t *testing.T) {
	base := RadarReportInput{
		ReportJSON: []byte(`{"schema":"koschei-customer-investigation-response-v3","target":"abc"}`),
		Subject: Subject{Chain: "solana", Type: "token", ID: "abc"},
		Window: ObservationWindow{FromUnixMS: 10, ToUnixMS: 20},
		Findings: []Finding{{
			ID: "authority",
			Kind: "authority_state",
			State: StateObserved,
		}},
	}
	a, err := BuildRadarEventV1(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(); err != nil {
		t.Fatalf("sealed radar event did not verify: %v", err)
	}

	changed := base
	changed.ReportJSON = []byte(`{"schema":"koschei-customer-investigation-response-v3","target":"def"}`)
	b, err := BuildRadarEventV1(changed)
	if err != nil {
		t.Fatal(err)
	}
	if a.EventSHA256 == b.EventSHA256 {
		t.Fatal("different radar report bytes produced identical event identity")
	}
	if len(a.SourceDigests) != 1 || a.SourceDigests[0] == b.SourceDigests[0] {
		t.Fatal("exact report bytes were not independently bound as source evidence")
	}
}

func TestBuildRadarEventRejectsInvalidReport(t *testing.T) {
	_, err := BuildRadarEventV1(RadarReportInput{
		ReportJSON: []byte(`not-json`),
		Subject: Subject{Chain: "solana", Type: "token", ID: "abc"},
		Window: ObservationWindow{FromUnixMS: 10, ToUnixMS: 20},
	})
	if err == nil {
		t.Fatal("invalid radar report unexpectedly accepted")
	}
}

func TestRadarAdapterPreservesLegacyOnlyAsBoundMetadata(t *testing.T) {
	score := 11
	e, err := BuildRadarEventV1(RadarReportInput{
		ReportJSON: []byte(`{"target":"abc"}`),
		Subject: Subject{Chain: "solana", Type: "token", ID: "abc"},
		Window: ObservationWindow{FromUnixMS: 10, ToUnixMS: 20},
		Legacy: &LegacyObservation{Grade: "f", Score: &score},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Legacy == nil || e.Legacy.Grade != "F" {
		t.Fatalf("legacy radar metadata was not preserved canonically: %#v", e.Legacy)
	}
	if e.Producer != RadarProducerV1+"@"+RadarRulesetV1 {
		t.Fatalf("unexpected producer identity: %s", e.Producer)
	}
}
