package services

import (
	"encoding/json"
	"testing"
)

func TestPlanSecurityRadarReplayPageStopsAtExactWatermark(t *testing.T) {
	cursor := securityRadarReplayCursor{WatermarkSignature: "old", WatermarkSlot: 100}
	page := []securityRadarReplaySignature{
		{Signature: "new-3", Slot: 103},
		{Signature: "new-2", Slot: 102},
		{Signature: "new-1", Slot: 101},
		{Signature: "old", Slot: 100},
		{Signature: "older", Slot: 99},
	}
	plan := planSecurityRadarReplayPage(cursor, page, 100)
	if !plan.ReachedWatermark {
		t.Fatal("expected exact recovery watermark to be reached")
	}
	if len(plan.Replay) != 3 {
		t.Fatalf("expected 3 missing signatures, got %d", len(plan.Replay))
	}
	if plan.NextBefore != "" {
		t.Fatalf("caught-up page must not request pagination, got %q", plan.NextBefore)
	}
	if plan.HeadSignature != "new-3" || plan.HeadSlot != 103 {
		t.Fatalf("unexpected scan head %q@%d", plan.HeadSignature, plan.HeadSlot)
	}
}

func TestPlanSecurityRadarReplayPageConsumesWholeWatermarkSlot(t *testing.T) {
	cursor := securityRadarReplayCursor{WatermarkSignature: "forked-away", WatermarkSlot: 100}
	page := []securityRadarReplaySignature{
		{Signature: "new", Slot: 101},
		{Signature: "same-slot-a", Slot: 100},
		{Signature: "same-slot-b", Slot: 100},
		{Signature: "older", Slot: 99},
	}
	plan := planSecurityRadarReplayPage(cursor, page, 100)
	if !plan.ReachedWatermark {
		t.Fatal("expected slot boundary fallback to close the gap")
	}
	if len(plan.Replay) != 3 {
		t.Fatalf("same-slot signatures must be replayed before stopping; got %d", len(plan.Replay))
	}
	if plan.Replay[1].Signature != "same-slot-a" || plan.Replay[2].Signature != "same-slot-b" {
		t.Fatalf("watermark slot was not preserved: %#v", plan.Replay)
	}
}

func TestPlanSecurityRadarReplayPageCarriesIndependentScanHeadAcrossPages(t *testing.T) {
	cursor := securityRadarReplayCursor{
		WatermarkSignature: "old",
		WatermarkSlot:      10,
		ScanHeadSignature:  "head-from-page-one",
		ScanHeadSlot:       30,
	}
	page := []securityRadarReplaySignature{
		{Signature: "page-two-a", Slot: 20},
		{Signature: "page-two-b", Slot: 19},
	}
	plan := planSecurityRadarReplayPage(cursor, page, 2)
	if plan.HeadSignature != cursor.ScanHeadSignature || plan.HeadSlot != cursor.ScanHeadSlot {
		t.Fatalf("scan head changed during pagination: %q@%d", plan.HeadSignature, plan.HeadSlot)
	}
	if plan.NextBefore != "page-two-b" {
		t.Fatalf("expected deterministic pagination cursor, got %q", plan.NextBefore)
	}
	if plan.ReachedWatermark {
		t.Fatal("watermark should not be reached yet")
	}
}

func TestReplaySignatureFailedDistinguishesNullFromFailure(t *testing.T) {
	if replaySignatureFailed(json.RawMessage("null")) {
		t.Fatal("null err must represent a successful signature")
	}
	if replaySignatureFailed(nil) {
		t.Fatal("missing err field must not be treated as a failure")
	}
	if !replaySignatureFailed(json.RawMessage(`{"InstructionError":[1,"Custom"]}`)) {
		t.Fatal("non-null transaction error must be treated as failed")
	}
}
