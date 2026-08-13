package services

import (
	"testing"
	"time"
)

func TestPumpPortalInboxEventKeyPrefersSignature(t *testing.T) {
	event := PumpPortalEvent{Signature: "  sig-123  ", Mint: "Mint111111111111111111111111111111111111"}
	if got := pumpPortalInboxEventKey(event); got != "sig:sig-123" {
		t.Fatalf("expected signature identity, got %q", got)
	}
}

func TestPumpPortalInboxEventKeySignaturelessIsDeterministic(t *testing.T) {
	event := PumpPortalEvent{
		Mint: "Mint111111111111111111111111111111111111",
		Type: "create", Creator: "creator", TxType: "create", Slot: 42,
		BlockTime:  time.Unix(1_700_000_000, 0).UTC(),
		ReceivedAt: time.Now().UTC(),
	}
	first := pumpPortalInboxEventKey(event)
	event.ReceivedAt = event.ReceivedAt.Add(time.Hour)
	second := pumpPortalInboxEventKey(event)
	if first == "" || first != second {
		t.Fatalf("received_at must not change durable event identity: %q != %q", first, second)
	}
}

func TestPumpPortalInboxEventKeySeparatesDifferentSlots(t *testing.T) {
	base := PumpPortalEvent{Mint: "Mint111111111111111111111111111111111111", Type: "create", Creator: "creator", Slot: 42}
	other := base
	other.Slot = 43
	if pumpPortalInboxEventKey(base) == pumpPortalInboxEventKey(other) {
		t.Fatal("different signatureless slot observations must not collapse into one inbox event")
	}
}
