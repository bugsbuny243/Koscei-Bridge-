package services

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSecurityRadarStreamIngestModeDefaultsLegacy(t *testing.T) {
	t.Setenv("KOSCHEI_STREAM_INGEST_MODE", "")
	if got := securityRadarStreamIngestMode(); got != securityRadarIngestModeLegacy {
		t.Fatalf("expected legacy, got %q", got)
	}
}

func TestSecurityRadarStreamIngestModeJournal(t *testing.T) {
	t.Setenv("KOSCHEI_STREAM_INGEST_MODE", " JOURNAL ")
	if got := securityRadarStreamIngestMode(); got != securityRadarIngestModeJournal {
		t.Fatalf("expected journal, got %q", got)
	}
}

func TestEnqueueSecurityRadarJournalEventHonorsBackpressure(t *testing.T) {
	queue := make(chan SecurityRadarStreamEventRecord, 1)
	queue <- SecurityRadarStreamEventRecord{Signature: "first"}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	err := enqueueSecurityRadarJournalEvent(ctx, queue, SecurityRadarStreamEventRecord{Signature: "second"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline while the queue stays full, got %v", err)
	}
	if len(queue) != 1 {
		t.Fatalf("journal enqueue must not evict an existing event; queue len=%d", len(queue))
	}
}

func TestEnqueueSecurityRadarJournalEventResumesAfterCapacity(t *testing.T) {
	queue := make(chan SecurityRadarStreamEventRecord, 1)
	queue <- SecurityRadarStreamEventRecord{Signature: "first"}

	drained := make(chan struct{})
	go func() {
		time.Sleep(10 * time.Millisecond)
		<-queue
		close(drained)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	event := SecurityRadarStreamEventRecord{Signature: "second"}
	if err := enqueueSecurityRadarJournalEvent(ctx, queue, event); err != nil {
		t.Fatalf("enqueue failed after capacity returned: %v", err)
	}
	<-drained
	got := <-queue
	if got.Signature != event.Signature {
		t.Fatalf("expected queued signature %q, got %q", event.Signature, got.Signature)
	}
}
