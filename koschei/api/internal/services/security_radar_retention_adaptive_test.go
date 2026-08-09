package services

import (
	"context"
	"errors"
	"testing"
)

func TestRetentionInitialBatchSizeUsesSmallerHeavyPayloadBatches(t *testing.T) {
	if got := retentionInitialBatchSize(retentionTarget{Table: "security_radar_verdicts"}); got != 1000 {
		t.Fatalf("expected verdict batch 1000, got %d", got)
	}
	if got := retentionInitialBatchSize(retentionTarget{Table: "security_radar_events"}); got != 2000 {
		t.Fatalf("expected event batch 2000, got %d", got)
	}
	if got := retentionInitialBatchSize(retentionTarget{Table: "security_radar_seen_signatures"}); got != radarRetentionBatchSize {
		t.Fatalf("expected default batch %d, got %d", radarRetentionBatchSize, got)
	}
}

func TestRetentionNextBatchSizeIsBounded(t *testing.T) {
	cases := map[int]int{
		5000: 2500,
		1000: 500,
		500:  250,
		250:  250,
		100:  250,
	}
	for input, expected := range cases {
		if got := retentionNextBatchSize(input); got != expected {
			t.Fatalf("input=%d expected=%d got=%d", input, expected, got)
		}
	}
}

func TestRetentionDeadlineErrorRecognizesContextAndPostgresCancellation(t *testing.T) {
	for _, err := range []error{
		context.DeadlineExceeded,
		errors.New("pq: canceling statement due to user request (57014)"),
		errors.New("statement timeout"),
	} {
		if !retentionDeadlineError(err) {
			t.Fatalf("expected deadline classification for %v", err)
		}
	}
	if retentionDeadlineError(errors.New("unique violation")) {
		t.Fatal("ordinary database errors must not be retried as deadline reductions")
	}
}
