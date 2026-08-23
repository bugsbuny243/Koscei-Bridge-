package handlers

import (
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestResolveLaunchForensicsAnchorPrefersVerifiedCanonicalCreate(t *testing.T) {
	source := map[string]any{
		"creator_relation_verified": true,
		"creator_wallet":            "CreatorOne",
		"slot":                      int64(435366376),
		"observed_at":               "2026-07-26T16:24:38Z",
		"event_type":                "pumpportal_migration",
		"canonical_creator_verification": map[string]any{
			"verified": true,
			"slot":     int64(435366376),
			"status":   "verified_canonical_create_transaction",
		},
	}
	cluster := services.HolderClusterAnalysis{
		LaunchEstimateSlot: 441064258,
		LaunchEstimateAt:   "2026-08-23T02:59:43Z",
	}
	blockTime, slot, sourceName := resolveLaunchForensicsAnchor(source, cluster)
	if slot != 435366376 {
		t.Fatalf("slot=%d want canonical create slot", slot)
	}
	want := time.Date(2026, 7, 26, 16, 24, 38, 0, time.UTC).Unix()
	if blockTime != want {
		t.Fatalf("block_time=%d want=%d", blockTime, want)
	}
	if sourceName != "verified_canonical_create_transaction" {
		t.Fatalf("source=%q", sourceName)
	}
}

func TestResolveLaunchForensicsAnchorFallsBackToClusterWithoutVerifiedCreate(t *testing.T) {
	cluster := services.HolderClusterAnalysis{
		LaunchEstimateSlot: 441064258,
		LaunchEstimateAt:   "2026-08-23T02:59:43Z",
	}
	blockTime, slot, sourceName := resolveLaunchForensicsAnchor(map[string]any{}, cluster)
	if slot != cluster.LaunchEstimateSlot || blockTime <= 0 || sourceName != "cluster_launch_estimate" {
		t.Fatalf("fallback=%d/%d/%q", blockTime, slot, sourceName)
	}
}
