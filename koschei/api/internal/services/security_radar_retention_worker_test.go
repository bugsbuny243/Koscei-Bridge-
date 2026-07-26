package services

import (
	"strings"
	"testing"
)

func TestRetentionTargetsArchiveProcessingBeforeStreamEvents(t *testing.T) {
	processing := -1
	stream := -1
	for index, target := range radarRetentionTargets {
		switch target.Table {
		case "arvis_stream_processing":
			processing = index
			if target.IDColumn != "stream_event_id" {
				t.Fatalf("processing ID column = %q", target.IDColumn)
			}
		case "security_radar_stream_events":
			stream = index
			if !strings.Contains(target.Where, "NOT EXISTS") || !strings.Contains(target.Where, "arvis_stream_processing") {
				t.Fatalf("stream target does not block cascade deletion: %s", target.Where)
			}
		}
	}
	if processing < 0 || stream < 0 || processing >= stream {
		t.Fatalf("processing target index=%d stream index=%d", processing, stream)
	}
}

func TestRetentionArchiveQueryVerifiesWholeBatchBeforeDelete(t *testing.T) {
	query := retentionArchiveQuery(retentionTarget{
		Table: "arvis_stream_processing", IDColumn: "stream_event_id",
		Where: "t.created_at < $1", Order: "t.created_at ASC",
	})
	for _, fragment := range []string{
		"verified AS",
		"a.payload=e.payload",
		"batch_ok AS",
		"selected_count=archived_count",
		"archived_count=verified_count",
		"EXISTS (SELECT 1 FROM batch_ok)",
		"t.stream_event_id::text",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("archive query missing %q:\n%s", fragment, query)
		}
	}
}

func TestRetentionProcessingExcludesOpenLeases(t *testing.T) {
	for _, target := range radarRetentionTargets {
		if target.Table != "arvis_stream_processing" {
			continue
		}
		if !strings.Contains(target.Where, "'pending','processing'") {
			t.Fatalf("processing retention does not preserve open leases: %s", target.Where)
		}
		return
	}
	t.Fatal("arvis_stream_processing target missing")
}
