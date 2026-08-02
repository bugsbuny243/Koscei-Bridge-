package services

import (
	"context"
	"fmt"
	"log"

	"koschei/api/internal/services/retentionexport"
)

func (w *securityRadarRetentionWorker) exportPendingArchive(ctx context.Context, phase string) error {
	result, err := retentionexport.RunFromEnv(ctx, w.db)
	if !result.Enabled {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s archive export failed: %w", phase, err)
	}
	if result.ExportedRows > 0 {
		log.Printf("radar retention export run %s phase=%s sink=%s rows=%d objects=%d bytes=%d ref=%s",
			result.RunID, phase, result.Sink, result.ExportedRows, result.ObjectCount,
			result.BytesExported, result.LastExportRef)
	}
	return nil
}
