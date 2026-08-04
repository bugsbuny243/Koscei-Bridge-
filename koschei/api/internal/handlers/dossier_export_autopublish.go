package handlers

import (
	"net/http"

	"koschei/api/internal/workerwake"
)

type dossierExportStatusWriter struct {
	http.ResponseWriter
	status int
}

func (w *dossierExportStatusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *dossierExportStatusWriter) Write(value []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(value)
}

// DossierExportWithAutopublishWake preserves the canonical export implementation
// and wakes the event-driven publication worker only after a successful HTTP
// result. The gate is coalescing, so repeated reads of an existing export do not
// create a polling loop or duplicate decisions.
func (h *Handler) DossierExportWithAutopublishWake(w http.ResponseWriter, r *http.Request) {
	capture := &dossierExportStatusWriter{ResponseWriter: w}
	h.DossierExport(capture, r)
	if capture.status >= 200 && capture.status < 300 {
		workerwake.Signal(workerwake.DossierAutopublish)
	}
}
