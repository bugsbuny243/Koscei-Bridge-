package http

import "net/http"

// privateDossierExport removes public-discovery metadata from the authenticated
// dossier export route. A stored export is private by default; only an explicit
// dossier_publications.status='public' record makes /dossier/{case_ref} public.
func privateDossierExport(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		next(&privateDossierExportWriter{ResponseWriter: w}, r)
	}
}

type privateDossierExportWriter struct {
	http.ResponseWriter
}

func (w *privateDossierExportWriter) scrub() {
	w.Header().Del("Content-Location")
	w.Header().Del("Link")
	w.Header().Del("X-Koschei-Public-Dossier")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Koschei-Dossier-Visibility", "private-export")
}

func (w *privateDossierExportWriter) WriteHeader(statusCode int) {
	w.scrub()
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *privateDossierExportWriter) Write(p []byte) (int, error) {
	w.scrub()
	return w.ResponseWriter.Write(p)
}
