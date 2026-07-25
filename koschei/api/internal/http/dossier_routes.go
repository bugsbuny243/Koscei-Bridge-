package http

import (
	"net/http"

	"koschei/api/internal/handlers"
)

func registerDossierRoutes(mux *http.ServeMux, h *handlers.Handler) {
	mux.HandleFunc("/api/v1/dossier/", requiresDB(h, h.DossierAccess(method(http.MethodPost, h.DossierExport))))
	mux.HandleFunc("/dossier/", requiresDB(h, method(http.MethodGet, h.DossierPage)))
	mux.HandleFunc("/case/", requiresDB(h, method(http.MethodGet, h.PublicCasePage)))
	mux.HandleFunc("/api/public/cases", requiresDB(h, method(http.MethodGet, h.PublicDossierCases)))
	mux.HandleFunc("/api/public/soc/feed", requiresDB(h, method(http.MethodGet, h.PublicSOCFeed)))
	mux.HandleFunc("/api/owner/dossier/publications", requiresDB(h, ownerOnly(h, method(http.MethodPost, h.OwnerDossierPublication))))
	mux.HandleFunc("/api/owner/arvis/acceptance", requiresDB(h, ownerOnly(h, method(http.MethodPost, h.OwnerInvestigationAcceptance))))
}
