package http

import (
	"net/http"

	"koschei/api/internal/handlers"
)

// registerDefenseOSRoutes is kept temporarily as the startup hook while ARVIS
// owner-memory routes are separated from the dormant Defense OS surface. Once
// the Defense OS group is removed, the startup hook can be renamed without
// risking these ARVIS routes.
func registerDefenseOSRoutes(mux *http.ServeMux, h *handlers.Handler) {
	registerArvisOwnerMemoryRoutes(mux, h)
	registerDormantDefenseOSRoutes(mux, h)
}

func registerArvisOwnerMemoryRoutes(mux *http.ServeMux, h *handlers.Handler) {
	mux.HandleFunc("/api/owner/radar/continuity", requiresDB(h, ownerOnly(h, method("GET", h.OwnerRadarContinuity))))
	mux.HandleFunc("/api/owner/radar/provider-memory", requiresDB(h, ownerOnly(h, method("GET", h.OwnerProviderWitnessMemory))))
	mux.HandleFunc("/api/owner/actor-memory/matches", requiresDB(h, ownerOnly(h, method("GET", h.OwnerActorOperationalMemory))))
}
