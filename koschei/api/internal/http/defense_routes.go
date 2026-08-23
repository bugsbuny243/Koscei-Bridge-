package http

import (
	"net/http"

	"koschei/api/internal/handlers"
)

// registerDefenseOSRoutes is kept as a compatibility name for the server wiring.
// The Defense OS product surface has been removed; only ARVIS continuity and
// persistent evidence-memory endpoints remain registered here.
func registerDefenseOSRoutes(mux *http.ServeMux, h *handlers.Handler) {
	mux.HandleFunc("/api/owner/radar/continuity", requiresDB(h, ownerOnly(h, method("GET", h.OwnerRadarContinuity))))
	mux.HandleFunc("/api/owner/radar/provider-memory", requiresDB(h, ownerOnly(h, method("GET", h.OwnerProviderWitnessMemory))))
	mux.HandleFunc("/api/owner/actor-memory/matches", requiresDB(h, ownerOnly(h, method("GET", h.OwnerActorOperationalMemory))))
}
