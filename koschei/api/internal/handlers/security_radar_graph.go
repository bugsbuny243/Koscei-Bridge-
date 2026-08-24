package handlers

import (
	"net/http"
	"strings"

	"koschei/api/internal/services"
)

func (h *Handler) SecurityRadarGraph(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusUnauthorized, APICodeUnauthorized, "Unauthorized")
		return
	}
	if _, err := h.requirePremiumOutput(claims.Sub, normalizedClaimEmail(claims)); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":   "plan_capacity_required",
			"message": "An active SaaS plan with available output capacity is required.",
		})
		return
	}
	if h == nil || h.DBRead == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "locked": false, "access_provider": "saas_entitlement",
			"graph": services.SecurityRadarGraphResponse{OK: true, Empty: true, Message: "No node graph evidence is available for this verdict yet.", Nodes: []services.SecurityRadarGraphNode{}, Edges: []services.SecurityRadarGraphEdge{}},
		})
		return
	}
	store := services.NewSecurityRadarStore(h.DBRead)
	verdictID := strings.TrimSpace(r.URL.Query().Get("verdict_id"))
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	moduleID := strings.TrimSpace(r.URL.Query().Get("module_id"))
	var graph services.SecurityRadarGraphResponse
	var err error
	if verdictID != "" {
		graph, err = store.GraphByVerdictID(r.Context(), verdictID)
	} else {
		graph, err = store.LatestGraphForTarget(r.Context(), target, moduleID)
	}
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "locked": false, "access_provider": "saas_entitlement",
			"graph":   services.SecurityRadarGraphResponse{OK: true, Empty: true, Message: "No node graph evidence is available for this verdict yet.", Nodes: []services.SecurityRadarGraphNode{}, Edges: []services.SecurityRadarGraphEdge{}},
			"warning": "node graph store unavailable",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "locked": false, "access_provider": "saas_entitlement", "graph": graph})
}
