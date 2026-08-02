package handlers

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/services"
)

// OwnerActorDefenseQueue returns Koschei's durable wallet investigation queue.
// Ordering is categorical and rule-based; no weighted priority or risk number
// is generated.
func (h *Handler) OwnerActorDefenseQueue(w http.ResponseWriter, r *http.Request) {
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Actor defense database is unavailable")
		return
	}

	network := strings.TrimSpace(r.URL.Query().Get("network"))
	if network == "" {
		network = "solana-mainnet"
	}
	state := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("state")))
	limit := actorDefenseQueueQueryInt(r, "limit", 50)
	offset := actorDefenseQueueQueryInt(r, "offset", 0)

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(services.LoadArvisScanBudgets().ActorQueueTimeoutSeconds)*time.Second)
	defer cancel()
	queue, err := services.NewActorDefenseStore(db).ListVerificationQueue(ctx, network, state, limit, offset)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "invalid actor defense state") {
			writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "Invalid actor defense state filter")
			return
		}
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Actor defense verification queue could not be loaded")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"schema_version":  "koschei-actor-defense-queue-v2",
		"ruleset_version": services.ActorDefenseRulesetVersion,
		"queue":           queue,
	})
}

func actorDefenseQueueQueryInt(r *http.Request, name string, fallback int) int {
	if r == nil {
		return fallback
	}
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}
