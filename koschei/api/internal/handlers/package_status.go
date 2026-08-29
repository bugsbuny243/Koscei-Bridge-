package handlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"
)

type customerPackageStatus struct {
	HasActivePackage bool       `json:"has_active_package"`
	PlanID           *string    `json:"plan_id"`
	Status           string     `json:"status"`
	OutputsTotal     int        `json:"outputs_total"`
	OutputsRemaining int        `json:"outputs_remaining"`
	RemainingOutputs int        `json:"remaining_outputs"`
	StartsAt         *time.Time `json:"starts_at,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at"`
	Warning          string     `json:"warning,omitempty"`
}

func (h *Handler) MePackage(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusUnauthorized, "AUTH_REQUIRED", "Authentication required")
		return
	}
	status, err := h.customerPackageStatus(r.Context(), claims.Sub, normalizedClaimEmail(claims))
	if err != nil {
		writeAPIData(w, http.StatusOK, customerPackageStatus{HasActivePackage: false, PlanID: nil, Status: "none", ExpiresAt: nil, Warning: "package_database_unavailable"})
		return
	}
	writeAPIData(w, http.StatusOK, status)
}

func (h *Handler) customerPackageStatus(ctx context.Context, authSubject, email string) (customerPackageStatus, error) {
	if h.DB == nil {
		return customerPackageStatus{HasActivePackage: false, PlanID: nil, Status: "none", ExpiresAt: nil, Warning: "package_database_unavailable"}, nil
	}
	authSubject = strings.TrimSpace(authSubject)
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		email = entitlementEmailFromSubject(authSubject)
	}
	var planID, status string
	var startsAt, expiresAt sql.NullTime
	var outputsTotal, outputsRemaining int
	err := h.DB.QueryRowContext(ctx, `
		SELECT COALESCE(e.plan_id,''), COALESCE(e.status,''), COALESCE(e.outputs_total,0), COALESCE(e.outputs_remaining,0), e.starts_at, e.expires_at
		FROM entitlements e
		LEFT JOIN app_user_profiles p ON lower(p.email) = lower(e.email)
		WHERE e.status = 'active'
		  AND COALESCE(e.plan_id, '') <> ''
		  AND COALESCE(e.plan_id, '') <> 'free'
		  AND COALESCE(e.outputs_remaining, 0) > 0
		  AND (e.expires_at IS NULL OR e.expires_at > now())
		  AND (($1 <> '' AND p.auth_subject = $1) OR ($2 <> '' AND lower(e.email) = lower($2)))
		ORDER BY e.updated_at DESC NULLS LAST, e.created_at DESC
		LIMIT 1`, authSubject, email).Scan(&planID, &status, &outputsTotal, &outputsRemaining, &startsAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return customerPackageStatus{HasActivePackage: false, PlanID: nil, Status: "none", ExpiresAt: nil}, nil
	}
	if err != nil {
		return customerPackageStatus{HasActivePackage: false, PlanID: nil, Status: "none", ExpiresAt: nil, Warning: "package_database_unavailable"}, nil
	}
	planID = normalizePackageID(planID)
	if outputsTotal <= 0 {
		if count, ok := packageOutputCount(planID); ok {
			outputsTotal = count
		}
	}
	if outputsRemaining < 0 {
		outputsRemaining = 0
	}
	return customerPackageStatus{HasActivePackage: true, PlanID: &planID, Status: firstNonEmpty(status, "active"), OutputsTotal: outputsTotal, OutputsRemaining: outputsRemaining, RemainingOutputs: outputsRemaining, StartsAt: nullTimePtr(startsAt), ExpiresAt: nullTimePtr(expiresAt)}, nil
}

func nullTimePtr(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	return &value.Time
}
