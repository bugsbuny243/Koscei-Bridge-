package handlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"
)

type planAccessEvaluation struct {
	Active           bool       `json:"active"`
	Plan             string     `json:"plan"`
	OutputsTotal     int        `json:"outputs_total"`
	OutputsRemaining int        `json:"outputs_remaining"`
	StartsAt         *time.Time `json:"starts_at,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	Source           string     `json:"source"`
}

type planAccessRequestContext struct {
	Evaluation  planAccessEvaluation
	AuthSubject string
	Email       string
}

type planAccessRequestContextKey struct{}

// canonicalSaaSPlan exposes one paid SaaS entitlement: Professional.
func canonicalSaaSPlan(plan string) string {
	if strings.EqualFold(strings.TrimSpace(plan), "professional") {
		return "professional"
	}
	return ""
}

func planTierRank(plan string) int {
	if canonicalSaaSPlan(plan) == "professional" {
		return 1
	}
	return 0
}

func planTierAuthorizes(current, required string) bool {
	currentRank := planTierRank(current)
	requiredRank := planTierRank(required)
	return currentRank > 0 && requiredRank > 0 && currentRank >= requiredRank
}

func withPlanAccessRequestContext(ctx context.Context, value planAccessRequestContext) context.Context {
	return context.WithValue(ctx, planAccessRequestContextKey{}, value)
}

func planAccessRequestFromContext(ctx context.Context) (planAccessRequestContext, bool) {
	value, ok := ctx.Value(planAccessRequestContextKey{}).(planAccessRequestContext)
	return value, ok
}

func (h *Handler) evaluatePlanAccess(ctx context.Context, authSubject, claimEmail string) (planAccessEvaluation, error) {
	if h == nil || h.DB == nil {
		return planAccessEvaluation{}, errors.New("database unavailable")
	}
	authSubject = strings.TrimSpace(authSubject)
	email := strings.ToLower(strings.TrimSpace(claimEmail))
	if email == "" {
		email = entitlementEmailFromSubject(authSubject)
	}
	if email == "" && authSubject != "" {
		_ = h.DB.QueryRowContext(ctx, `
			SELECT lower(email)
			FROM app_user_profiles
			WHERE auth_subject=$1 AND status='active'
			ORDER BY updated_at DESC, created_at DESC
			LIMIT 1`, authSubject).Scan(&email)
	}
	if email == "" {
		return planAccessEvaluation{Plan: "none", Source: "entitlement"}, nil
	}

	var plan string
	var total, remaining int
	var startsAt, expiresAt sql.NullTime
	err := h.DB.QueryRowContext(ctx, `
		SELECT COALESCE(plan_id,''), COALESCE(outputs_total,0), COALESCE(outputs_remaining,0), starts_at, expires_at
		FROM entitlements
		WHERE lower(email)=lower($1)
		  AND status='active'
		  AND lower(COALESCE(plan_id,''))='professional'
		  AND (expires_at IS NULL OR expires_at > now())
		ORDER BY updated_at DESC NULLS LAST, created_at DESC
		LIMIT 1`, email).Scan(&plan, &total, &remaining, &startsAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return planAccessEvaluation{Plan: "none", Source: "entitlement"}, nil
	}
	if err != nil {
		return planAccessEvaluation{}, err
	}
	plan = canonicalSaaSPlan(plan)
	if planTierRank(plan) == 0 {
		return planAccessEvaluation{Plan: "none", Source: "entitlement"}, nil
	}
	if total < 0 {
		total = 0
	}
	if remaining < 0 {
		remaining = 0
	}
	return planAccessEvaluation{
		Active:           true,
		Plan:             plan,
		OutputsTotal:     total,
		OutputsRemaining: remaining,
		StartsAt:         nullTimePtr(startsAt),
		ExpiresAt:        nullTimePtr(expiresAt),
		Source:           "entitlement",
	}, nil
}

func (h *Handler) RequirePlanTier(required string, next http.HandlerFunc) http.HandlerFunc {
	required = canonicalSaaSPlan(required)
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := userFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if planTierRank(required) == 0 {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "invalid_required_plan"})
			return
		}
		evaluation, err := h.evaluatePlanAccess(r.Context(), claims.Sub, normalizedClaimEmail(claims))
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "plan_access_unavailable"})
			return
		}
		if !evaluation.Active || !planTierAuthorizes(evaluation.Plan, required) {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error": "plan_tier_required", "required_plan": required, "current_plan": evaluation.Plan,
			})
			return
		}
		ctx := withPlanAccessRequestContext(r.Context(), planAccessRequestContext{
			Evaluation: evaluation, AuthSubject: claims.Sub, Email: normalizedClaimEmail(claims),
		})
		next(w, r.WithContext(ctx))
	}
}

func (h *Handler) RequireAPIKeyPlanTier(required string, next http.HandlerFunc) http.HandlerFunc {
	required = canonicalSaaSPlan(required)
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := apiPrincipalFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if planTierRank(required) == 0 {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "invalid_required_plan"})
			return
		}
		evaluation, err := h.evaluatePlanAccess(r.Context(), principal.AuthSubject, principal.Email)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "plan_access_unavailable"})
			return
		}
		if !evaluation.Active || !planTierAuthorizes(evaluation.Plan, required) {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error": "plan_tier_required", "required_plan": required, "current_plan": evaluation.Plan,
			})
			return
		}
		next(w, r)
	}
}

func (h *Handler) EnforcePlanOutput(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		access, ok := planAccessRequestFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "plan_context_unavailable"})
			return
		}
		reservation, err := h.reservePremiumOutput(r.Context(), access.AuthSubject, access.Email, "saas_"+access.Evaluation.Plan+"_output")
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "active package output required") {
				writeJSON(w, http.StatusTooManyRequests, map[string]any{
					"error": "plan_outputs_exhausted", "plan": access.Evaluation.Plan,
				})
				return
			}
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "plan_output_reservation_unavailable"})
			return
		}

		tracker := &quotaResponseWriter{ResponseWriter: w, status: http.StatusOK}
		consumeReservation := false
		defer func() {
			if recovered := recover(); recovered != nil {
				refundPlanOutputDetached(h, reservation)
				panic(recovered)
			}
			if !consumeReservation {
				refundPlanOutputDetached(h, reservation)
			}
		}()
		next(tracker, r)
		consumeReservation = tracker.shouldConsumeQuota()
	}
}

func refundPlanOutputDetached(h *Handler, reservation premiumOutputReservation) {
	if h == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = h.refundPremiumOutputReservation(ctx, reservation, "saas_output_refund")
}
