package handlers

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

func entitlementEmailFromSubject(authSubject string) string {
	subject := strings.TrimSpace(authSubject)
	if subject == "" {
		return ""
	}
	lower := strings.ToLower(subject)
	if strings.HasPrefix(lower, "local:") {
		return strings.ToLower(strings.TrimSpace(subject[len("local:"):]))
	}
	if strings.Contains(subject, "@") {
		return strings.ToLower(subject)
	}
	return ""
}

// Legacy package counters remain readable for historical owner data, but they
// no longer grant customer access or control product usage.
func (h *Handler) userCreditsAndRole(authSubject string, emails ...string) (bool, int, error) {
	authSubject = strings.TrimSpace(authSubject)
	email := ""
	if len(emails) > 0 {
		email = strings.ToLower(strings.TrimSpace(emails[0]))
	}
	if email == "" {
		email = entitlementEmailFromSubject(authSubject)
	}

	var available int
	err := h.DB.QueryRow(`
		WITH identity AS (
			SELECT lower(p.email) AS email
			FROM app_user_profiles p
			WHERE p.status = 'active'
			  AND (
				($1 <> '' AND p.auth_subject = $1)
				OR ($2 <> '' AND lower(p.email) = lower($2))
			  )
			ORDER BY CASE WHEN $1 <> '' AND p.auth_subject = $1 THEN 0 ELSE 1 END,
			         p.updated_at DESC,
			         p.created_at DESC
			LIMIT 1
		)
		SELECT COALESCE(SUM(e.outputs_remaining), 0)::int
		FROM entitlements e
		JOIN identity i ON lower(e.email) = i.email
		WHERE e.status = 'active'
		  AND COALESCE(e.plan_id, '') <> 'free'
		  AND COALESCE(e.outputs_remaining, 0) > 0
		  AND (e.expires_at IS NULL OR e.expires_at > now())`, authSubject, email).Scan(&available)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, 0, nil
		}
		return false, 0, err
	}
	return false, available, nil
}

func (h *Handler) applyCreditChargeTxWithReason(tx *sql.Tx, authSubject, email, reason string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	authSubject = strings.TrimSpace(authSubject)
	if email == "" {
		email = entitlementEmailFromSubject(authSubject)
	}

	var activeEmail string
	err := tx.QueryRow(`
		SELECT lower(p.email)
		FROM app_user_profiles p
		WHERE p.status = 'active'
		  AND (
			($1 <> '' AND p.auth_subject = $1)
			OR ($2 <> '' AND lower(p.email) = lower($2))
		  )
		ORDER BY CASE WHEN $1 <> '' AND p.auth_subject = $1 THEN 0 ELSE 1 END,
		         p.updated_at DESC,
		         p.created_at DESC
		LIMIT 1`, authSubject, email).Scan(&activeEmail)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("active profile required")
	}
	if err != nil {
		return err
	}

	res, err := tx.Exec(`
		UPDATE entitlements
		SET outputs_remaining = GREATEST(outputs_remaining - 1, 0),
		    updated_at = now()
		WHERE id = (
			SELECT id
			FROM entitlements
			WHERE lower(email) = lower($1)
			  AND status = 'active'
			  AND COALESCE(plan_id, '') <> 'free'
			  AND COALESCE(outputs_remaining, 0) > 0
			  AND (expires_at IS NULL OR expires_at > now())
			ORDER BY outputs_remaining DESC, created_at DESC
			LIMIT 1
			FOR UPDATE
		)`, activeEmail)
	if err != nil {
		return err
	}
	if rows, err := res.RowsAffected(); err != nil {
		return err
	} else if rows == 1 {
		_, err = tx.Exec(`INSERT INTO credit_events (email, amount, reason, event_type) VALUES (lower($1), -1, $2, $3)`, activeEmail, reason, reason)
		return err
	}

	return errors.New("active package output required")
}

// Route-level EnforcePlanOutput owns commercial output consumption. This
// compatibility helper intentionally remains a no-op so older handlers do not
// double-charge an already-reserved SaaS output.
func (h *Handler) consumePremiumOutput(authSubject, email, reason string) error {
	return nil
}

func (h *Handler) hasActivePaidPackage(authSubject, email string) (bool, error) {
	if h == nil || h.DB == nil {
		return false, errors.New("database unavailable")
	}
	evaluation, err := h.evaluatePlanAccess(context.Background(), authSubject, email)
	if err != nil {
		return false, err
	}
	return evaluation.Active && planTierAuthorizes(evaluation.Plan, "starter"), nil
}

// Existing premium handlers may still perform an internal preflight in addition
// to the route-level SaaS gate. Keep that compatibility check entitlement-backed
// so it can never reintroduce KOSCH holder authorization.
func (h *Handler) requirePremiumOutput(authSubject string, emails ...string) (int, error) {
	if h == nil || h.DB == nil {
		return 0, errors.New("database unavailable")
	}
	email := ""
	if len(emails) > 0 {
		email = strings.ToLower(strings.TrimSpace(emails[0]))
	}
	evaluation, err := h.evaluatePlanAccess(context.Background(), authSubject, email)
	if err != nil {
		return 0, err
	}
	if !evaluation.Active || !planTierAuthorizes(evaluation.Plan, "starter") || evaluation.OutputsRemaining <= 0 {
		return 0, errors.New("active package output required")
	}
	return evaluation.OutputsRemaining, nil
}
