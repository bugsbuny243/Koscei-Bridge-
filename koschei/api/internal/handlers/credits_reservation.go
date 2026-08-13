package handlers

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

type premiumOutputReservation struct {
	EntitlementID string
	Email         string
	Reason        string
}

func (h *Handler) reservePremiumOutput(ctx context.Context, authSubject, email, reason string) (premiumOutputReservation, error) {
	if h == nil || h.DB == nil {
		return premiumOutputReservation{}, errors.New("database unavailable")
	}
	authSubject = strings.TrimSpace(authSubject)
	email = strings.ToLower(strings.TrimSpace(email))
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "premium_output"
	}
	if email == "" {
		email = entitlementEmailFromSubject(authSubject)
	}
	if email == "" && authSubject != "" {
		_ = h.DB.QueryRowContext(ctx, `SELECT lower(email) FROM app_user_profiles WHERE auth_subject=$1`, authSubject).Scan(&email)
	}
	if email == "" {
		return premiumOutputReservation{}, errors.New("entitlement email unavailable")
	}

	tx, err := h.DB.BeginTx(ctx, nil)
	if err != nil {
		return premiumOutputReservation{}, err
	}
	defer tx.Rollback()

	var entitlementID, normalizedEmail string
	err = tx.QueryRowContext(ctx, `
		UPDATE entitlements
		SET outputs_remaining = outputs_remaining - 1,
		    updated_at = now()
		WHERE id = (
			SELECT id
			FROM entitlements
			WHERE lower(email)=lower($1)
			  AND status='active'
			  AND COALESCE(plan_id,'') <> ''
			  AND COALESCE(plan_id,'') <> 'free'
			  AND COALESCE(outputs_remaining,0) > 0
			  AND (expires_at IS NULL OR expires_at > now())
			ORDER BY outputs_remaining DESC, created_at DESC
			LIMIT 1
			FOR UPDATE
		)
		RETURNING id::text, lower(email)
	`, email).Scan(&entitlementID, &normalizedEmail)
	if errors.Is(err, sql.ErrNoRows) {
		return premiumOutputReservation{}, errors.New("active package output required")
	}
	if err != nil {
		return premiumOutputReservation{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO credit_events(email,amount,reason,event_type) VALUES(lower($1),-1,$2,$3)`, normalizedEmail, reason+"_reserved", "reserve"); err != nil {
		return premiumOutputReservation{}, err
	}
	if err := tx.Commit(); err != nil {
		return premiumOutputReservation{}, err
	}
	return premiumOutputReservation{EntitlementID: entitlementID, Email: normalizedEmail, Reason: reason}, nil
}

func (h *Handler) refundPremiumOutputReservation(ctx context.Context, reservation premiumOutputReservation, refundReason string) error {
	if h == nil || h.DB == nil || strings.TrimSpace(reservation.EntitlementID) == "" {
		return nil
	}
	refundReason = strings.TrimSpace(refundReason)
	if refundReason == "" {
		refundReason = reservation.Reason + "_refund"
	}
	tx, err := h.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `
		UPDATE entitlements
		SET outputs_remaining = LEAST(outputs_remaining + 1, outputs_total),
		    updated_at = now()
		WHERE id=$1::uuid
	`, reservation.EntitlementID)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return errors.New("reserved entitlement not found")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO credit_events(email,amount,reason,event_type) VALUES(lower($1),1,$2,$3)`, reservation.Email, refundReason, "refund"); err != nil {
		return err
	}
	return tx.Commit()
}
