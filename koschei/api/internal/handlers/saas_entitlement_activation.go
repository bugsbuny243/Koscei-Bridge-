package handlers

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

type entitlementActivationResult struct {
	Activated        bool
	PackageID        string
	OutputsTotal     int
	OutputsRemaining int
}

func packageOutputCount(plan string) (int, bool) {
	switch canonicalSaaSPlan(plan) {
	case "starter":
		return 25, true
	case "professional":
		return 100, true
	case "enterprise":
		return 300, true
	default:
		return 0, false
	}
}

func activatePackageEntitlementDetailedTx(ctx context.Context, tx *sql.Tx, email, plan, paymentProvider, externalPaymentID, paymentRequestID, orderID, productID string, expiresAt any) (entitlementActivationResult, error) {
	if tx == nil {
		return entitlementActivationResult{}, errors.New("transaction unavailable")
	}
	email = strings.ToLower(strings.TrimSpace(email))
	plan = canonicalSaaSPlan(plan)
	provider := strings.ToLower(strings.TrimSpace(paymentProvider))
	externalPaymentID = strings.TrimSpace(externalPaymentID)
	paymentRequestID = strings.TrimSpace(paymentRequestID)
	orderID = strings.TrimSpace(orderID)
	outputs, ok := packageOutputCount(plan)
	if email == "" || !ok || outputs <= 0 || provider == "" {
		return entitlementActivationResult{}, errors.New("invalid entitlement activation input")
	}

	if externalPaymentID != "" {
		var existingID, existingPlan string
		var existingTotal, existingRemaining int
		err := tx.QueryRowContext(ctx, `
			SELECT id::text, COALESCE(plan_id,''), COALESCE(outputs_total,0), COALESCE(outputs_remaining,0)
			FROM entitlements
			WHERE payment_provider=$1 AND external_payment_id=$2
			ORDER BY created_at DESC
			LIMIT 1`, provider, externalPaymentID).Scan(&existingID, &existingPlan, &existingTotal, &existingRemaining)
		if err == nil {
			_, err = tx.ExecContext(ctx, `
				UPDATE entitlements
				SET email=lower($1), plan_id=$2, status='active', starts_at=COALESCE(starts_at,now()), expires_at=$3,
				    order_id=COALESCE(NULLIF($4,'')::uuid,order_id), outputs_total=GREATEST(COALESCE(outputs_total,0),$5),
				    outputs_remaining=GREATEST(COALESCE(outputs_remaining,0),$5), updated_at=now()
				WHERE id=$6::uuid`, email, plan, expiresAt, orderID, outputs, existingID)
			if err != nil {
				return entitlementActivationResult{}, err
			}
			return entitlementActivationResult{
				Activated:        false,
				PackageID:        canonicalSaaSPlan(existingPlan),
				OutputsTotal:     maxInt(existingTotal, outputs),
				OutputsRemaining: maxInt(existingRemaining, outputs),
			}, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return entitlementActivationResult{}, err
		}
	}

	var activeID string
	err := tx.QueryRowContext(ctx, `
		SELECT id::text
		FROM entitlements
		WHERE lower(email)=lower($1)
		  AND status='active'
		  AND COALESCE(plan_id,'')<>''
		  AND COALESCE(plan_id,'')<>'free'
		ORDER BY updated_at DESC NULLS LAST, created_at DESC
		LIMIT 1
		FOR UPDATE`, email).Scan(&activeID)
	if err == nil {
		_, err = tx.ExecContext(ctx, `
			UPDATE entitlements
			SET plan_id=$2, payment_request_id=COALESCE(NULLIF($3,''),payment_request_id), payment_provider=$4,
			    external_payment_id=NULLIF($5,''), outputs_total=GREATEST(COALESCE(outputs_total,0),$6),
			    outputs_remaining=GREATEST(COALESCE(outputs_remaining,0),$6), starts_at=COALESCE(starts_at,now()),
			    expires_at=$7, order_id=COALESCE(NULLIF($8,'')::uuid,order_id), updated_at=now()
			WHERE id=$1::uuid`, activeID, plan, paymentRequestID, provider, externalPaymentID, outputs, expiresAt, orderID)
		if err != nil {
			return entitlementActivationResult{}, err
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		if paymentRequestID != "" {
			_, err = tx.ExecContext(ctx, `
				INSERT INTO entitlements
				(email,plan_id,payment_request_id,payment_provider,external_payment_id,outputs_total,outputs_remaining,status,starts_at,expires_at,order_id,created_at,updated_at)
				VALUES (lower($1),$2,$3,$4,NULLIF($5,''),$6,$6,'active',now(),$7,NULLIF($8,'')::uuid,now(),now())`,
				email, plan, paymentRequestID, provider, externalPaymentID, outputs, expiresAt, orderID)
		} else {
			_, err = tx.ExecContext(ctx, `
				INSERT INTO entitlements
				(email,plan_id,payment_provider,external_payment_id,outputs_total,outputs_remaining,status,starts_at,expires_at,order_id,created_at,updated_at)
				VALUES (lower($1),$2,$3,NULLIF($4,''),$5,$5,'active',now(),$6,NULLIF($7,'')::uuid,now(),now())`,
				email, plan, provider, externalPaymentID, outputs, expiresAt, orderID)
		}
		if err != nil {
			return entitlementActivationResult{}, err
		}
	} else {
		return entitlementActivationResult{}, err
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE app_user_profiles
		SET plan_id=CASE
			WHEN CASE $2 WHEN 'enterprise' THEN 3 WHEN 'professional' THEN 2 WHEN 'starter' THEN 1 ELSE 0 END >=
			     CASE lower(COALESCE(plan_id,'free')) WHEN 'enterprise' THEN 3 WHEN 'studio' THEN 3 WHEN 'professional' THEN 2 WHEN 'builder' THEN 2 WHEN 'pro' THEN 2 WHEN 'starter' THEN 1 WHEN 'basic' THEN 1 ELSE 0 END
			THEN $2 ELSE plan_id END,
			updated_at=now()
		WHERE lower(email)=lower($1)`, email, plan); err != nil {
		return entitlementActivationResult{}, err
	}

	return entitlementActivationResult{Activated: true, PackageID: plan, OutputsTotal: outputs, OutputsRemaining: outputs}, nil
}
