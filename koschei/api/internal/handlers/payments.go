package handlers

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

type saasPackage struct {
	ID      string
	Name    string
	Outputs int
}

var saasPackages = map[string]saasPackage{
	"starter":      {ID: "starter", Name: "Koschei Starter", Outputs: 25},
	"professional": {ID: "professional", Name: "Koschei Professional", Outputs: 100},
	"enterprise":   {ID: "enterprise", Name: "Koschei Enterprise", Outputs: 300},
}

type entitlementActivationResult struct {
	Activated        bool
	PackageID        string
	OutputsTotal     int
	OutputsRemaining int
}

type entitlementRevocationResult struct {
	Revoked     bool
	Email       string
	ProfilePlan string
}

func normalizePackageID(packageID string) string {
	switch strings.ToLower(strings.TrimSpace(packageID)) {
	case "starter":
		return "starter"
	case "builder", "pro", "professional":
		return "professional"
	case "studio", "enterprise":
		return "enterprise"
	default:
		return ""
	}
}

func packageOutputCount(packageID string) (int, bool) {
	pack, ok := saasPackages[normalizePackageID(packageID)]
	return pack.Outputs, ok
}

func packageName(packageID string) string {
	pack, ok := saasPackages[normalizePackageID(packageID)]
	if !ok {
		return ""
	}
	return pack.Name
}

func normalizePaymentProvider(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "polar", "shopier", "shopier_manual", "owner_manual":
		return strings.ToLower(strings.TrimSpace(provider))
	default:
		return ""
	}
}

func (h *Handler) activatePackageEntitlement(ctx context.Context, email, packageID, paymentProvider, externalPaymentID string) (entitlementActivationResult, error) {
	if h == nil || h.DB == nil {
		return entitlementActivationResult{}, errors.New("db nil")
	}
	tx, err := h.DB.BeginTx(ctx, nil)
	if err != nil {
		return entitlementActivationResult{}, err
	}
	defer tx.Rollback()
	result, err := activatePackageEntitlementTx(ctx, tx, email, packageID, paymentProvider, externalPaymentID, "")
	if err != nil {
		return entitlementActivationResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return entitlementActivationResult{}, err
	}
	return result, nil
}

func activatePackageEntitlementTx(ctx context.Context, tx *sql.Tx, email, packageID, paymentProvider, externalPaymentID, paymentRequestID string) (entitlementActivationResult, error) {
	return activatePackageEntitlementDetailedTx(ctx, tx, email, packageID, paymentProvider, externalPaymentID, paymentRequestID, "", "", nil)
}

func activatePackageEntitlementDetailedTx(ctx context.Context, tx *sql.Tx, email, packageID, paymentProvider, externalPaymentID, paymentRequestID, orderID, productID string, expiresAt any) (entitlementActivationResult, error) {
	if tx == nil {
		return entitlementActivationResult{}, errors.New("db transaction nil")
	}
	email = strings.ToLower(strings.TrimSpace(email))
	packageID = normalizePackageID(packageID)
	provider := normalizePaymentProvider(paymentProvider)
	externalPaymentID = strings.TrimSpace(externalPaymentID)
	paymentRequestID = strings.TrimSpace(paymentRequestID)
	orderID = strings.TrimSpace(orderID)
	outputs, ok := packageOutputCount(packageID)
	if email == "" || provider == "" || !ok || outputs <= 0 {
		return entitlementActivationResult{}, errors.New("invalid entitlement activation input")
	}

	if externalPaymentID != "" {
		var existingID, existingPackage string
		var existingTotal, existingRemaining int
		err := tx.QueryRowContext(ctx, `
			SELECT id::text, COALESCE(plan_id,''), COALESCE(outputs_total,0), COALESCE(outputs_remaining,0)
			FROM entitlements
			WHERE payment_provider = $1 AND external_payment_id = $2
			ORDER BY created_at DESC
			LIMIT 1`, provider, externalPaymentID).Scan(&existingID, &existingPackage, &existingTotal, &existingRemaining)
		if err == nil {
			_, err = tx.ExecContext(ctx, `
				UPDATE entitlements
				SET email=lower($1), plan_id=$2, status='active', starts_at=COALESCE(starts_at, now()), expires_at=$3,
				    order_id=COALESCE(NULLIF($4,'')::uuid, order_id), outputs_total=GREATEST(COALESCE(outputs_total,0), $5),
				    outputs_remaining=GREATEST(COALESCE(outputs_remaining,0), $5), updated_at=now()
				WHERE id=$6::uuid`, email, packageID, expiresAt, orderID, outputs, existingID)
			if err != nil {
				return entitlementActivationResult{}, err
			}
			return entitlementActivationResult{Activated: false, PackageID: normalizePackageID(existingPackage), OutputsTotal: maxInt(existingTotal, outputs), OutputsRemaining: maxInt(existingRemaining, outputs)}, nil
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
		  AND COALESCE(plan_id, '') <> ''
		  AND COALESCE(plan_id, '') <> 'free'
		ORDER BY updated_at DESC NULLS LAST, created_at DESC
		LIMIT 1
		FOR UPDATE`, email).Scan(&activeID)
	if err == nil {
		_, err = tx.ExecContext(ctx, `
			UPDATE entitlements
			SET plan_id=$2, payment_request_id=COALESCE(NULLIF($3,''), payment_request_id), payment_provider=$4,
			    external_payment_id=NULLIF($5,''), outputs_total=GREATEST(COALESCE(outputs_total,0), $6),
			    outputs_remaining=GREATEST(COALESCE(outputs_remaining,0), $6), starts_at=COALESCE(starts_at, now()),
			    expires_at=$7, order_id=COALESCE(NULLIF($8,'')::uuid, order_id), updated_at=now()
			WHERE id=$1::uuid`, activeID, packageID, paymentRequestID, provider, externalPaymentID, outputs, expiresAt, orderID)
		if err != nil {
			return entitlementActivationResult{}, err
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		if paymentRequestID != "" {
			_, err = tx.ExecContext(ctx, `
				INSERT INTO entitlements (email, plan_id, payment_request_id, payment_provider, external_payment_id, outputs_total, outputs_remaining, status, starts_at, expires_at, order_id, created_at, updated_at)
				VALUES (lower($1), $2, $3, $4, NULLIF($5, ''), $6, $6, 'active', now(), $7, NULLIF($8,'')::uuid, now(), now())`, email, packageID, paymentRequestID, provider, externalPaymentID, outputs, expiresAt, orderID)
		} else {
			_, err = tx.ExecContext(ctx, `
				INSERT INTO entitlements (email, plan_id, payment_provider, external_payment_id, outputs_total, outputs_remaining, status, starts_at, expires_at, order_id, created_at, updated_at)
				VALUES (lower($1), $2, $3, NULLIF($4, ''), $5, $5, 'active', now(), $6, NULLIF($7,'')::uuid, now(), now())`, email, packageID, provider, externalPaymentID, outputs, expiresAt, orderID)
		}
		if err != nil {
			return entitlementActivationResult{}, err
		}
	} else {
		return entitlementActivationResult{}, err
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE app_user_profiles
		SET plan_id = CASE
			WHEN CASE $2 WHEN 'enterprise' THEN 3 WHEN 'professional' THEN 2 WHEN 'starter' THEN 1 ELSE 0 END >=
			     CASE COALESCE(plan_id, 'free') WHEN 'enterprise' THEN 3 WHEN 'studio' THEN 3 WHEN 'professional' THEN 2 WHEN 'builder' THEN 2 WHEN 'starter' THEN 1 ELSE 0 END
			THEN $2
			ELSE plan_id
		END,
		updated_at = now()
		WHERE lower(email) = lower($1)`, email, packageID); err != nil {
		return entitlementActivationResult{}, err
	}

	return entitlementActivationResult{Activated: true, PackageID: packageID, OutputsTotal: outputs, OutputsRemaining: outputs}, nil
}

// revokePackageEntitlementDetailedTx revokes only the entitlement carrying the
// exact provider/external-payment evidence. It then derives the profile plan
// from any other still-active entitlement instead of blindly downgrading the
// account, preserving independent/manual access grants.
func revokePackageEntitlementDetailedTx(ctx context.Context, tx *sql.Tx, paymentProvider, externalPaymentID string) (entitlementRevocationResult, error) {
	if tx == nil {
		return entitlementRevocationResult{}, errors.New("db transaction nil")
	}
	provider := normalizePaymentProvider(paymentProvider)
	externalPaymentID = strings.TrimSpace(externalPaymentID)
	if provider == "" || externalPaymentID == "" {
		return entitlementRevocationResult{}, errors.New("invalid entitlement revocation input")
	}

	var email string
	err := tx.QueryRowContext(ctx, `
		UPDATE entitlements
		SET status='inactive', expires_at=LEAST(COALESCE(expires_at, now()), now()), updated_at=now()
		WHERE payment_provider=$1 AND external_payment_id=$2 AND status='active'
		RETURNING lower(COALESCE(email,''))`, provider, externalPaymentID).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return entitlementRevocationResult{Revoked: false}, nil
	}
	if err != nil {
		return entitlementRevocationResult{}, err
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return entitlementRevocationResult{}, errors.New("revoked entitlement missing email")
	}

	profilePlan := "free"
	var remainingPlan string
	err = tx.QueryRowContext(ctx, `
		SELECT COALESCE(plan_id,'free')
		FROM entitlements
		WHERE lower(email)=lower($1)
		  AND status='active'
		  AND (expires_at IS NULL OR expires_at > now())
		ORDER BY CASE COALESCE(plan_id,'free')
		           WHEN 'enterprise' THEN 3 WHEN 'studio' THEN 3
		           WHEN 'professional' THEN 2 WHEN 'builder' THEN 2
		           WHEN 'starter' THEN 1 ELSE 0 END DESC,
		         updated_at DESC NULLS LAST, created_at DESC
		LIMIT 1`, email).Scan(&remainingPlan)
	if err == nil {
		if normalized := normalizePackageID(remainingPlan); normalized != "" {
			profilePlan = normalized
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return entitlementRevocationResult{}, err
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE app_user_profiles
		SET plan_id=$2, updated_at=now()
		WHERE lower(email)=lower($1)`, email, profilePlan); err != nil {
		return entitlementRevocationResult{}, err
	}
	return entitlementRevocationResult{Revoked: true, Email: email, ProfilePlan: profilePlan}, nil
}
