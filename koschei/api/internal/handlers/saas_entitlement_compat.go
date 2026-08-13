package handlers

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// activatePackageEntitlement is the narrow transaction-owning wrapper retained
// for owner/Paddle-compatible SaaS entitlement activation. Payment-provider
// handlers supply provenance, but authorization is represented only by the
// entitlement written by activatePackageEntitlementDetailedTx.
func (h *Handler) activatePackageEntitlement(ctx context.Context, email, plan, paymentProvider, externalPaymentID string) (entitlementActivationResult, error) {
	if h == nil || h.DB == nil {
		return entitlementActivationResult{}, errors.New("database unavailable")
	}
	ctx = nonNilContext(ctx)
	tx, err := h.DB.BeginTx(ctx, nil)
	if err != nil {
		return entitlementActivationResult{}, err
	}
	defer func() { _ = tx.Rollback() }()

	result, err := activatePackageEntitlementDetailedTx(
		ctx,
		tx,
		strings.ToLower(strings.TrimSpace(email)),
		plan,
		paymentProvider,
		externalPaymentID,
		"",
		"",
		"",
		nil,
	)
	if err != nil {
		return entitlementActivationResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return entitlementActivationResult{}, err
	}
	return result, nil
}

// ensurePaymentSchema is a deliberate retirement tombstone. Legacy Shopier /
// manual-payment tables are no longer created at runtime. Migrations own schema
// creation; SaaS entitlement authority must never depend on resurrecting the
// retired payment subsystem from an HTTP/owner request path.
func ensurePaymentSchema(context.Context, *sql.DB) error {
	return nil
}

func nonNilContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
