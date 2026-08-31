from pathlib import Path

payments = Path('koschei/api/internal/handlers/payments.go')
p = payments.read_text()
anchor = '// revokePackageEntitlementDetailedTx revokes only the entitlement carrying the\n'
if 'func refreshPackageEntitlementPeriodTx' not in p:
    insert = '''func refreshPackageEntitlementPeriodTx(ctx context.Context, tx *sql.Tx, paymentProvider, externalPaymentID, packageID string, expiresAt any) (entitlementActivationResult, error) {
\tif tx == nil {
\t\treturn entitlementActivationResult{}, errors.New("db transaction nil")
\t}
\tprovider := normalizePaymentProvider(paymentProvider)
\texternalPaymentID = strings.TrimSpace(externalPaymentID)
\tpackageID = normalizePackageID(packageID)
\toutputs, ok := packageOutputCount(packageID)
\tif provider == "" || externalPaymentID == "" || !ok || outputs <= 0 {
\t\treturn entitlementActivationResult{}, errors.New("invalid entitlement renewal input")
\t}

\tvar email string
\terr := tx.QueryRowContext(ctx, `
\t\tUPDATE entitlements
\t\tSET outputs_total=$4, outputs_remaining=$4, starts_at=now(), expires_at=$5, updated_at=now()
\t\tWHERE payment_provider=$1 AND external_payment_id=$2 AND plan_id=$3 AND status='active'
\t\tRETURNING lower(COALESCE(email,''))`, provider, externalPaymentID, packageID, outputs, expiresAt).Scan(&email)
\tif err != nil {
\t\treturn entitlementActivationResult{}, err
\t}
\tif strings.TrimSpace(email) == "" {
\t\treturn entitlementActivationResult{}, errors.New("renewed entitlement missing email")
\t}
\treturn entitlementActivationResult{Activated: false, PackageID: packageID, OutputsTotal: outputs, OutputsRemaining: outputs}, nil
}

'''
    if anchor not in p:
        raise SystemExit('payments renewal insertion anchor missing')
    payments.write_text(p.replace(anchor, insert + anchor, 1))

polar = Path('koschei/api/internal/handlers/polar_billing.go')
s = polar.read_text()
old_struct = '''type polarSubscription struct {
\tID               string         `json:"id"`
\tStatus           string         `json:"status"`
\tCustomerID       string         `json:"customer_id"`
\tProductID        string         `json:"product_id"`
\tCheckoutID       string         `json:"checkout_id"`
\tCurrentPeriodEnd string         `json:"current_period_end"`
\tMetadata         map[string]any `json:"metadata"`
}
'''
new_struct = '''type polarSubscription struct {
\tID               string             `json:"id"`
\tStatus           string             `json:"status"`
\tCustomerID       string             `json:"customer_id"`
\tProductID        string             `json:"product_id"`
\tCheckoutID       string             `json:"checkout_id"`
\tCurrentPeriodEnd string             `json:"current_period_end"`
\tMetadata         map[string]any     `json:"metadata"`
\tBillingReason    string             `json:"billing_reason"`
\tPaid             bool               `json:"paid"`
\tSubscriptionID   string             `json:"subscription_id"`
\tSubscription     *polarSubscription `json:"subscription"`
}
'''
if 'BillingReason' not in s:
    if old_struct not in s:
        raise SystemExit('polar struct anchor missing')
    s = s.replace(old_struct, new_struct, 1)

old_normalize = '''\toccurredAt := polarOccurredAt(envelope.Timestamp, signedAt)
\tsubscription := envelope.Data
\tsubscription.ID = strings.TrimSpace(subscription.ID)
'''
new_normalize = '''\toccurredAt := polarOccurredAt(envelope.Timestamp, signedAt)
\tsubscription := polarSubscriptionForEnvelope(envelope)
\tsubscription.ID = strings.TrimSpace(subscription.ID)
'''
if 'subscription := polarSubscriptionForEnvelope(envelope)' not in s:
    if old_normalize not in s:
        raise SystemExit('polar normalization anchor missing')
    s = s.replace(old_normalize, new_normalize, 1)

old_binding = '''\tswitch envelope.Type {
\tcase "subscription.active", "subscription.revoked":
\t\tif subscription.ID == "" || plan == "" || metadataPlan != plan || authSubject == "" || email == "" {
'''
new_binding = '''\trequiresSubscriptionBinding := envelope.Type == "subscription.active" || envelope.Type == "subscription.revoked" || polarIsPaidSubscriptionCycle(envelope)
\tif requiresSubscriptionBinding {
\t\tif subscription.ID == "" || plan == "" || metadataPlan != plan || authSubject == "" || email == "" {
'''
if 'requiresSubscriptionBinding :=' not in s:
    if old_binding not in s:
        raise SystemExit('polar binding anchor missing')
    s = s.replace(old_binding, new_binding, 1)

renewal_anchor = '''\tcase "subscription.revoked":
\t\trevocation, err := revokePackageEntitlementDetailedTx(r.Context(), tx, "polar", subscription.ID)
'''
renewal_case = '''\tcase "order.paid":
\t\tif !polarIsPaidSubscriptionCycle(envelope) {
\t\t\tresponse["entitlement_changed"] = false
\t\t\tbreak
\t\t}
\t\tif !strings.EqualFold(strings.TrimSpace(subscription.Status), "active") {
\t\t\twriteJSON(w, http.StatusConflict, map[string]string{"error": "renewal_subscription_not_active"})
\t\t\treturn
\t\t}
\t\trefreshed, err := refreshPackageEntitlementPeriodTx(r.Context(), tx, "polar", subscription.ID, plan, polarNullableTime(subscription.CurrentPeriodEnd))
\t\tif errors.Is(err, sql.ErrNoRows) {
\t\t\twriteJSON(w, http.StatusConflict, map[string]string{"error": "renewal_entitlement_missing"})
\t\t\treturn
\t\t}
\t\tif err != nil {
\t\t\twriteJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "entitlement_renewal_failed"})
\t\t\treturn
\t\t}
\t\tresponse["entitlement_refreshed"] = true
\t\tresponse["plan"] = refreshed.PackageID
\t\tresponse["outputs_remaining"] = refreshed.OutputsRemaining
'''
if 'case "order.paid":' not in s:
    if renewal_anchor not in s:
        raise SystemExit('polar renewal action anchor missing')
    s = s.replace(renewal_anchor, renewal_case + renewal_anchor, 1)

helper_anchor = 'func polarMetadataString(values map[string]any, key string) string {'
if 'func polarSubscriptionForEnvelope' not in s:
    helpers = '''func polarIsPaidSubscriptionCycle(envelope polarWebhookEnvelope) bool {
\treturn envelope.Type == "order.paid" && envelope.Data.Paid && strings.EqualFold(strings.TrimSpace(envelope.Data.BillingReason), "subscription_cycle")
}

func polarSubscriptionForEnvelope(envelope polarWebhookEnvelope) polarSubscription {
\tif envelope.Type != "order.paid" {
\t\treturn envelope.Data
\t}
\torder := envelope.Data
\tif order.Subscription == nil {
\t\treturn polarSubscription{ID: strings.TrimSpace(order.SubscriptionID), ProductID: strings.TrimSpace(order.ProductID), Metadata: order.Metadata}
\t}
\tsubscription := *order.Subscription
\tif strings.TrimSpace(subscription.ID) == "" {
\t\tsubscription.ID = strings.TrimSpace(order.SubscriptionID)
\t}
\tif strings.TrimSpace(subscription.ProductID) == "" {
\t\tsubscription.ProductID = strings.TrimSpace(order.ProductID)
\t}
\tif len(subscription.Metadata) == 0 {
\t\tsubscription.Metadata = order.Metadata
\t}
\treturn subscription
}

'''
    if helper_anchor not in s:
        raise SystemExit('polar helper anchor missing')
    s = s.replace(helper_anchor, helpers + helper_anchor, 1)
polar.write_text(s)

tests = Path('koschei/api/internal/handlers/polar_billing_test.go')
t = tests.read_text()
if 'TestPolarPaidSubscriptionCycleNormalization' not in t:
    t += '''

func TestPolarPaidSubscriptionCycleNormalization(t *testing.T) {
\tenvelope := polarWebhookEnvelope{
\t\tType: "order.paid",
\t\tData: polarSubscription{
\t\t\tPaid:           true,
\t\t\tBillingReason:  "subscription_cycle",
\t\t\tSubscriptionID: "sub_123",
\t\t\tProductID:      "prod_starter",
\t\t\tSubscription: &polarSubscription{
\t\t\t\tStatus:           "active",
\t\t\t\tCurrentPeriodEnd: "2026-10-01T00:00:00Z",
\t\t\t\tMetadata: map[string]any{
\t\t\t\t\t"koschei_auth_subject": "auth-123",
\t\t\t\t\t"koschei_email":        "user@example.com",
\t\t\t\t\t"koschei_plan":         "starter",
\t\t\t\t},
\t\t\t},
\t\t},
\t}
\tif !polarIsPaidSubscriptionCycle(envelope) {
\t\tt.Fatal("paid subscription cycle not recognized")
\t}
\tsubscription := polarSubscriptionForEnvelope(envelope)
\tif subscription.ID != "sub_123" || subscription.ProductID != "prod_starter" || subscription.Status != "active" {
\t\tt.Fatalf("unexpected normalized renewal subscription: %#v", subscription)
\t}
\tif polarIsPaidSubscriptionCycle(polarWebhookEnvelope{Type: "order.paid", Data: polarSubscription{Paid: false, BillingReason: "subscription_cycle"}}) {
\t\tt.Fatal("unpaid order accepted as renewal")
\t}
\tif polarIsPaidSubscriptionCycle(polarWebhookEnvelope{Type: "order.paid", Data: polarSubscription{Paid: true, BillingReason: "subscription_update"}}) {
\t\tt.Fatal("proration order accepted as renewal")
\t}
}
'''
    tests.write_text(t)

docs = Path('docs/payment-paths.md')
d = docs.read_text()
old = '7. `subscription.canceled` and `subscription.past_due` are recorded but do not immediately revoke Koschei access; Polar can keep paid-period/grace-period access alive in those states.\n8. For `subscription.revoked`, only the entitlement carrying the exact `polar` provider plus subscription ID evidence is revoked. Other manual/provider grants are not touched, and the customer profile is recomputed from any remaining active entitlement.\n9. Duplicate events are idempotent, and an older `subscription.active` event cannot re-enable access after a newer/equal recorded revocation.'
new = '7. `subscription.canceled` and `subscription.past_due` are recorded but do not immediately revoke Koschei access; Polar can keep paid-period/grace-period access alive in those states.\n8. A verified `order.paid` with `billing_reason=subscription_cycle` and an active, correctly bound subscription refreshes that exact Polar entitlement period and restores the plan output capacity. Pending `order.created`, unpaid orders, purchases and proration orders do not refresh quota.\n9. For `subscription.revoked`, only the entitlement carrying the exact `polar` provider plus subscription ID evidence is revoked. Other manual/provider grants are not touched, and the customer profile is recomputed from any remaining active entitlement.\n10. Duplicate events are idempotent, and an older `subscription.active` event cannot re-enable access after a newer/equal recorded revocation.'
if old in d:
    d = d.replace(old, new, 1)
if 'Required Polar webhook events:' not in d:
    marker = 'No Polar public-config endpoint exists.'
    addition = 'Required Polar webhook events: `subscription.active`, `subscription.revoked`, and `order.paid`. Other signed subscription events may be retained as audit evidence but do not independently grant paid access.\n\n'
    if marker not in d:
        raise SystemExit('payment docs marker missing')
    d = d.replace(marker, addition + marker, 1)
docs.write_text(d)
