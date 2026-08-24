'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const read=(...parts)=>fs.readFileSync(path.join(root,...parts),'utf8');
const server=read('internal','http','server.go');
const watch=read('internal','http','watchlist_routes.go');
const billingRoutes=read('internal','http','billing_routes.go');
const routeInventory=read('internal','http','route_inventory.go');
const staticAliases=read('internal','http','static_aliases.go');
const securityHeaders=read('internal','http','security_headers.go');
const plan=read('internal','handlers','plan_access.go');
const premium=read('internal','handlers','premium_access_status.go');
const history=read('internal','handlers','customer_investigation_history.go');
const dossierAccess=read('internal','handlers','dossier_access.go');
const retired=read('internal','handlers','kosch_retirement.go');
const credits=read('internal','handlers','credits_atomic.go');
const reservation=read('internal','handlers','credits_reservation.go');
const quotaWriter=read('internal','handlers','scan_quota.go');
const court=read('internal','handlers','court_narrative.go');
const courtRoute=read('internal','handlers','security_radar_court.go');
const paddle=read('internal','handlers','paddle_billing.go');
const paddlePublic=read('internal','handlers','paddle_public_config.go');
const apiKeys=read('internal','handlers','api_keys.go');
const migration=read('migrations','101_paddle_saas_billing_v1.sql');
const pricing=read('public','pricing.html');
const account=read('public','account.html');
const reports=read('public','reports.html');
const token2022=read('public','token-2022-scanner.html');
const checkout=read('public','js','paddle-checkout.js');
const hostedCheckout=read('public','paddle-checkout.html');
const hostedCheckoutJS=read('public','js','paddle-hosted-checkout.js');
const workspace=read('public','js','customer-workspace-v2.js');
const customerAccess=read('public','js','customer-access-v2.js');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden ${pattern}`);}

for(const legacy of [
  ['internal','handlers','token_access.go'],
  ['internal','handlers','api_key_kosch_access.go'],
  ['internal','handlers','kosch_security_policy.go'],
  ['internal','handlers','owner_kosch_access_v2.go']
]){
  if(fs.existsSync(path.join(root,...legacy)))throw new Error(`retired KOSCH commercial authorization file returned: ${legacy.join('/')}`);
}

requireText(server,'h.RequirePlanTier(plan, next)','customer SaaS authorization primitive');
requireText(server,'h.RequireAPIKeyPlanTier("enterprise"','developer Enterprise authorization');
requireText(server,'h.EnforcePlanOutput(next)','paid output meter');
requireText(server,'registerBillingRoutes(mux, h)','billing routes in boot chain');
forbid(server,/RequireTokenTier|RequireAPIKeyTokenTier|EnforceScanQuota/,'KOSCH/token authorization in boot chain');

requireText(watch,'h.RetiredTokenAccessStatus','legacy token-access tombstone route');
requireText(retired,'http.StatusGone','token access retired status');
requireText(retired,'access_model": "saas_entitlement"','token access replacement authority');

requireText(plan,'func canonicalSaaSPlan','canonical plan normalization');
for(const p of ['starter','professional','enterprise'])requireText(plan,`return "${p}"`,`${p} canonical plan`);
requireText(plan,'FROM entitlements','entitlement authorization source');
requireText(plan,"status='active'",'active entitlement requirement');
requireText(plan,'expires_at IS NULL OR expires_at > now()','entitlement expiration gate');
requireText(plan,'reservePremiumOutput','entitlement capacity reservation');
forbid(plan,/evaluateTokenAccess|tokenTier|KOSCH/i,'token evaluation inside SaaS authorization');

requireText(premium,'Source:           "entitlement"','premium status entitlement source');
forbid(premium,/token_(?:tier|amount)|TokenTier|TokenGate|KOSCH/i,'token fields in premium status');
requireText(history,'h.RequirePlanTier("starter", h.customerInvestigationHistoryRead)(w, r)','history Starter SaaS gate');
forbid(history,/RequireTokenTier|KOSCH access/i,'token-backed investigation history authorization');
requireText(dossierAccess,'h.APIKeyAuth(h.RequireAPIKeyPlanTier("enterprise", next))(w, r)','dossier API-key Enterprise SaaS gate');
requireText(dossierAccess,'RequireAuth(h.RequirePlanTier("enterprise", next))(w, r)','dossier session Enterprise SaaS gate');
requireText(dossierAccess,'KOSCH holdings and token-access snapshots','dossier token-separation boundary');
forbid(dossierAccess,/RequireStoredTokenTier|RequireAPIKeyStoredTokenTier|token_access_snapshots|tokenTierRank|evaluateStoredTokenAccess/,'token-backed dossier authorization');
requireText(apiKeys,'evaluation, evaluationErr := h.evaluatePlanAccess','API-key entitlement lookup');
requireText(apiKeys,'planTierAuthorizes(plan, "enterprise")','API-key Enterprise requirement');
forbid(apiKeys,/evaluateTokenAccess|token_tier/i,'token-backed API key issuance');

requireText(credits,'evaluation, err := h.evaluatePlanAccess(context.Background(), authSubject, email)','legacy premium compatibility uses SaaS entitlement');
requireText(credits,'planTierAuthorizes(evaluation.Plan, "starter")','legacy premium compatibility Starter boundary');
forbid(credits,/hasTokenTierAccess|evaluateTokenAccess|verified KOSCH holder|kosch_holder_required/i,'token-backed compatibility preflight');
requireText(reservation,'UPDATE entitlements','SaaS reservation ledger');
forbid(reservation,/KOSCH|kosch_quota|QuotaEventReason|QuotaTier|QuotaDayKey/i,'legacy KOSCH quota reservation state');
requireText(quotaWriter,'No token-balance or KOSCH-tier state is involved.','quota writer token separation');
forbid(quotaWriter,/EnforceScanQuota|configuredKOSCHDailyQuota|tokenAccessRequestContext|kosch_daily_scan/i,'retired KOSCH daily quota engine');
requireText(court,'planAccessRequestFromContext(ctx)','court reads SaaS plan context');
requireText(court,'h.evaluatePlanAccess(ctx, claims.Sub, normalizedClaimEmail(claims))','court fallback reads SaaS entitlement');
forbid(court,/tokenAccessRequestFromContext|evaluateTokenAccess|handlerScanQuotaLedger|KOSCHEI_COURT_QUOTA_/,'token-backed court tier or quota');
requireText(courtRoute,'planAccessRequestFromContext(ctx)','court request identity from SaaS context');
forbid(courtRoute,/authenticated KOSCH tier|tokenAccessRequestFromContext/,'token-backed court route semantics');

requireText(billingRoutes,'/paddle/public-config','Paddle browser config route');
forbid(billingRoutes,/\/api\/paddle\/public-config/,'browser config accidentally exposed as programmatic API');
requireText(billingRoutes,'/api/paddle/checkout','Paddle checkout route');
requireText(billingRoutes,'/api/paddle/webhook','Paddle webhook route');
requireText(paddle,'Paddle-Signature','Paddle signature header');
requireText(paddle,'hmac.New(sha256.New','Paddle HMAC verifier');
requireText(paddle,'mac.Write(raw)','raw-body signature binding');
requireText(paddle,'hmac.Equal(expected, decoded)','constant-time signature comparison');
requireText(paddle,'envelope.EventType != "transaction.completed"','completed transaction authority boundary');
requireText(paddle,'transaction_price_plan_mismatch','configured price to plan binding');
requireText(paddle,'transaction_customer_binding_mismatch','account/payment binding');
requireText(paddle,'ON CONFLICT (notification_id) DO NOTHING','webhook idempotency');
requireText(paddle,'activatePackageEntitlementDetailedTx','entitlement activation');
requireText(paddlePublic,'cfg.AutomationReady','browser config requires webhook-ready automation');
requireText(paddlePublic,'cfg.AllPlansReady','browser config requires complete plan catalog');
requireText(paddlePublic,'cfg.ClientToken','browser-safe Paddle client token');
forbid(paddlePublic,/cfg\.(?:APIKey|WebhookSecret)\b/,'server Paddle secrets in browser config');

requireText(migration,'CREATE TABLE IF NOT EXISTS paddle_billing_events','Paddle event ledger');
requireText(migration,'raw_sha256 text NOT NULL','raw payload digest');
forbid(migration,/raw_(?:body|payload)\s+(?:text|json|jsonb|bytea)/i,'raw webhook payload persistence');
requireText(migration,"payment_provider = 'paddle'",'Paddle-scoped payment id uniqueness');

requireText(pricing,'FREE CORE · NORMAL SAAS BILLING','normal SaaS pricing surface');
for(const p of ['Starter','Professional','Enterprise'])requireText(pricing,`<h2>${p}</h2>`,`${p} pricing card`);
requireText(pricing,'data-koschei-checkout="starter"','Starter checkout');
requireText(pricing,'data-koschei-checkout="professional"','Professional checkout');
requireText(pricing,'data-koschei-checkout="enterprise"','Enterprise checkout');
requireText(pricing,'$299 / month','Starter price');
requireText(pricing,'$999 / month','Professional price');
requireText(pricing,'$4,999 / month','Enterprise price');
forbid(pricing,/Price to finalize/i,'unfinalized price placeholder');
forbid(pricing,/Official KOSCH mint|KOSCH Holder Access|\b(?:25K|250K|2M)\s+KOSCH/i,'token-backed pricing');

requireText(account,'Account & SaaS Access','SaaS account surface');
requireText(account,'KOSCH balances and holder tiers do not unlock routes','account token separation');
forbid(account,/TOKEN ACCESS EVIDENCE|Official mint snapshot|LIVE TOKEN POLICY/i,'token authority account sections');
requireText(reports,'STARTER+ SAAS · DURABLE CANONICAL JOB HISTORY','SaaS investigation history copy');
requireText(reports,'KOSCH holdings do not authorize this surface.','history token separation');
forbid(reports,/BASIC\+ KOSCH|Basic KOSCH tier/i,'holder-gated investigation history copy');
requireText(token2022,'Starter SaaS plan or higher','Token-2022 Starter SaaS boundary');
requireText(token2022,'KOSCH holdings and legacy holder tiers do not authorize or upgrade this surface.','Token-2022 token separation');
forbid(token2022,/Basic-tier|Basic tier|Verify KOSCH Access|premium Basic-tier gate|customer-session \+ KOSCH/i,'Token-2022 token-backed commercial copy');
requireText(checkout,"fetch('/api/paddle/checkout'",'browser Paddle checkout');
requireText(checkout,"parsed.protocol !== 'https:'",'secure checkout redirect');
forbid(checkout,/kosch_token|\/kosch-access/,'legacy token checkout');

requireText(hostedCheckout,'https://cdn.paddle.com/paddle/v2/paddle.js','Paddle.js on default payment link');
requireText(hostedCheckout,'/js/paddle-hosted-checkout.js?v=1','hosted checkout initializer');
requireText(hostedCheckout,'/terms.html','checkout Terms link');
requireText(hostedCheckout,'/privacy.html','checkout Privacy link');
requireText(hostedCheckout,'/refund-policy.html','checkout Refund link');
forbid(hostedCheckout,/<script(?![^>]*\bsrc=)[^>]*>/i,'inline checkout script');
forbid(hostedCheckout,/\son[a-z]+\s*=|\sstyle\s*=/i,'inline checkout event/style attributes');
requireText(hostedCheckoutJS,"fetch('/paddle/public-config'",'hosted checkout browser config');
requireText(hostedCheckoutJS,'window.Paddle.Initialize','Paddle.js initialization');
requireText(hostedCheckoutJS,"params.get('_ptxn')",'Paddle default payment transaction binding');
requireText(hostedCheckoutJS,'transactionId:transactionID','transaction fallback opening');
forbid(hostedCheckoutJS,/PADDLE_API_KEY|pdl_live_apikey|PADDLE_WEBHOOK_SECRET/i,'server secret in hosted checkout JavaScript');
requireText(staticAliases,'"/paddle-checkout"','canonical Paddle checkout route');
requireText(staticAliases,'paddle-checkout.html','Paddle checkout static target');
requireText(securityHeaders,'paddleCheckoutCSP','checkout-specific CSP');
requireText(securityHeaders,'https://cdn.paddle.com','Paddle CDN CSP source');
requireText(securityHeaders,'https://*.paddle.com','Paddle API/frame CSP source');

forbid(workspace,/token_tier|token_amount|KOSCH holder access/i,'workspace token authorization state');
forbid(customerAccess,/\/api\/auth\/token-access|token_tier|token_amount|mint_address/i,'account token authorization source');

requireText(routeInventory,'public_free_core_plus_saas_entitlements','route-map access model');
requireText(routeInventory,'KOSCH holdings, wallet balances and legacy holder tiers do not authorize','route-map token separation');
requireText(routeInventory,'POST /api/paddle/checkout','billing route inventory');
requireText(routeInventory,'api_key_plus_enterprise_entitlement','developer SaaS inventory');
forbid(routeInventory,/customer_session_plus_kosch|api_key_plus_live_kosch_holder/,'legacy KOSCH route authorization labels');

console.log('SaaS billing / KOSCH decoupling v1 contract: ok');
