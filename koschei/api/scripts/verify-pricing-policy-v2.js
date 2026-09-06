'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','pricing.html'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','pricing-policy-v2.css'),'utf8');
const universe=fs.readFileSync(path.join(root,'public','css','koschei-universe-v1.css'),'utf8');
const planAccess=fs.readFileSync(path.join(root,'internal','handlers','plan_access.go'),'utf8');
const premiumAccess=fs.readFileSync(path.join(root,'internal','handlers','premium_access_status.go'),'utf8');
const checkoutGate=fs.readFileSync(path.join(root,'internal','handlers','polar_checkout_gate.go'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden pattern ${pattern}`);}

requireText(html,'<html lang="en">','pricing language');
requireText(html,'ONE ACCESS CONTRACT · PROFESSIONAL','single-plan disclosure');
requireText(html,'Enter the ARVIS universe.','universe headline');
requireText(html,'One plan. The real system.','single-plan headline');
requireText(html,'data-polar-plan="professional"','Professional Polar checkout action');
requireText(html,'/js/polar-checkout-v1.js?v=1','secure checkout client');
requireText(html,'Professional is the only paid customer plan.','single paid plan copy');
requireText(html,'There is no free investigation tier, no Starter package and no Enterprise package.','removed package disclosure');
requireText(html,'The server decides access. The browser never invents it.','server-side entitlement authority');
requireText(html,'PROFESSIONAL</strong>','Professional policy card');
requireText(html,'SERVER-SIDE','server authority card');
requireText(html,'FAIL-CLOSED','evidence boundary card');
requireText(html,'/css/koschei-universe-v1.css?v=1','universe stylesheet');

forbid(html,/<h2>Free Core<\/h2>/i,'free investigation tier');
forbid(html,/Request early access/i,'retired early access form');
forbid(html,/COMMERCIAL CHECKOUT PAUSED/i,'retired paused-checkout marketing');
forbid(html,/STARTER\+|ENTERPRISE\+/i,'retired paid tier badges');
forbid(html,/\$299\s*\/\s*month|\$999\s*\/\s*month|\$4,999\s*\/\s*month/i,'invented or retired hard-coded pricing');
forbid(html,/paddle/i,'retired Paddle billing surface');
forbid(html,/data-koschei-checkout/i,'retired browser checkout action');
forbid(html,/<script(?![^>]*\bsrc=)[^>]*>/i,'inline runtime script');
forbid(html,/\son[a-z]+\s*=/i,'inline event handler');

requireText(checkoutGate,'KOSCHEI_COMMERCIAL_CHECKOUT_ENABLED','server readiness flag');
requireText(checkoutGate,'h.PolarCheckout(w, r)','Polar checkout delegation');
requireText(planAccess,'func canonicalSaaSPlan(plan string) string','canonical SaaS plan mapping');
requireText(planAccess,'func (h *Handler) RequirePlanTier','customer entitlement authorization');
requireText(planAccess,'FROM entitlements','entitlement source');
requireText(planAccess,"status='active'",'active entitlement requirement');
requireText(planAccess,'EnforcePlanOutput','entitlement output metering');
requireText(premiumAccess,'Source:           "entitlement"','premium access entitlement source');
requireText(premiumAccess,'OutputsRemaining: evaluation.OutputsRemaining','remaining capacity response');
forbid(premiumAccess,/token_(?:tier|amount)/i,'asset-backed premium access fields');

requireText(css,'.pricing-plans','pricing layout');
requireText(css,'.pricing-policy-grid','pricing contract layout');
requireText(css,'@media(max-width:620px)','mobile pricing layout');
requireText(universe,'body.koschei-universe','universe body contract');
requireText(universe,'.universe-entry','universe entry contract');
console.log('pricing Professional-only universe contract: ok');
