'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','pricing.html'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','pricing-policy-v2.css'),'utf8');
const earlyCss=fs.readFileSync(path.join(root,'public','css','early-access-v1.css'),'utf8');
const earlyJS=fs.readFileSync(path.join(root,'public','js','early-access-v1.js'),'utf8');
const planAccess=fs.readFileSync(path.join(root,'internal','handlers','plan_access.go'),'utf8');
const premiumAccess=fs.readFileSync(path.join(root,'internal','handlers','premium_access_status.go'),'utf8');
const checkoutGate=fs.readFileSync(path.join(root,'internal','handlers','polar_checkout_gate.go'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden pattern ${pattern}`);}

requireText(html,'<html lang="en">','pricing language');
requireText(html,'COMMERCIAL CHECKOUT PAUSED','commercial readiness disclosure');
requireText(html,'Evidence first. Paid checkout later.','commercial readiness headline');
requireText(html,'New checkout is fail-closed','fail-closed customer disclosure');
requireText(html,'<h2>Free Core</h2>','free core');
requireText(html,'<h2>Request access</h2>','single early access surface');
requireText(html,'id="earlyAccessForm"','early access form');
requireText(html,'id="earlyAccessEmail"','early access email');
requireText(html,'id="earlyAccessUseCase"','early access use case');
requireText(html,'/js/early-access-v1.js?v=1','early access client');
requireText(html,'Existing access still follows the server-side entitlement.','server-side entitlement authority');
requireText(html,'Existing entitlements remain valid','existing entitlement preservation');
requireText(html,'WEBHOOK LIFECYCLE','provider lifecycle preservation');
requireText(html,'No payment is collected by the early access form.','no-charge early access disclosure');

forbid(html,/data-polar-plan=/i,'active Polar checkout button');
forbid(html,/Subscribe with Polar/i,'active paid checkout copy');
forbid(html,/polar-checkout-v1\.js/i,'paid checkout browser client');
forbid(html,/\$299\s*\/\s*month/i,'Starter price while checkout paused');
forbid(html,/\$999\s*\/\s*month/i,'Professional price while checkout paused');
forbid(html,/\$4,999\s*\/\s*month/i,'Enterprise price while checkout paused');
forbid(html,/paddle/i,'retired Paddle billing surface');
forbid(html,/data-koschei-checkout/i,'retired browser checkout action');
forbid(html,/<script(?![^>]*\bsrc=)[^>]*>/i,'inline runtime script');
forbid(html,/\son[a-z]+\s*=/i,'inline event handler');

requireText(earlyJS,"event_name:'customer_feedback'",'existing feedback persistence');
requireText(earlyJS,"subject:'Koschei Web3 early access request'",'early access classification');
requireText(earlyJS,'No payment was taken.','no-charge confirmation');
requireText(earlyCss,'.early-access-form','early access layout');

requireText(checkoutGate,'KOSCHEI_COMMERCIAL_CHECKOUT_ENABLED','server readiness flag');
requireText(checkoutGate,'commercial_checkout_paused','stable paused checkout response');
requireText(checkoutGate,'h.PolarCheckout(w, r)','existing Polar checkout preservation');

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
console.log('pricing commercial-readiness contract: ok');
