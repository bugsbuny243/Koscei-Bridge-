'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','pricing.html'),'utf8');
const checkout=fs.readFileSync(path.join(root,'public','js','paddle-checkout.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','pricing-policy-v2.css'),'utf8');
const planAccess=fs.readFileSync(path.join(root,'internal','handlers','plan_access.go'),'utf8');
const premiumAccess=fs.readFileSync(path.join(root,'internal','handlers','premium_access_status.go'),'utf8');
const retired=fs.readFileSync(path.join(root,'internal','handlers','kosch_retirement.go'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden pattern ${pattern}`);}

requireText(html,'<html lang="en">','pricing language');
requireText(html,'<h2>Starter</h2>','Starter SaaS plan');
requireText(html,'<h2>Professional</h2>','Professional SaaS plan');
requireText(html,'<h2>Enterprise</h2>','Enterprise SaaS plan');
requireText(html,'data-koschei-checkout="starter"','Starter checkout action');
requireText(html,'data-koschei-checkout="professional"','Professional checkout action');
requireText(html,'data-koschei-checkout="enterprise"','Enterprise checkout action');
requireText(html,'Paddle checkout for paid plans','normal paid checkout');
requireText(html,'Token holdings grant no product authority','token/access separation');
requireText(html,'/js/koschei-auth.js?v=33','existing frozen auth client');
requireText(html,'/js/paddle-checkout.js?v=2','Paddle checkout client');
requireText(html,'Price to finalize','commercial prices intentionally undecided');
forbid(html,/Official KOSCH mint/i,'KOSCH mint on pricing page');
forbid(html,/Current (?:Basic|Pro|Enterprise) policy/i,'holder-tier pricing');
forbid(html,/premium holder access/i,'holder access marketing');
forbid(html,/\b(?:25K|25,000|250K|250,000|2M|2,000,000)\s+KOSCH\b/i,'hardcoded holder threshold');
forbid(html,/<script(?![^>]*\bsrc=)[^>]*>/i,'inline runtime script');
forbid(html,/\son[a-z]+\s*=/i,'inline event handler');

requireText(planAccess,'func canonicalSaaSPlan(plan string) string','canonical SaaS plan mapping');
requireText(planAccess,'func (h *Handler) RequirePlanTier','customer entitlement authorization');
requireText(planAccess,'FROM entitlements','entitlement source');
requireText(planAccess,"status='active'",'active entitlement requirement');
requireText(planAccess,'EnforcePlanOutput','entitlement output metering');
requireText(premiumAccess,'Source:           "entitlement"','premium access entitlement source');
requireText(premiumAccess,'OutputsRemaining: evaluation.OutputsRemaining','remaining capacity response');
forbid(premiumAccess,/token_(?:tier|amount)|KOSCH/i,'token-backed premium access fields');

requireText(retired,'http.StatusGone','legacy token-access tombstone');
requireText(retired,'KOSCH holdings no longer grant product access','explicit retirement message');

requireText(checkout,"fetch('/api/paddle/checkout'",'Paddle checkout API');
requireText(checkout,"provider: 'paddle'",'Paddle provider identity');
requireText(checkout,"parsed.protocol !== 'https:'",'HTTPS checkout redirect gate');
forbid(checkout,/\/kosch-access|provider:\s*'kosch_token'/,'legacy KOSCH checkout');
forbid(checkout,/\blocalStorage\b|\bsessionStorage\b/,'checkout persistence');

requireText(css,'.pricing-plans','pricing tier layout');
requireText(css,'.pricing-policy-grid','pricing contract layout');
requireText(css,'@media(max-width:620px)','mobile pricing layout');
console.log('pricing SaaS entitlement contract: ok');
