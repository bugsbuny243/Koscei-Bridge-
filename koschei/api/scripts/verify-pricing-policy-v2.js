'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','pricing.html'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','pricing-policy-v2.css'),'utf8');
const planAccess=fs.readFileSync(path.join(root,'internal','handlers','plan_access.go'),'utf8');
const premiumAccess=fs.readFileSync(path.join(root,'internal','handlers','premium_access_status.go'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden pattern ${pattern}`);}

requireText(html,'<html lang="en">','pricing language');
requireText(html,'<h2>Starter</h2>','Starter SaaS plan');
requireText(html,'<h2>Professional</h2>','Professional SaaS plan');
requireText(html,'<h2>Enterprise</h2>','Enterprise SaaS plan');
requireText(html,'data-polar-plan="starter">Subscribe with Polar</button>','Starter Polar checkout');
requireText(html,'data-polar-plan="professional">Subscribe with Polar</button>','Professional Polar checkout');
requireText(html,'data-polar-plan="enterprise">Subscribe with Polar</button>','Enterprise Polar checkout');
requireText(html,'id="polarBillingMessage"','billing feedback surface');
requireText(html,'Product access follows the server-side entitlement.','server-side entitlement authority');
requireText(html,'Paid access requires an active entitlement','subscription/access separation');
requireText(html,'ARVIS EARLY ACCESS','ARVIS readiness disclosure');
requireText(html,'Unfinished modules are not represented as production features','no unfinished feature overclaim');
requireText(html,'If the required evidence or entitlement state is unavailable, paid access remains unavailable.','fail-closed entitlement language');
requireText(html,'/js/koschei-auth.js?v=33','existing frozen auth client');
requireText(html,'/js/polar-checkout-v1.js?v=1','Polar checkout client');
requireText(html,'$299 / month','Starter commercial price');
requireText(html,'$999 / month','Professional commercial price');
requireText(html,'$4,999 / month','Enterprise commercial price');
forbid(html,/Price to finalize/i,'unfinalized commercial pricing');
forbid(html,/token holdings?/i,'asset-holdings reference on pricing page');
forbid(html,/Current (?:Basic|Pro|Enterprise) policy/i,'holder-tier pricing');
forbid(html,/premium holder access/i,'holder access marketing');
forbid(html,/paddle/i,'retired Paddle billing surface');
forbid(html,/data-koschei-checkout/i,'retired browser checkout action');
forbid(html,/<script(?![^>]*\bsrc=)[^>]*>/i,'inline runtime script');
forbid(html,/\son[a-z]+\s*=/i,'inline event handler');

requireText(planAccess,'func canonicalSaaSPlan(plan string) string','canonical SaaS plan mapping');
requireText(planAccess,'func (h *Handler) RequirePlanTier','customer entitlement authorization');
requireText(planAccess,'FROM entitlements','entitlement source');
requireText(planAccess,"status='active'",'active entitlement requirement');
requireText(planAccess,'EnforcePlanOutput','entitlement output metering');
requireText(premiumAccess,'Source:           "entitlement"','premium access entitlement source');
requireText(premiumAccess,'OutputsRemaining: evaluation.OutputsRemaining','remaining capacity response');
forbid(premiumAccess,/token_(?:tier|amount)/i,'asset-backed premium access fields');

requireText(css,'.pricing-plans','pricing tier layout');
requireText(css,'.pricing-policy-grid','pricing contract layout');
requireText(css,'@media(max-width:620px)','mobile pricing layout');
console.log('pricing SaaS entitlement contract: ok');
