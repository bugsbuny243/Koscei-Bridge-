'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','pricing.html'),'utf8');
const checkout=fs.readFileSync(path.join(root,'public','js','paddle-checkout.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','pricing-policy-v2.css'),'utf8');
const planAccess=fs.readFileSync(path.join(root,'internal','handlers','plan_access.go'),'utf8');
const premiumAccess=fs.readFileSync(path.join(root,'internal','handlers','premium_access_status.go'),'utf8');

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
requireText(html,'Paid access follows an active subscription','subscription/access separation');
requireText(html,'ARVIS EARLY ACCESS','ARVIS readiness disclosure');
requireText(html,'Unfinished radar modules are not represented as production features','no unfinished feature overclaim');
requireText(html,'Checking Paddle catalog readiness','checkout readiness placeholder');
requireText(html,'/js/koschei-auth.js?v=33','existing frozen auth client');
requireText(html,'/js/paddle-checkout.js?v=3','Paddle checkout client');
requireText(html,'$299 / month','Starter commercial price');
requireText(html,'$999 / month','Professional commercial price');
requireText(html,'$4,999 / month','Enterprise commercial price');
forbid(html,/Price to finalize/i,'unfinalized commercial pricing');
forbid(html,/\bKOSCH\b/i,'retired token reference on pricing page');
forbid(html,/token holdings?/i,'token-holdings reference on pricing page');
forbid(html,/Current (?:Basic|Pro|Enterprise) policy/i,'holder-tier pricing');
forbid(html,/premium holder access/i,'holder access marketing');
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

requireText(checkout,"fetch('/paddle/public-config'",'Paddle public readiness API');
requireText(checkout,"paddle[plan + '_ready'] === true",'per-plan catalog readiness gate');
requireText(checkout,"fetch('/api/paddle/checkout'",'Paddle checkout API');
requireText(checkout,"provider: 'paddle'",'Paddle provider identity');
requireText(checkout,"parsed.protocol !== 'https:'",'HTTPS checkout redirect gate');
requireText(checkout,"Paddle catalog is not active yet",'zero-plan catalog block');
forbid(checkout,/\/kosch-access|provider:\s*'kosch_token'|\/api\/auth\/token-access/i,'retired asset-based checkout/access');
forbid(checkout,/\blocalStorage\b|\bsessionStorage\b/,'checkout persistence');

requireText(css,'.pricing-plans','pricing tier layout');
requireText(css,'.pricing-policy-grid','pricing contract layout');
requireText(css,'@media(max-width:620px)','mobile pricing layout');
console.log('pricing SaaS entitlement contract: ok');
