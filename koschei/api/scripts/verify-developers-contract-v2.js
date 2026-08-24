'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','developers.html'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','developers-contract-v2.css'),'utf8');
const inventory=fs.readFileSync(path.join(root,'internal','http','route_inventory.go'),'utf8');
const apiRef=fs.readFileSync(path.resolve(root,'..','..','docs','api-reference.md'),'utf8');
const b2b=fs.readFileSync(path.join(root,'internal','handlers','b2b_token_scan.go'),'utf8');
const apiKeys=fs.readFileSync(path.join(root,'internal','handlers','api_keys.go'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden pattern ${pattern}`);}

requireText(html,'<html lang="en">','developer portal language');
requireText(html,'REGISTERED ROUTES · SAAS AUTH · ARVIS EARLY ACCESS','developer contract heading');
requireText(html,'Customer session ≠ API key','auth separation');
requireText(html,'keep developer API keys server-side','server-side API key boundary');
requireText(html,'localStorage, or sessionStorage','explicit browser-storage warning');
requireText(html,'Route registration does not by itself mean','route/readiness boundary');
requireText(html,'KOSCH holdings do not authorize, upgrade, discount, or meter commercial access.','token separation');
requireText(html,'Enterprise entitlement + API key','Enterprise API boundary');
requireText(html,'/scan?mode=deep','canonical Deep Scan route');
requireText(html,'/docs/api','API docs route');
requireText(html,'/pilot','pilot route');
requireText(html,'/transaction-firewall','B2B guard route');
requireText(html,'/js/koschei-global-shell.js?v=4','global shell v4');
requireText(html,'/css/developers-contract-v2.css?v=1','developer styles');
if(html.includes('/security-radar'))throw new Error('developers must not advertise legacy security-radar');
forbid(html,/customer session \+ KOSCH|API key \+ live KOSCH|verified KOSCH holder|live KOSCH eligibility|KOSCH tier/i,'token-backed developer authorization copy');
forbid(html,/<script(?![^>]*\bsrc=)[^>]*>/i,'inline runtime script');
forbid(html,/\son[a-z]+\s*=/i,'inline event handler');
forbid(html,/"grade"\s*:\s*"A-F"/,'fabricated verdict JSON grade');
forbid(html,/"risk_index"\s*:\s*45/,'fabricated verdict JSON risk score');
forbid(html,/(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(/i,'browser API-key persistence code');
forbid(html,/(?:localStorage|sessionStorage)\s*\[[^\]]+\]\s*=/i,'browser API-key persistence assignment');

requireText(inventory,'Name: "public_and_system", Auth: "public_or_mixed"','public route group');
requireText(inventory,'"POST /api/arvis/preflight", "POST /api/token/scan"','public preflight/token routes');
requireText(inventory,'Name: "premium_radar_and_reports", Auth: "customer_session_plus_saas_entitlement"','customer premium SaaS group');
requireText(inventory,'"POST /api/v1/token/extensions", "POST /api/v1/address-poisoning/check"','Token-2022/customer protection routes');
requireText(inventory,'"POST /api/v1/radar/check", "POST /api/v1/radar/jobs"','customer radar routes');
requireText(inventory,'Name: "developer_api", Auth: "api_key_plus_enterprise_entitlement"','developer API Enterprise auth group');
requireText(inventory,'"POST /api/v1/scan/token", "GET /api/v1/usage", "POST /api/v1/shield/preflight"','developer API core routes');
requireText(inventory,'"POST /api/v1/shield/transaction", "POST /api/v1/shield/state-recheck", "POST /api/v1/shield/address-poisoning"','developer shield routes');
requireText(inventory,'Name: "watchlist_and_webhooks", Auth: "professional_or_enterprise_saas_entitlement"','watchlist/webhook SaaS auth group');
forbid(inventory,/customer_session_plus_kosch|api_key_plus_live_kosch_holder/,'legacy route inventory authorization labels');

for(const endpoint of ['/api/arvis/preflight','/api/token/scan','/api/v1/radar/check','/api/v1/radar/jobs','/api/v1/token/extensions','/api/watchlist','/api/webhooks','/api/v1/scan/token','/api/v1/shield/transaction','/api/v1/shield/preflight','/api/v1/shield/address-poisoning','/api/v1/usage']){
  requireText(html,endpoint,`developer page endpoint ${endpoint}`);
}
requireText(html,'POST /api/v1/token/extensions','dedicated Token-2022 route');
if(/Token-2022[^<]{0,200}POST \/api\/token\/scan/i.test(html.replace(/\s+/g,' ')))throw new Error('generic /api/token/scan must not be labeled as dedicated Token-2022 route');

requireText(apiRef,'Authentication: customer session + active Starter SaaS entitlement or higher.','customer API auth reference');
requireText(apiRef,'Authentication: developer API key + active Enterprise SaaS entitlement.','developer API auth reference');
requireText(apiRef,'KOSCH holdings, wallet balances, historical token tiers and `token_access_snapshots` do not grant, upgrade or discount commercial access.','API reference token separation');
requireText(apiRef,'A registered route is an integration contract, not by itself a claim','API reference readiness boundary');
requireText(apiRef,'When verified evidence is unavailable, ARVIS withholds the authoritative verdict instead of fabricating a grade.','signed verdict fail-closed rule');
requireText(apiRef,'Developer API keys are identity credentials. Registered developer routes require an active Enterprise SaaS entitlement','developer key identity boundary');
requireText(html,'No evidence, no claim','developer trust copy');
requireText(html,'No model authority:','model authority boundary');

requireText(b2b,'maxBatchTokenScans   = 20','batch max contract');
requireText(b2b,'cost := len(targets)','one reserved usage credit per normalized target');
requireText(b2b,'refund := reserved - charged','batch partial refund contract');
requireText(html,'up to 20 unique Solana token targets','batch limit copy');
requireText(html,'Failed batch items are refunded','batch refund copy');

requireText(apiKeys,'"credits_reserved": reserved','usage reserved field');
requireText(apiKeys,'"credits_charged":  charged','usage charged field');
requireText(apiKeys,'"result_url":       "/api/v1/usage?request_id=" + rid','usage result URL');
requireText(apiKeys,'"poll_after_ms"','async usage polling');
requireText(html,'API usage reservation/charge metadata','usage-credit interpretation boundary');

requireText(css,'.dev-auth.public','public auth styles');
requireText(css,'.dev-auth.session','customer session styles');
requireText(css,'.dev-auth.api','developer API styles');
requireText(css,'.dev-code','developer code block styles');
requireText(css,'@media(max-width:620px)','mobile developer layout');
console.log('developers contract v2 + SaaS/readiness boundary: ok');
