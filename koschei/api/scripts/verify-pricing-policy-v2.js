'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','pricing.html'),'utf8');
const js=fs.readFileSync(path.join(root,'public','js','pricing-policy-v2.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','pricing-policy-v2.css'),'utf8');
const tokenAccess=fs.readFileSync(path.join(root,'internal','handlers','token_access.go'),'utf8');
const premiumAccess=fs.readFileSync(path.join(root,'internal','handlers','premium_access_status.go'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden pattern ${pattern}`);}

requireText(html,'<html lang="en">','pricing language');
requireText(html,'Current Basic policy','Basic policy-owned tier');
requireText(html,'Current Pro policy','Pro policy-owned tier');
requireText(html,'Current Enterprise policy','Enterprise policy-owned tier');
requireText(html,'Basic is the minimum token tier that can activate premium holder access','premium minimum explanation');
requireText(html,'/scan?mode=deep','canonical Deep Scan route');
requireText(html,'/kosch','canonical KOSCH route');
requireText(html,'/js/koschei-auth.js?v=33','existing frozen auth client');
requireText(html,'/js/pricing-policy-v2.js?v=1','pricing policy controller');
requireText(html,'Official KOSCH mint','official mint identity');
if(html.includes('/security-radar'))throw new Error('pricing must not advertise legacy security-radar');
if(html.includes('/kosch-access'))throw new Error('pricing must not advertise legacy kosch-access');
forbid(html,/\bAny\s+KOSCH\b/i,'Any-KOSCH premium claim');
forbid(html,/\b(?:25K|25,000|250K|250,000|2M|2,000,000)\s+KOSCH\b/i,'hardcoded holder threshold');
forbid(html,/<script(?![^>]*\bsrc=)[^>]*>/i,'inline runtime script');
forbid(html,/\son[a-z]+\s*=/i,'inline event handler');

requireText(tokenAccess,'Thresholds      map[string]string `json:"thresholds,omitempty"`','token threshold response contract');
requireText(tokenAccess,'configuredTokenThresholds(evaluation.Decimals)','runtime threshold configuration');
requireText(tokenAccess,'tokenTierThresholdEnv("KOSCHEI_TOKEN_TIER_BASIC"','Basic configurable threshold');
requireText(tokenAccess,'tokenTierThresholdEnv("KOSCHEI_TOKEN_TIER_PRO"','Pro configurable threshold');
requireText(tokenAccess,'tokenTierThresholdEnv("KOSCHEI_TOKEN_TIER_ENTERPRISE"','Enterprise configurable threshold');
requireText(premiumAccess,'RequiredTokenTier: "basic"','premium minimum tier');
requireText(premiumAccess,'tokenTierRank(token.Tier) >= tokenTierRank("basic")','premium activation tier gate');

requireText(js,"KoscheiAuth.apiCall('/api/auth/token-access'",'live token policy source');
requireText(js,'KoscheiAuth.isLoggedIn?.()','signed-in policy read boundary');
requireText(js,"renderSignedOut();return;",'signed-out no-policy inference');
requireText(js,"'UNAVAILABLE'",'missing threshold state');
requireText(js,'The UI does not guess a legacy value.','no threshold guessing');
requireText(js,"configured&&gate?'Live token-access policy loaded.",'gate/config state rendering');
forbid(js,/\bfetch\s*\(/,'raw token-policy fetch');
forbid(js,/\blocalStorage\b|\bsessionStorage\b/,'browser token/access persistence');
forbid(js,/\.innerHTML\s*=/,'policy-derived innerHTML');
forbid(js,/\b(?:signMessage|signTransaction|signAllTransactions|signAndSendTransaction|sendTransaction)\b/,'wallet authority on public pricing');
forbid(js,/\b(?:25000|250000|2000000)\b/,'hardcoded token thresholds in pricing controller');

requireText(css,'.pricing-plans','pricing tier layout');
requireText(css,'.pricing-policy-grid','live policy layout');
requireText(css,'.pricing-policy-status.bad','unavailable policy styling');
requireText(css,'@media(max-width:620px)','mobile pricing layout');
console.log('pricing policy v2 contract: ok');
