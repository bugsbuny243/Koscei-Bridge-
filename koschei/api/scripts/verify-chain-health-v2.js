'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','chain-health.html'),'utf8');
const js=fs.readFileSync(path.join(root,'public','js','chain-health-v2.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','chain-health-v2.css'),'utf8');
const handler=fs.readFileSync(path.join(root,'internal','handlers','platform.go'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden pattern ${pattern}`);}

requireText(html,'<html lang="en">','chain page language');
requireText(html,'Provider comes from API evidence','provider evidence boundary');
requireText(html,'Unavailable ≠ online','unavailable health boundary');
requireText(html,'UI refresh time, not a provider-signed observation timestamp','browser-time boundary');
requireText(html,'/scan?mode=deep','canonical Deep Scan route');
requireText(html,'/kosch','canonical KOSCH route');
requireText(html,'/js/chain-health-v2.js?v=1','external health controller');
if(html.includes('/security-radar'))throw new Error('chain health must not advertise legacy security-radar');
if(html.includes('/kosch-access'))throw new Error('chain health must not advertise legacy kosch-access');
forbid(html,/<script(?![^>]*\bsrc=)[^>]*>/i,'inline runtime script');
forbid(html,/\son[a-z]+\s*=/i,'inline event handler');

requireText(handler,'type chainHealthResponse struct','chain health response contract');
requireText(handler,'Provider string `json:"provider"`','provider response field');
requireText(handler,'Network  string `json:"network"`','network response field');
requireText(handler,'Status   string `json:"status"`','status response field');
requireText(handler,'OK       bool   `json:"ok"`','explicit health boolean');

requireText(js,"fetch(`/api/web3/health?chain=${encodeURIComponent(chain)}`",'health endpoint');
requireText(js,"data?.ok===true?'online'",'strict online state');
requireText(js,"data?.ok===true?'ONLINE'",'strict online label');
requireText(js,"safeValue(data?.provider)",'provider from response only');
requireText(js,"safeValue(data?.network)",'network from response only');
requireText(js,"return{ok:false,status:'unavailable'",'request failure unavailable state');
requireText(js,'Promise.all(CHAINS.map','parallel health collection');
requireText(js,'timer=setTimeout(load,REFRESH_MS)','non-overlapping scheduled refresh');
requireText(js,"if(!response.ok||!data||typeof data!=='object')",'HTTP/JSON validity gate');
requireText(js,'UI refreshed','explicit browser refresh label');

forbid(js,/\bAlchemy\b/,'fabricated provider fallback');
forbid(js,/\.innerHTML\s*=/,'API-derived innerHTML');
forbid(js,/setInterval\s*\(/,'overlapping interval refresh');
forbid(js,/\b(?:localStorage|sessionStorage)\b/,'browser health-state persistence');
forbid(js,/Math\.random\s*\(/,'synthetic health evidence');
forbid(js,/\bd&&d\.ok\b|\bdata&&data\.ok\b/,'truthy health coercion');

requireText(css,'.chain-card.good','healthy state styles');
requireText(css,'.chain-card.bad','unhealthy state styles');
requireText(css,'.chain-summary.bad','degraded summary styles');
requireText(css,'@media(max-width:620px)','mobile chain health layout');
console.log('chain health v2 contract: ok');
