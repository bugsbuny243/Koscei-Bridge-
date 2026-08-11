'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','index.html'),'utf8');
const js=fs.readFileSync(path.join(root,'public','js','homepage-preflight-v2.js'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden pattern ${pattern}`);}

requireText(html,'<html lang="en">','homepage language');
requireText(html,'id="instant-check"','homepage preflight surface');
requireText(html,'id="result" aria-live="polite"','accessible preflight result');
requireText(html,'/js/homepage-preflight-v2.js?v=1','external homepage controller');
requireText(html,'href="/scan?mode=deep"','canonical deep scan navigation');
if(html.includes('/security-radar'))throw new Error('homepage must not revive duplicate security-radar navigation');
forbid(html,/<script(?![^>]*\bsrc=)[^>]*>/i,'inline runtime script');
forbid(html,/\son[a-z]+\s*=/i,'inline event handler');

requireText(js,"fetchJSON('/api/arvis/preflight'",'canonical preflight endpoint');
requireText(js,"fetch('/health'",'health endpoint');
requireText(js,"return raw==='allow'&&(score===null||level!=='low'||limited)?'withhold':raw",'incomplete allow downgrade');
requireText(js,"score===null?'—':score",'missing preflight risk display');
requireText(js,"parsed===null?'—':parsed.toLocaleString('en-US')",'missing health metric display');
requireText(js,"metric('verdicts',arvis?.signed_verdicts_total??arvis?.visible_verdicts)",'signed verdict fallback without zero invention');
requireText(js,'Do not interpret this failure as zero risk or permission to proceed.','degraded preflight boundary');
requireText(js,"deep.href=deepScanURL(target?.value)",'result deep scan route');
requireText(js,"value===null||value===undefined||String(value).trim()===''",'null numeric guard');

forbid(js,/\.innerHTML\s*=/,'API-derived innerHTML');
forbid(js,/Math\.random\s*\(/,'synthetic homepage evidence');
forbid(js,/\b(?:signTransaction|signAllTransactions|signAndSendTransaction|sendTransaction)\b/,'transaction authority');
forbid(js,/(?:risk_index|score)\s*\|\|\s*0/,'missing-risk zero fallback');
forbid(js,/(?:risk_index|score)\s*\?\?\s*0/,'missing-risk zero fallback');
forbid(js,/Number\([^)]*\|\|\s*0\)/,'health zero invention');
console.log('homepage preflight v2 contract: ok');
