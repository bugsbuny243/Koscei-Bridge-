'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','transaction-firewall.html'),'utf8');
const js=fs.readFileSync(path.join(root,'public','js','transaction-firewall-v2.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','transaction-firewall-v2.css'),'utf8');
const docs=fs.readFileSync(path.resolve(root,'..','..','docs','transaction-firewall.md'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden pattern ${pattern}`);}

requireText(html,'<html lang="en">','firewall language');
requireText(html,'id="firewallForm"','firewall form');
requireText(html,'id="apiKey"','api key input');
requireText(html,'id="transaction"','transaction input');
requireText(html,'id="firewallResult" aria-live="polite"','accessible evidence result');
requireText(html,'API key not persisted','non-persistence copy');
requireText(html,'/scan?mode=deep','canonical deep scan navigation');
requireText(html,'/js/transaction-firewall-v2.js?v=1','external firewall controller');
if(html.includes('/security-radar'))throw new Error('firewall must not generate legacy security-radar navigation');
forbid(html,/<script(?![^>]*\bsrc=)[^>]*>/i,'inline runtime script');
forbid(html,/\son[a-z]+\s*=/i,'inline event handler');

requireText(docs,'POST /api/v1/shield/transaction','documented guard endpoint');
requireText(docs,'A missing signal never means safe.','documented missing-signal contract');
requireText(docs,'it never stores the serialized transaction','documented no-storage boundary');
requireText(js,"fetch('/api/v1/shield/transaction'",'exact B2B guard endpoint');
requireText(js,"'X-API-Key':key",'API key header contract');
requireText(js,"return raw==='allow'&&(risk===null||level!=='low')?'withhold':raw",'incomplete allow downgrade');
requireText(js,"risk===null?'—':risk",'missing risk display');
requireText(js,"units===null?'UNAVAILABLE'",'missing compute display');
requireText(js,"programs===null?'UNAVAILABLE'",'missing program-count display');
requireText(js,"latency===null?'UNAVAILABLE'",'missing latency display');
requireText(js,'Do not interpret a failed request as zero risk or permission to sign.','degraded fail-closed boundary');
requireText(js,"value===null||value===undefined||String(value).trim()===''",'null numeric guard');

forbid(js,/\blocalStorage\b|\bsessionStorage\b/,'browser credential persistence');
forbid(js,/\.innerHTML\s*=/,'API-derived innerHTML');
forbid(js,/Math\.random\s*\(/,'synthetic transaction evidence');
forbid(js,/\b(?:signTransaction|signAllTransactions|signAndSendTransaction|sendTransaction)\b/,'transaction authority');
forbid(js,/(?:risk_index|risk)\s*\|\|\s*0/,'missing-risk zero fallback');
forbid(js,/(?:risk_index|risk)\s*\?\?\s*0/,'missing-risk zero fallback');
forbid(js,/(?:units_consumed|latency_ms)\s*\?\?\s*0/,'missing operational metric zero fallback');

requireText(css,'.firewall-shell','firewall layout');
requireText(css,'.firewall-item.bad','blocking evidence styles');
requireText(css,'.firewall-code','sanitized evidence log styles');
requireText(css,'@media(max-width:900px)','mobile firewall layout');
console.log('B2B transaction firewall v2 contract: ok');
