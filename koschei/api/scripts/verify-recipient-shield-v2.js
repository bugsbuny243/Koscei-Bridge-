'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','address-poisoning-shield.html'),'utf8');
const js=fs.readFileSync(path.join(root,'public','js','address-poisoning-shield-v2.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','koschei.css'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function requireOrder(source,first,second,label){const a=source.indexOf(first),b=source.indexOf(second);if(a<0||b<0||a>=b)throw new Error(`${label}: expected ${first} before ${second}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden pattern ${pattern}`);}

requireText(html,'<html lang="en">','recipient html language');
requireText(html,'/css/koschei.css?v=1','global shell');
requireText(html,'/css/koschei.css?v=1','shared safety styles');
requireText(html,'id="recipientForm"','recipient form');
requireText(html,'id="wallet"','wallet input');
requireText(html,'id="candidate"','candidate input');
requireText(html,'id="contacts"','trusted contacts input');
requireText(html,'id="recipientRun"','recipient submit');
requireText(html,'id="recipientNotice"','recipient notice');
requireText(html,'id="recipientResult" aria-live="polite"','accessible result surface');
requireText(html,'Missing contact evidence ≠ safe','missing-evidence boundary');
requireText(html,'PREFLIGHT CLEAR','strict clear-state explanation');
requireText(html,'/js/koschei-auth.js?v=33','existing frozen auth client');
requireText(html,'/js/address-poisoning-shield-v2.js?v=1','recipient controller');
requireOrder(html,'/js/koschei-auth.js?v=33','/js/address-poisoning-shield-v2.js?v=1','auth client before page controller');
if(html.includes('/security-radar'))throw new Error('recipient shield must not revive duplicate security-radar route');
forbid(html,/\son[a-z]+\s*=/i,'inline event handler');
forbid(html,/<script(?![^>]*\bsrc=)[^>]*>/i,'inline script');

requireText(js,"KoscheiAuth.apiCall('/api/v1/address-poisoning/check'",'existing authenticated API contract');
requireText(js,"KoscheiAuth.requireAuth('/login.html')",'existing auth requirement');
requireText(js,"KoscheiAuth.loginURL('/login.html')",'existing reauthentication continuation');
requireText(js,"if(rawPolicy==='allow'&&risk!==null&&level==='low'&&rpc==='collected')",'strict allow display gate');
requireText(js,"risk===null?'—':risk",'missing risk display');
requireText(js,"observed===null?'UNAVAILABLE'",'missing contact count display');
requireText(js,"rpc==='collected'?'No lookalike match was returned in the evaluated contact scope.'",'empty match scoped wording');
requireText(js,"policy.no_evidence_no_claim===true?'ENFORCED':'UNAVAILABLE'",'evidence policy enforcement display');
requireText(js,'Do not interpret an unavailable check as permission to send.','degraded fail-closed guidance');
requireText(js,'Engine policy was ALLOW, but the UI did not display a clear-send state','raw policy versus signing guidance boundary');
requireText(js,"value===null||value===undefined||String(value).trim()===''",'null numeric guard');

forbid(js,/\bfetch\s*\(/,'raw fetch bypassing KoscheiAuth');
forbid(js,/\blocalStorage\b|\bsessionStorage\b/,'manual browser token storage');
forbid(js,/Authorization/i,'manual authorization header');
forbid(js,/\.innerHTML\s*=/,'API-derived innerHTML');
forbid(js,/Math\.random\s*\(/,'synthetic recipient evidence');
forbid(js,/\b(?:signTransaction|signAllTransactions|signAndSendTransaction|sendTransaction)\b/,'transaction authority');
forbid(js,/(?:risk_index|risk)\s*\|\|\s*0/,'missing-risk zero fallback');
forbid(js,/(?:risk_index|risk)\s*\?\?\s*0/,'missing-risk zero fallback');

requireText(css,'.safety-score.good','clear state styling');
requireText(css,'.safety-score.warn','warning state styling');
requireText(css,'.safety-score.bad','blocking state styling');
requireText(css,'.safety-error','degraded state styling');
requireText(css,'@media(max-width:620px)','mobile safety layout');
console.log('recipient shield v2 contract: ok');
