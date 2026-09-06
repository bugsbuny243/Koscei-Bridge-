'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','arvis-chat.html'),'utf8');
const js=fs.readFileSync(path.join(root,'public','js','customer-arvis-chat-v1.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','customer-arvis-chat-v1.css'),'utf8');
const server=fs.readFileSync(path.join(root,'internal','http','server.go'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden ${pattern}`);}

requireText(html,'ARVIS Investigation Chat','customer chat title');
requireText(html,'Follow-up questions are answered only from the returned investigation evidence','evidence-grounded copy');
requireText(html,'id="arvisChatScanForm"','scan form');
requireText(html,'id="arvisChatQuestionForm"','question form');
requireText(html,'/js/customer-arvis-chat-v1.js?v=1','chat controller');
forbid(html,/<script(?![^>]*\bsrc=)[^>]*>/i,'inline runtime script');
forbid(html,/\son[a-z]+\s*=/i,'inline event handler');

requireText(server,'/api/v1/radar/check','canonical customer investigation route exists');
requireText(js,"api('/api/v1/radar/check'",'chat reuses canonical ARVIS investigation');
requireText(js,"mode:'customer_arvis_chat'",'chat investigation mode');
requireText(js,"KoscheiAuth.apiCall(path",'shared authenticated API client');
requireText(js,"KoscheiAuth.requireAuth('/login.html')",'verified customer session');
requireText(js,'Chat does not create a second verdict.','deterministic verdict boundary');
requireText(js,'I still do not infer safety from missing evidence.','missing evidence boundary');
requireText(js,'No evidence-backed attack-path projection was returned','no invented attack path');
requireText(js,'Follow-up questions use this returned evidence only.','follow-up evidence boundary');
forbid(js,/\bfetch\s*\(/,'raw fetch bypass');
forbid(js,/\blocalStorage\b|\bsessionStorage\b/,'browser persistence');
forbid(js,/\.innerHTML\s*=/,'API-derived innerHTML');
forbid(js,/Math\.random\s*\(/,'synthetic evidence');
forbid(js,/openai|anthropic|together|gemini|claude/i,'parallel LLM scanner');
forbid(js,/signMessage|signTransaction|signAllTransactions|signAndSendTransaction|sendTransaction/,'wallet authority');

requireText(css,'.arvis-chat-shell','chat layout');
requireText(css,'@media(max-width:800px)','mobile layout');
console.log('ARVIS customer chat v1 acceptance: ok');
