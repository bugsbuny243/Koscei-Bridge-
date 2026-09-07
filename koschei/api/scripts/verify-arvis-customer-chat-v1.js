'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','arvis-chat.html'),'utf8');
const js=fs.readFileSync(path.join(root,'public','js','customer-arvis-chat-v1.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','koschei.css'),'utf8');
const universe=fs.readFileSync(path.join(root,'public','css','koschei.css'),'utf8');
const metaverse=fs.readFileSync(path.join(root,'public','css','koschei.css'),'utf8');
const metaverseJS=fs.readFileSync(path.join(root,'public','js','customer-arvis-metaverse-v1.js'),'utf8');
const server=fs.readFileSync(path.join(root,'internal','http','server.go'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden ${pattern}`);}

requireText(html,'One target enters. The evidence universe opens.','customer universe chat headline');
requireText(html,'The visual map below lights up only from fields returned by that investigation; missing data stays missing.','evidence-grounded copy');
requireText(html,'PROFESSIONAL · CANONICAL INVESTIGATION','Professional chat boundary');
requireText(html,'Threat Hypothesis','threat hypothesis universe stage');
requireText(html,'Threat hypotheses describe evidence-backed technical possibilities, not intent or numeric probability.','hypothesis epistemic boundary');
requireText(html,'How ARVIS works','metaverse explanation');
requireText(html,'id="metaEvidence"','metaverse evidence node');
requireText(html,'id="arvisChatScanForm"','scan form');
requireText(html,'id="arvisChatQuestionForm"','question form');
requireText(html,'/js/customer-arvis-metaverse-v1.js?v=1','metaverse controller');
requireText(html,'/js/customer-arvis-chat-v1.js?v=3','chat controller');
requireText(html,'/css/koschei.css?v=1','metaverse stylesheet');
requireText(html,'/css/koschei.css?v=1','universe stylesheet');
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
requireText(js,'No evidence-backed threat hypothesis was returned','no invented hypothesis');
requireText(js,'capability/exposure hypothesis','capability-not-intent hypothesis copy');
requireText(js,'not intent or a numeric probability','no probability or intent claim');
requireText(js,'investigation_report?.intelligence_contract?.hypotheses','canonical hypothesis source');
requireText(js,'Evidence refs:','hypothesis evidence references');
requireText(js,'Still required:','hypothesis missing evidence projection');
requireText(js,'Follow-up questions use this returned evidence only.','follow-up evidence boundary');
requireText(js,"document.dispatchEvent(new CustomEvent('koschei:arvis-investigation-ready'",'canonical result is published to metaverse');
requireText(metaverseJS,"document.addEventListener('koschei:arvis-investigation-ready'",'metaverse consumes canonical result event');
requireText(metaverseJS,'NO SUPPORTED PATH','attack-path absence stays explicit');
requireText(metaverseJS,'NOT EXPLICITLY RETURNED','missing evidence stays explicit');
forbid(js,/\bfetch\s*\(/,'raw fetch bypass');
forbid(js,/\blocalStorage\b|\bsessionStorage\b/,'browser persistence');
forbid(js,/\.innerHTML\s*=/,'API-derived innerHTML');
forbid(js,/Math\.random\s*\(/,'synthetic evidence');
forbid(js,/openai|anthropic|together|gemini|claude/i,'parallel LLM scanner');
forbid(js,/signMessage|signTransaction|signAllTransactions|signAndSendTransaction|sendTransaction/,'wallet authority');
forbid(metaverseJS,/Math\.random\s*\(/,'synthetic metaverse telemetry');

requireText(css,'.arvis-chat-shell','chat layout');
requireText(css,'@media(max-width:800px)','mobile layout');
requireText(metaverse,'.arvis-meta-stage','metaverse layout');
requireText(universe,'.universe-entry','universe entry visual contract');
console.log('ARVIS customer chat universe + threat hypothesis + metaverse acceptance: ok');
