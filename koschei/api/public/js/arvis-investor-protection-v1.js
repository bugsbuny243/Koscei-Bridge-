(()=>{
'use strict';
const api=window.KoscheiARVISPremium;
if(!api||window.__koscheiSharedInvestorProtectionV1)return;
window.__koscheiSharedInvestorProtectionV1=true;

const text=value=>String(value??'').replace(/\s+/g,' ').trim();
const obj=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
const arr=value=>Array.isArray(value)?value:[];
const esc=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));

function reportOf(payload){const envelope=obj(payload);return obj(envelope.investigation_report||envelope.report||envelope);}
function decisionOf(payload){return obj(reportOf(payload).investor_protection_decision);}
function finalVerdictOf(payload){const envelope=obj(payload),report=reportOf(envelope);return obj(report.final_verdict||envelope.final_verdict);}
function decisionLabel(value){return text(value).replaceAll('_',' ');}
function actionLabel(decision){
 const explicit=decisionLabel(decision.investor_action);
 if(explicit)return explicit;
 switch(text(decision.decision).toUpperCase()){
  case'AVOID':return'AVOID TARGET';
  case'NOT_CLEARED':return'DO NOT TREAT AS SAFE';
  case'REVIEW_FIRST':return'REQUIRE EXPERT REVIEW';
  case'CLEARED_WITH_LIMITS':return'PROCEED WITH LIMITS';
  default:return'REVIEW RESULT';
 }
}
function chipLabel(decision){
 switch(text(decision.decision).toUpperCase()){
  case'AVOID':return'AVOID · BLOCK';
  case'NOT_CLEARED':return'NOT CLEARED · WITHHOLD';
  case'REVIEW_FIRST':return'REVIEW FIRST';
  case'CLEARED_WITH_LIMITS':return'CLEARED WITH LIMITS';
  default:return'';
 }
}
function verdictEvidenceRefs(payload){
 const verdict=finalVerdictOf(payload),out=[],seen=new Set();
 for(const hit of arr(verdict.triggered_rules)){
  const ruleID=text(hit?.rule_id)||'RULE';
  const status=text(hit?.evidence_status)||'unknown';
  const signatures=arr(hit?.signatures).map(text).filter(Boolean);
  const keys=arr(hit?.evidence_keys).map(text).filter(Boolean);
  for(const key of keys){
   const id=`${ruleID}|key|${key}`;if(seen.has(id))continue;seen.add(id);
   out.push({rule_id:ruleID,evidence_status:status,kind:'evidence_key',reference:key,summary:text(hit?.summary||hit?.title)});
  }
  for(const signature of signatures){
   const id=`${ruleID}|signature|${signature}`;if(seen.has(id))continue;seen.add(id);
   out.push({rule_id:ruleID,evidence_status:status,kind:'transaction_signature',reference:signature,summary:text(hit?.summary||hit?.title)});
  }
 }
 return out;
}
function patchPolicy(card,decision){
 const label=chipLabel(decision);if(!card||!label)return;
 for(const chip of card.querySelectorAll('.arvis-chip')){
  const current=text(chip.textContent).toLowerCase();
  if(!current.startsWith('policy ')&&!current.includes('not blocked')&&!current.includes('review required'))continue;
  chip.textContent=label;chip.classList.remove('good','info');chip.classList.add(text(decision.decision).toUpperCase()==='CLEARED_WITH_LIMITS'?'good':'warn');
 }
}
function renderDecision(card,decision){
 if(!card||!text(decision.decision))return;
 const existing=card.querySelector('.koschei-investor-protection');
 if(existing)return;
 const section=document.createElement('section');section.className='koschei-investor-protection';section.dataset.decision=text(decision.decision).toLowerCase();section.setAttribute('aria-label','Investor protection decision');
 const basis=arr(decision.basis),gaps=arr(decision.critical_gaps);
 section.innerHTML=`<div class="koschei-investor-protection__top"><div><span class="koschei-investor-protection__kicker">INVESTOR PROTECTION DECISION</span><h2>${esc(decisionLabel(decision.decision))}</h2><p>${esc(text(decision.summary)||'Koschei has not issued a safety clearance for this target.')}</p></div><strong class="koschei-investor-protection__action">${esc(actionLabel(decision))}</strong></div><div class="koschei-investor-protection__facts"><div><span>Grade</span><b>${esc(text(decision.grade)||'—')}</b></div><div><span>Verdict</span><b>${esc(text(decision.verdict)||'—')}</b></div><div><span>Execution</span><b>${esc(text(decision.execution_action)||'—')}</b></div><div><span>Cleared</span><b>${decision.cleared===true?'YES':'NO'}</b></div></div>${basis.length?`<div class="koschei-investor-protection__basis"><h3>Why this decision</h3>${basis.slice(0,6).map(item=>`<div class="koschei-investor-protection__basis-row"><b>${esc(text(item.rule_id)||text(item.code)||'Evidence rule')}</b><span>${esc(text(item.evidence_status).toUpperCase())}</span><p>${esc(text(item.summary)||'Evidence-backed risk rule triggered.')}</p></div>`).join('')}</div>`:''}${gaps.length?`<div class="koschei-investor-protection__gaps"><h3>Not collected in this scan (${gaps.length})</h3>${gaps.slice(0,5).map(item=>`<p>${esc(text(item.capability)||'Capability')}: ${esc(text(item.reason)||text(item.status)||'unavailable')}</p>`).join('')}</div>`:''}`;
 const head=card.querySelector('.arvis-premium-head');if(head)head.insertAdjacentElement('afterend',section);else card.prepend(section);
}
function patchEvidenceProjection(root,payload){
 if(!root)return;const refs=verdictEvidenceRefs(payload);if(!refs.length)return;
 const section=root.querySelector('[data-arvis-complete-v4]');if(!section)return;
 const panels=[...section.querySelectorAll('.arvis-truth-panel')];
 const panel=panels.find(item=>text(item.querySelector('.arvis-truth-kicker')?.textContent).toUpperCase()==='EVIDENCE');if(!panel)return;
 panel.querySelector('.arvis-verdict-evidence-refs')?.remove();
 const heading=panel.querySelector('h4');const standalone=(heading?.textContent.match(/^\s*(\d+)/)||[])[1];
 if(heading)heading.textContent=`${standalone||'0'} standalone evidence record(s) · ${refs.length} verdict evidence reference(s)`;
 const list=panel.querySelector('.arvis-truth-list');
 if(list&&Number(standalone||0)===0){const empty=[...list.querySelectorAll('.arvis-truth-row')].find(row=>text(row.textContent).includes('No canonical evidence record attached'));if(empty){const value=empty.querySelector('span');if(value)value.textContent='No standalone canonical evidence row is attached. Verdict-bound evidence references are shown below.';}}
 const block=document.createElement('div');block.className='arvis-verdict-evidence-refs';
 block.innerHTML=`<div class="arvis-verdict-evidence-refs__head"><b>Verdict-bound evidence references</b><span>References are not silently promoted into standalone canonical rows.</span></div>${refs.slice(0,30).map(ref=>`<div class="arvis-verdict-evidence-ref"><b>${esc(ref.rule_id)}</b><span>${esc(ref.kind)} · ${esc(ref.reference)}</span><em>${esc(ref.evidence_status)}</em>${ref.summary?`<p>${esc(ref.summary)}</p>`:''}</div>`).join('')}`;
 panel.appendChild(block);
}
function apply(root,payload,card){const decision=decisionOf(payload);if(!text(decision.decision))return;renderDecision(card,decision);patchPolicy(card,decision);patchEvidenceProjection(root,payload);}

const baseMount=api.mountPremiumCard.bind(api);
api.mountPremiumCard=(rootNode,payload,options={})=>{const card=baseMount(rootNode,payload,options),root=typeof rootNode==='string'?document.getElementById(rootNode):rootNode;apply(root,payload,card);return card;};
api.investorProtectionPresentationVersion='1.0.0';
})();
