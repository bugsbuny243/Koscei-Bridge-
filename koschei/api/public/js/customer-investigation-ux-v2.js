(()=>{
'use strict';
if(window.__koscheiCustomerInvestigationUXV2)return;
window.__koscheiCustomerInvestigationUXV2=true;

const arr=value=>Array.isArray(value)?value:[];
const obj=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
const text=value=>String(value??'').replace(/\s+/g,' ').trim();
const lower=value=>text(value).toLowerCase();
const upper=value=>text(value).toUpperCase();
const el=(tag,className,content)=>{const node=document.createElement(tag);if(className)node.className=className;if(content!==undefined)node.textContent=content;return node;};

function customerRoot(card){
  return card?.closest?.('[data-customer-arvis-result],#result,#scanResult,#reportBody')||null;
}

function canonicalReport(payload){
  const envelope=obj(payload),report=obj(envelope.investigation_report||envelope.report||envelope);
  return {envelope,report,final:obj(report.final_verdict||envelope.final_verdict)};
}

function chipValue(card,prefix){
  const wanted=upper(prefix);
  for(const chip of card.querySelectorAll('.arvis-chip')){
    const value=text(chip.textContent);
    if(upper(value).startsWith(wanted))return text(value.slice(prefix.length));
  }
  return '';
}

function sectionByKicker(card,label){
  const wanted=upper(label);
  return [...card.querySelectorAll('.arvis-premium-section')].find(section=>upper(section.querySelector('.arvis-kicker')?.textContent).includes(wanted))||null;
}

function policyOf(card,payload){
  const {envelope,report,final}=canonicalReport(payload);
  const raw=lower(chipValue(card,'Policy ')||envelope.final_policy||report.final_policy||final.policy||'');
  if(raw.includes('withhold'))return'withhold';
  if(raw.includes('block'))return'block';
  if(raw.includes('warn')||raw.includes('review'))return'warn';
  if(raw.includes('allow'))return'allow';
  return'review';
}

function decisionCopy(policy){
  switch(policy){
    case'block':return 'A deterministic blocking condition was reached. Do not proceed on the basis of this scan.';
    case'warn':return 'Material evidence requires review before you act. Inspect the findings and unresolved evidence below.';
    case'withhold':return 'Required evidence is unresolved or incomplete. Koschei withholds a safety conclusion instead of filling the gap with an assumption.';
    case'allow':return 'No deterministic blocking condition fired. ALLOW is not a safety guarantee; bounded, observed, or unresolved evidence still matters.';
    default:return 'The investigation produced evidence, but no final execution policy is available in this view. Review the technical evidence before acting.';
  }
}

function actionLabel(policy){
  return({block:'DO NOT PROCEED',warn:'REVIEW FIRST',withhold:'EVIDENCE REQUIRED',allow:'NO BLOCK RULE FIRED',review:'REVIEW RESULT'})[policy]||'REVIEW RESULT';
}

function rowSnapshot(row){
  const label=text(row.querySelector('b')?.textContent)||'Evidence finding';
  const detail=text(row.querySelector('span')?.textContent)||text(row.textContent);
  const state=upper(row.querySelector('em')?.textContent||'REVIEW');
  return {label,detail,state,tone:row.classList.contains('bad')?'bad':row.classList.contains('warn')?'warn':'info'};
}

function uniqueFindings(card){
  const material=sectionByKicker(card,'MATERIAL FINDINGS');
  const candidates=material?[...material.querySelectorAll('.arvis-evidence-row')]:[...card.querySelectorAll('.arvis-evidence-row.bad,.arvis-evidence-row.warn')];
  const seen=new Set(),rows=[];
  for(const row of candidates){
    const finding=rowSnapshot(row),key=lower(`${finding.label}|${finding.detail}`);
    if(!key||seen.has(key))continue;
    seen.add(key);rows.push(finding);
  }
  return rows;
}

function unresolvedItems(card,payload){
  const {report,final}=canonicalReport(payload),items=[],seen=new Set();
  const add=value=>{
    const clean=text(value);if(!clean)return;
    const key=lower(clean);if(seen.has(key))return;
    seen.add(key);items.push(clean);
  };
  const pattern=/unresolved|unavailable|partial|pending|withhold|missing evidence|not resolved|could not be verified|bounded window/i;
  card.querySelectorAll('.arvis-evidence-row').forEach(row=>{const value=text(row.textContent);if(pattern.test(value))add(value);});
  arr(report.limitations).forEach(add);
  arr(final.limitations).forEach(add);
  return items;
}

function addFact(grid,label,value){
  const item=el('div','customer-result-fact');item.append(el('span','',label),el('strong','',value||'—'));grid.appendChild(item);
}

function installDecisionSummary(card,payload){
  if(card.querySelector('[data-customer-decision-summary]'))return;
  const head=card.querySelector('.arvis-premium-head');if(!head)return;
  const policy=policyOf(card,payload);
  const grade=text(card.querySelector('.arvis-grade-orb strong')?.textContent)||'—';
  const confidence=(chipValue(card,'Confidence ')||'unknown').toUpperCase();
  const signed=[...card.querySelectorAll('.arvis-chip')].some(chip=>upper(chip.textContent).includes('SIGNED VERDICT'));
  const findings=uniqueFindings(card);
  const unresolved=unresolvedItems(card,payload);

  const section=el('section','customer-result-summary');section.dataset.customerDecisionSummary='v2';
  const top=el('div','customer-result-summary__top');
  const copy=el('div','customer-result-summary__copy');
  copy.append(el('span','customer-result-eyebrow','WHAT THIS RESULT MEANS'),el('h3','',`Why ${policy.toUpperCase()}?`),el('p','',decisionCopy(policy)));
  const action=el('span','customer-result-action',actionLabel(policy));action.dataset.policy=policy;
  top.append(copy,action);section.appendChild(top);

  const facts=el('div','customer-result-facts');
  addFact(facts,'Grade',grade);addFact(facts,'Policy',policy.toUpperCase());addFact(facts,'Integrity',signed?'SIGNED':'UNSIGNED / PENDING');addFact(facts,'Confidence',confidence);
  section.appendChild(facts);

  if(policy==='allow'&&grade!=='—'&&grade!=='A'){
    section.appendChild(el('div','customer-result-boundary',`Grade ${grade} and ALLOW are not contradictory: grade summarizes evidence-backed risk pressure; ALLOW only means the deterministic blocking policy did not fire.`));
  }

  const important=el('div','customer-result-block');
  important.append(el('div','customer-result-block__head','WHAT MATTERS NOW'));
  const findingList=el('div','customer-result-finding-list');
  const selected=findings.filter(item=>item.tone!=='info').slice(0,4);
  const fallback=findings.slice(0,4);
  const shown=selected.length?selected:fallback;
  if(shown.length){
    shown.forEach(item=>{
      const row=el('div',`customer-result-finding ${item.tone}`);
      const body=el('div','');body.append(el('b','',item.label),el('span','',item.detail));
      row.append(body,el('em','',item.state));findingList.appendChild(row);
    });
  }else{
    findingList.appendChild(el('div','customer-result-empty','No material finding row was attached to the premium summary. Open the technical evidence before treating that absence as meaningful.'));
  }
  important.appendChild(findingList);section.appendChild(important);

  const unresolvedBlock=el('div','customer-result-block');
  const unresolvedHead=el('div','customer-result-block__head','WHAT IS UNRESOLVED');unresolvedBlock.appendChild(unresolvedHead);
  if(unresolved.length){
    const list=el('ul','customer-result-unresolved');unresolved.slice(0,4).forEach(item=>list.appendChild(el('li','',item)));unresolvedBlock.appendChild(list);
    if(unresolved.length>4)unresolvedBlock.appendChild(el('small','customer-result-more',`${unresolved.length-4} additional evidence boundary item(s) remain in the full technical evidence.`));
  }else{
    unresolvedBlock.appendChild(el('p','customer-result-no-unresolved','No explicit unresolved item was attached to this summary. Bounded evidence windows and the report disclaimer still apply.'));
  }
  section.appendChild(unresolvedBlock);
  head.insertAdjacentElement('afterend',section);
}

function collapsePremiumEvidence(card){
  if(card.querySelector(':scope > details.customer-full-technical'))return;
  const grid=card.querySelector(':scope > .arvis-premium-grid');if(!grid)return;
  const sectionCount=grid.querySelectorAll(':scope > .arvis-premium-section').length;
  const details=document.createElement('details');details.className='customer-full-technical';details.dataset.customerFullTechnical='v2';
  const summary=document.createElement('summary');
  const copy=el('div','');copy.append(el('b','',`Full technical evidence${sectionCount?` · ${sectionCount} sections`:''}`),el('span','','Funding, token controls, exits, actor context, and the rule-by-rule trace remain available here.'));
  summary.append(copy,el('em','','OPEN EVIDENCE'));details.appendChild(summary);
  grid.parentNode.insertBefore(details,grid);details.appendChild(grid);
}

function isSourcePanel(node){
  return node?.matches?.('.public-investigation-card,#lp-control-evidence,.lp-control-card,#full-scan-live-evidence,.live-evidence-card')===true;
}

function collapseSourcePanels(card){
  const root=customerRoot(card);if(!root)return;
  let details=[...root.children].find(node=>node.matches?.('details.customer-source-panels'));
  if(!details){
    details=document.createElement('details');details.className='customer-source-panels';details.dataset.customerSourcePanels='v2';
    const summary=document.createElement('summary');
    const copy=el('div','');copy.append(el('b','','Source evidence panels'),el('span','','Canonical report, liquidity-control evidence, and bounded live-transaction evidence.'));
    summary.append(copy,el('em','','OPEN SOURCES'));details.appendChild(summary);
    details.appendChild(el('div','customer-source-panels__body'));
    card.insertAdjacentElement('afterend',details);
  }
  const body=details.querySelector('.customer-source-panels__body');
  [...root.children].filter(node=>node!==card&&node!==details&&isSourcePanel(node)).forEach(node=>body.appendChild(node));
  const count=[...body.children].filter(isSourcePanel).length;
  const label=details.querySelector('summary b');if(label)label.textContent=`Source evidence panels${count?` · ${count}`:''}`;
}

function enhance(card,payload){
  if(!card||!customerRoot(card))return;
  const canonical=payload||window.KoscheiCustomerARVISPremium?.latestPayload||{};
  installDecisionSummary(card,canonical);
  collapsePremiumEvidence(card);
  collapseSourcePanels(card);
  card.dataset.customerInvestigationUx='v2';
}

window.addEventListener('koschei:customer-premium-mounted',event=>enhance(event.detail?.card,event.detail?.payload));

function bootstrap(){
  const root=document.querySelector('[data-customer-arvis-result],#result,#scanResult,#reportBody');
  const card=root?.querySelector?.('[data-arvis-premium-card]');
  if(card)enhance(card,window.KoscheiCustomerARVISPremium?.latestPayload||{});
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bootstrap);else bootstrap();
})();
