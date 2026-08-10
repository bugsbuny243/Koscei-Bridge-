(()=>{
'use strict';
if(window.__koscheiOwnerInvestigationUXV1)return;
window.__koscheiOwnerInvestigationUXV1=true;

const text=value=>String(value??'').replace(/\s+/g,' ').trim();
const upper=value=>text(value).toUpperCase();
const el=(tag,className,content)=>{const node=document.createElement(tag);if(className)node.className=className;if(content!==undefined)node.textContent=content;return node;};

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
  return [...card.querySelectorAll('.arvis-premium-section')].find(section=>{
    const kicker=section.querySelector('.arvis-kicker');
    return kicker&&upper(kicker.textContent).includes(wanted);
  })||null;
}

function policyCopy(policy,materialCount,reviewCount){
  switch(policy){
    case'block':return 'A deterministic blocking condition was reached. Do not treat the target as approved for execution.';
    case'warn':return 'Reviewable evidence is present. The result requires human review before acting.';
    case'withhold':return 'Required evidence is incomplete or unresolved. Koschei refuses to convert missing evidence into safety.';
    default:{
      const remaining=materialCount+reviewCount;
      return remaining>0
        ?`No deterministic blocking rule fired, but ${remaining} material/review finding${remaining===1?' remains':'s remain'}. ALLOW is not a safety guarantee.`
        :'No deterministic blocking rule fired under the current ruleset. Review evidence limits before acting.';
    }
  }
}

function policyAction(policy){
  return({block:'DO NOT PROCEED',warn:'REVIEW FIRST',withhold:'EVIDENCE REQUIRED',allow:'NO BLOCK RULE FIRED'})[policy]||'REVIEW RESULT';
}

function addStat(grid,label,value){
  const item=el('div','koschei-decision-stat');
  item.append(el('span','',label),el('strong','',value||'—'));
  grid.appendChild(item);
}

function installDecisionLens(card){
  if(card.dataset.investigationUx==='v1')return;
  card.dataset.investigationUx='v1';
  card.classList.add('koschei-ux-enhanced');

  const head=card.querySelector('.arvis-premium-head');
  if(!head)return;
  const grade=text(card.querySelector('.arvis-grade-orb strong')?.textContent)||'—';
  const policy=(chipValue(card,'Policy ')||'review').toLowerCase();
  const confidence=(chipValue(card,'Confidence ')||'unknown').toLowerCase();
  const signed=[...card.querySelectorAll('.arvis-chip')].some(chip=>upper(chip.textContent).includes('SIGNED VERDICT'));
  const materialCount=card.querySelectorAll('.arvis-evidence-row.bad').length;
  const reviewCount=card.querySelectorAll('.arvis-evidence-row.warn').length;
  const ruleCount=card.querySelectorAll('.arvis-rule.triggered').length||card.querySelectorAll('.arvis-rule').length;

  const lens=el('section','koschei-decision-lens');
  lens.setAttribute('aria-label','Decision summary');
  const top=el('div','koschei-decision-lens__top');
  const copy=el('div','koschei-decision-lens__copy');
  copy.append(el('span','koschei-decision-lens__kicker','DECISION LENS'),el('h3','',`Why ${policy.toUpperCase()}?`),el('p','',policyCopy(policy,materialCount,reviewCount)));
  const action=el('span','koschei-decision-lens__action',policyAction(policy));
  action.dataset.policy=policy;
  top.append(copy,action);
  const grid=el('div','koschei-decision-lens__grid');
  addStat(grid,'Grade',grade);
  addStat(grid,'Verdict integrity',signed?'SIGNED':'UNSIGNED / PENDING');
  addStat(grid,'Confidence',confidence.toUpperCase());
  addStat(grid,'Rule trace',ruleCount?`${ruleCount} evidence rule${ruleCount===1?'':'s'}`:'No attached rule');
  lens.append(top,grid);
  if(policy==='allow'&&grade!=='—'&&grade!=='A'){
    lens.appendChild(el('div','koschei-ux-note',`Grade ${grade} and policy ALLOW answer different questions: the grade summarizes evidence-backed risk pressure; ALLOW only means the deterministic block policy was not triggered.`));
  }
  head.insertAdjacentElement('afterend',lens);
}

function installEvidenceNavigator(card){
  if(card.querySelector('.koschei-evidence-nav'))return;
  const targets=[
    ['Findings','MATERIAL FINDINGS'],
    ['Funding','HOLDER CLUSTER EVIDENCE'],
    ['Token controls','TOKEN-2022 SECURITY GATE'],
    ['Exits','EXIT DESTINATIONS'],
    ['Rule trace','EXPLAINABLE VERDICT']
  ].map(([label,kicker])=>[label,sectionByKicker(card,kicker)]).filter(([,section])=>section);
  if(targets.length<2)return;
  const nav=el('nav','koschei-evidence-nav');
  nav.setAttribute('aria-label','Evidence sections');
  for(const [label,section] of targets){
    section.classList.add('koschei-ux-section-target');
    const button=el('button','',label);button.type='button';
    button.addEventListener('click',()=>section.scrollIntoView({behavior:'smooth',block:'start'}));
    nav.appendChild(button);
  }
  const lens=card.querySelector('.koschei-decision-lens');
  (lens||card.querySelector('.arvis-premium-head'))?.insertAdjacentElement('afterend',nav);
}

function installRuleDisclosure(card){
  const section=sectionByKicker(card,'EXPLAINABLE VERDICT');
  if(!section||section.dataset.ruleDisclosure==='v1')return;
  section.dataset.ruleDisclosure='v1';
  section.classList.add('koschei-rule-section');
  const rules=[...section.querySelectorAll('.arvis-rule')];
  if(rules.length<=4)return;
  section.classList.add('is-collapsed');
  const button=el('button','koschei-rule-toggle');button.type='button';
  const refresh=()=>{const collapsed=section.classList.contains('is-collapsed');button.textContent=collapsed?`Show all ${rules.length} rule records`:'Collapse rule trace';button.setAttribute('aria-expanded',String(!collapsed));};
  button.addEventListener('click',()=>{section.classList.toggle('is-collapsed');refresh();});
  refresh();
  section.appendChild(button);
}

function enhance(root=document){
  root.querySelectorAll?.('[data-arvis-premium-card]').forEach(card=>{
    installDecisionLens(card);
    installEvidenceNavigator(card);
    installRuleDisclosure(card);
  });
}

const observer=new MutationObserver(records=>{
  for(const record of records){
    for(const node of record.addedNodes){
      if(node.nodeType!==1)continue;
      if(node.matches?.('[data-arvis-premium-card]'))enhance(node.parentElement||document);
      else if(node.querySelector?.('[data-arvis-premium-card]'))enhance(node);
    }
  }
});
observer.observe(document.documentElement,{childList:true,subtree:true});
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',()=>enhance());else enhance();
window.addEventListener('koschei:investigation-rendered',()=>enhance());
})();
