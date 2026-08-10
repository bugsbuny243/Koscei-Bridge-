(()=>{
'use strict';
if(window.__koscheiOwnerInvestigationUXV1)return;
window.__koscheiOwnerInvestigationUXV1=true;

const text=value=>String(value??'').replace(/\s+/g,' ').trim();
const upper=value=>text(value).toUpperCase();
const arr=value=>Array.isArray(value)?value:[];
const obj=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
const el=(tag,className,content)=>{const node=document.createElement(tag);if(className)node.className=className;if(content!==undefined)node.textContent=content;return node;};
const short=(value,head=8,tail=6)=>{const raw=text(value);return raw.length>head+tail+3?`${raw.slice(0,head)}…${raw.slice(-tail)}`:raw||'—';};

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

function currentReport(){
  const payload=obj(window.OwnerRadarKit?.lastScan);
  return obj(payload.investigation_report||payload.report||payload);
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

function installCampaignIntelligence(card){
  if(card.dataset.campaignUx==='v1')return;
  const report=currentReport();
  const tempo=obj(report.campaign_tempo_fingerprint);
  const signatures=obj(report.behavioral_signatures);
  if(!Object.keys(tempo).length&&!Object.keys(signatures).length)return;
  card.dataset.campaignUx='v1';

  const grid=card.querySelector('.arvis-premium-grid');
  if(!grid)return;
  const section=el('article','arvis-premium-section full koschei-operator-intelligence koschei-ux-section-target');
  const head=el('div','arvis-section-head');
  const headCopy=el('div','');
  headCopy.append(el('span','arvis-kicker','OPERATOR INTELLIGENCE'),el('h3','','Funding trajectory & recurring campaign behavior'),el('p','','Cross-wallet correlations are investigation context only. They do not identify a real-world operator or prove common control, intent, a rug, or wrongdoing.'));
  head.appendChild(headCopy);section.appendChild(head);

  const statGrid=el('div','koschei-operator-stats');
  const stat=(label,value)=>{const item=el('div','koschei-operator-stat');item.append(el('span','',label),el('strong','',String(value??'—')));statGrid.appendChild(item);};
  stat('Tempo paths',tempo.path_count??0);
  stat('Distinct actors',tempo.distinct_actor_count??0);
  stat('Distinct tokens',tempo.distinct_token_count??0);
  stat('Funding sources',tempo.distinct_funding_source_count??0);
  section.appendChild(statGrid);

  const matches=arr(signatures.matches).filter(match=>match?.triggered===true);
  const list=el('div','koschei-operator-list');
  if(matches.length){
    for(const match of matches.slice(0,8)){
      const row=el('div','koschei-operator-row');
      const title=el('div','koschei-operator-row__title');
      title.append(el('strong','',text(match.signature_id||'Behavior family')),el('span','',text(match.status||match.evidence_status||'observed')));
      row.append(title,el('b','',text(match.label||'Recurring technical behavior')),el('p','',text(match.explanation||'Evidence-backed behavior family observed.')));
      const facts=el('div','koschei-operator-row__facts');
      const actorCount=arr(match.actor_wallets).length,tokenCount=arr(match.targets).length,funderCount=arr(match.funding_sources).length;
      if(actorCount)facts.appendChild(el('span','',`${actorCount} actor${actorCount===1?'':'s'}`));
      if(tokenCount)facts.appendChild(el('span','',`${tokenCount} token${tokenCount===1?'':'s'}`));
      if(funderCount)facts.appendChild(el('span','',`${funderCount} funder${funderCount===1?'':'s'}`));
      facts.appendChild(el('span','',match.verdict_authority===true?'verdict authority':'watch/context only'));
      row.appendChild(facts);list.appendChild(row);
    }
  }else{
    list.appendChild(el('div','arvis-empty',tempo.available===true?'No recurring behavior family triggered for the retained campaign paths.':'No complete verified campaign-tempo path is available yet.'));
  }
  section.appendChild(list);

  const paths=arr(tempo.paths);
  if(paths.length){
    const detail=document.createElement('details');detail.className='koschei-tempo-details';
    const summary=el('summary','',`Inspect ${paths.length} verified tempo path${paths.length===1?'':'s'}`);detail.appendChild(summary);
    const pathList=el('div','koschei-tempo-paths');
    for(const path of paths.slice(0,12)){
      const row=el('div','koschei-tempo-path');
      row.append(el('b','',`${short(path.funding_source_wallet)} → ${short(path.actor_wallet)} → ${short(path.token_mint)}`),el('span','',text(path.tempo_profile||path.terminal_family||'verified path')));
      pathList.appendChild(row);
    }
    detail.appendChild(pathList);section.appendChild(detail);
  }

  const ruleSection=sectionByKicker(card,'EXPLAINABLE VERDICT');
  if(ruleSection)grid.insertBefore(section,ruleSection);else grid.appendChild(section);
}

function installEvidenceNavigator(card){
  card.querySelector('.koschei-evidence-nav')?.remove();
  const targets=[
    ['Findings','MATERIAL FINDINGS'],
    ['Funding','HOLDER CLUSTER EVIDENCE'],
    ['Operator intel','OPERATOR INTELLIGENCE'],
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
    installCampaignIntelligence(card);
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
