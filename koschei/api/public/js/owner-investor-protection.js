(()=>{
'use strict';
if(window.__koscheiInvestorProtectionV1)return;
window.__koscheiInvestorProtectionV1=true;

const text=value=>String(value??'').replace(/\s+/g,' ').trim();
const obj=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
const arr=value=>Array.isArray(value)?value:[];
const el=(tag,className,content)=>{const node=document.createElement(tag);if(className)node.className=className;if(content!==undefined)node.textContent=content;return node;};

function currentReport(){
  const payload=obj(window.OwnerRadarKit?.lastScan);
  return obj(payload.investigation_report||payload.report||payload);
}

function renderProtection(card){
  const report=currentReport();
  const decision=obj(report.investor_protection_decision);
  if(!text(decision.decision))return;

  card.querySelector('.koschei-investor-protection')?.remove();
  const section=el('section','koschei-investor-protection');
  section.dataset.decision=text(decision.decision).toLowerCase();
  section.setAttribute('aria-label','Investor protection decision');

  const top=el('div','koschei-investor-protection__top');
  const copy=el('div','');
  copy.append(
    el('span','koschei-investor-protection__kicker','INVESTOR PROTECTION DECISION'),
    el('h2','',text(decision.decision).replaceAll('_',' ')),
    el('p','',text(decision.summary)||'Koschei has not issued a safety clearance for this target.')
  );
  const action=el('strong','koschei-investor-protection__action',text(decision.investor_action).replaceAll('_',' ')||'DO NOT TREAT AS SAFE');
  top.append(copy,action);section.appendChild(top);

  const facts=el('div','koschei-investor-protection__facts');
  const fact=(label,value)=>{const item=el('div','');item.append(el('span','',label),el('b','',text(value)||'—'));facts.appendChild(item);};
  fact('Grade',decision.grade);
  fact('Verdict',decision.verdict);
  fact('Execution',decision.execution_action);
  fact('Cleared',decision.cleared===true?'YES':'NO');
  section.appendChild(facts);

  const basis=arr(decision.basis);
  if(basis.length){
    const list=el('div','koschei-investor-protection__basis');
    list.appendChild(el('h3','','Why this decision'));
    for(const item of basis.slice(0,6)){
      const row=el('div','koschei-investor-protection__basis-row');
      row.append(
        el('b','',text(item.rule_id)||text(item.code)||'Evidence rule'),
        el('span','',text(item.evidence_status).toUpperCase()),
        el('p','',text(item.summary)||'Evidence-backed risk rule triggered.')
      );
      list.appendChild(row);
    }
    section.appendChild(list);
  }

  const gaps=arr(decision.critical_gaps);
  if(gaps.length){
    const gap=el('div','koschei-investor-protection__gaps');
    gap.appendChild(el('h3','',`Not collected in this scan (${gaps.length})`));
    for(const item of gaps.slice(0,5))gap.appendChild(el('p','',`${text(item.capability)||'Capability'}: ${text(item.reason)||text(item.status)||'unavailable'}`));
    section.appendChild(gap);
  }

  const head=card.querySelector('.arvis-premium-head');
  if(head)head.insertAdjacentElement('afterend',section);
  else card.prepend(section);
}

function enhance(root=document){
  root.querySelectorAll?.('[data-arvis-premium-card]').forEach(renderProtection);
}

const observer=new MutationObserver(records=>{
  for(const record of records){
    for(const node of record.addedNodes){
      if(node.nodeType!==1)continue;
      if(node.matches?.('[data-arvis-premium-card]')||node.querySelector?.('[data-arvis-premium-card]'))enhance(node.parentElement||node);
    }
  }
});
observer.observe(document.documentElement,{childList:true,subtree:true});
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',()=>enhance());else enhance();
window.addEventListener('koschei:investigation-rendered',()=>enhance());
})();
