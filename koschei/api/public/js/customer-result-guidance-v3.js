(()=>{
'use strict';
if(window.__koscheiCustomerResultGuidanceV3)return;
window.__koscheiCustomerResultGuidanceV3=true;
const ready=fn=>document.readyState==='loading'?document.addEventListener('DOMContentLoaded',fn,{once:true}):fn();
const text=value=>String(value??'').trim();

function policyOf(summary){
  const action=summary?.querySelector('.customer-result-action');
  const raw=text(action?.dataset.policy||action?.textContent).toLowerCase();
  if(raw.includes('block')||raw.includes('do not proceed'))return'block';
  if(raw.includes('withhold')||raw.includes('evidence required'))return'withhold';
  if(raw.includes('warn')||raw.includes('review first'))return'warn';
  if(raw.includes('allow')||raw.includes('no block'))return'allow';
  return'review';
}

function guidance(policy){
  switch(policy){
    case'block':return {impact:'A deterministic blocking condition is present. Proceeding would expose you to the condition described in the material findings.',action:'Do not proceed until the blocking evidence has been independently resolved or the target changes.'};
    case'warn':return {impact:'Material evidence raises a risk that needs human review before action. The exact issue is listed in the findings below.',action:'Review the material findings and unresolved evidence before buying, connecting or signing.'};
    case'withhold':return {impact:'Koschei cannot establish a safe decision path because required evidence is missing, incomplete or unresolved.',action:'Treat the target as unresolved. Obtain the missing evidence or wait for a complete investigation before proceeding.'};
    case'allow':return {impact:'No deterministic blocking rule fired in the available evidence. That does not mean the target is risk-free or that future state cannot change.',action:'Proceed only if the remaining evidence boundaries are acceptable to you, and re-check before a high-value action.'};
    default:return {impact:'The evidence view does not expose a final execution policy in this summary.',action:'Review the technical evidence and unresolved items before acting.'};
  }
}

function block(label,copy){
  const section=document.createElement('div');section.className='customer-result-block customer-result-guidance-v3';
  const head=document.createElement('div');head.className='customer-result-block__head';head.textContent=label;
  const p=document.createElement('p');p.className='customer-result-guidance-copy';p.textContent=copy;
  section.append(head,p);return section;
}

function enhance(summary){
  if(!summary||summary.dataset.customerGuidanceV3)return;
  const policy=policyOf(summary),copy=guidance(policy);
  const firstEvidenceBlock=summary.querySelector('.customer-result-block');
  const wrap=document.createElement('div');wrap.className='customer-result-guidance-wrap';
  wrap.append(block('WHAT COULD HAPPEN',copy.impact),block('WHAT TO DO NOW',copy.action));
  if(firstEvidenceBlock)summary.insertBefore(wrap,firstEvidenceBlock);else summary.appendChild(wrap);
  summary.dataset.customerGuidanceV3='1';
}

function scan(){document.querySelectorAll('.customer-result-summary').forEach(enhance)}
ready(()=>{scan();const root=document.querySelector('#result,[data-customer-arvis-result]')||document.body;new MutationObserver(scan).observe(root,{childList:true,subtree:true});});
})();