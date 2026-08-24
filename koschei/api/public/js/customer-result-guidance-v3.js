(()=>{
'use strict';
if(window.__koscheiCustomerResultGuidanceV3)return;
window.__koscheiCustomerResultGuidanceV3=true;
const ready=fn=>document.readyState==='loading'?document.addEventListener('DOMContentLoaded',fn,{once:true}):fn();
const arr=value=>Array.isArray(value)?value:[];
const obj=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
const text=value=>String(value??'').replace(/\s+/g,' ').trim();

function canonicalReport(payload){
  const envelope=obj(payload),report=obj(envelope.investigation_report||envelope.report||envelope);
  return {envelope,report};
}

function threatOf(payload){
  const {envelope,report}=canonicalReport(payload);
  return obj(report.threat_anticipation||envelope.threat_anticipation);
}

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

function pathwayRank(status){
  return({open:0,unknown:1,limited:2,observed:3,not_observed:4,closed:5})[text(status).toLowerCase()]??6;
}

function threatBlock(threat){
  const section=document.createElement('div');section.className='customer-result-block customer-threat-brief-v3';
  const head=document.createElement('div');head.className='customer-result-block__head';head.textContent='WHAT COULD HAPPEN';section.appendChild(head);
  const pathways=arr(threat.pathways).filter(item=>text(item?.label||item?.id)).sort((a,b)=>pathwayRank(a?.status)-pathwayRank(b?.status)).slice(0,6);
  if(!pathways.length)return null;
  const list=document.createElement('div');list.className='customer-threat-pathways';
  pathways.forEach(item=>{
    const row=document.createElement('div');row.className='customer-threat-pathway';
    const top=document.createElement('div');top.className='customer-threat-pathway__top';
    const label=document.createElement('b');label.textContent=text(item.label||item.id)||'Threat pathway';
    const state=document.createElement('em');state.className=`state-${text(item.status).toLowerCase().replace(/[^a-z0-9_-]/g,'-')}`;state.textContent=text(item.status||'unknown').replace(/_/g,' ').toUpperCase();
    top.append(label,state);
    const summary=document.createElement('p');summary.textContent=text(item.summary)||'No bounded pathway explanation was attached.';
    row.append(top,summary);list.appendChild(row);
  });
  section.appendChild(list);
  const primary=text(threat.primary_exposure);
  if(primary){const note=document.createElement('p');note.className='customer-threat-primary';note.textContent=primary;section.appendChild(note);}
  return section;
}

function watchCopy(threat){
  const signals=arr(threat.watch_signals).filter(item=>text(item?.title||item?.trigger)).slice(0,4);
  if(signals.length)return signals.map(item=>`${text(item.title||item.id)} — ${text(item.trigger)}`).join(' ');
  const next=[];
  arr(threat.scenarios).forEach(scenario=>arr(scenario?.next_signals).forEach(signal=>{const value=text(signal);if(value&&!next.includes(value))next.push(value);}));
  if(next.length)return next.slice(0,4).join(' · ');
  return'';
}

function render(summary,payload){
  if(!summary)return;
  const threat=threatOf(payload);
  const hasThreat=arr(threat.pathways).length>0;
  const desiredMode=hasThreat?'threat':'fallback';
  if(summary.dataset.customerGuidanceV3===desiredMode)return;
  summary.querySelectorAll('[data-customer-guidance-v3]').forEach(node=>node.remove());
  const policy=policyOf(summary),copy=guidance(policy);
  const firstEvidenceBlock=summary.querySelector('.customer-result-block');
  const shell=document.createElement('div');shell.dataset.customerGuidanceV3='1';shell.className='customer-result-guidance-shell-v3';
  if(hasThreat){
    const threatSection=threatBlock(threat);if(threatSection)shell.appendChild(threatSection);
    const wrap=document.createElement('div');wrap.className='customer-result-guidance-wrap';
    const watch=watchCopy(threat);
    if(watch)wrap.appendChild(block('WHAT TO WATCH',watch));
    wrap.appendChild(block('WHAT TO DO NOW',copy.action));
    shell.appendChild(wrap);
  }else{
    const wrap=document.createElement('div');wrap.className='customer-result-guidance-wrap';
    wrap.append(block('WHAT COULD HAPPEN',copy.impact),block('WHAT TO DO NOW',copy.action));
    shell.appendChild(wrap);
  }
  if(firstEvidenceBlock)summary.insertBefore(shell,firstEvidenceBlock);else summary.appendChild(shell);
  summary.dataset.customerGuidanceV3=desiredMode;
}

function latestPayload(){return window.KoscheiCustomerARVISPremium?.latestPayload||{};}
function scan(){document.querySelectorAll('.customer-result-summary').forEach(summary=>render(summary,latestPayload()));}
window.addEventListener('koschei:customer-premium-mounted',event=>queueMicrotask(()=>{
  const root=event.detail?.card?.closest?.('[data-customer-arvis-result],#result,#scanResult,#reportBody')||document;
  render(root.querySelector?.('.customer-result-summary'),event.detail?.payload||latestPayload());
}));
ready(()=>{scan();const root=document.querySelector('#result,[data-customer-arvis-result]')||document.body;new MutationObserver(scan).observe(root,{childList:true,subtree:true});});
})();