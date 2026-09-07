(()=>{
'use strict';
if(window.__koscheiDashboard)return;
window.__koscheiDashboard=true;

const $=id=>document.getElementById(id);
const text=value=>String(value??'').trim();

function node(tag,className,value){
  const element=document.createElement(tag);
  if(className)element.className=className;
  if(value!==undefined)element.textContent=text(value);
  return element;
}

function setNav(open){
  document.body.classList.toggle('nav-open',open);
  const trigger=$('mobileMenu');
  if(trigger)trigger.setAttribute('aria-expanded',open?'true':'false');
}

function installNavigation(){
  const trigger=$('mobileMenu');
  trigger?.addEventListener('click',()=>setNav(!document.body.classList.contains('nav-open')));
  document.querySelectorAll('.side-nav a').forEach(link=>link.addEventListener('click',()=>setNav(false)));
  document.addEventListener('click',event=>{
    if(!document.body.classList.contains('nav-open'))return;
    const sidebar=$('sidebar');
    if(sidebar?.contains(event.target)||trigger?.contains(event.target))return;
    setNav(false);
  });
  document.addEventListener('keydown',event=>{if(event.key==='Escape')setNav(false);});
}

async function hydrateHealth(){
  const pipeline=$('commandPipelineState');
  const top=$('topStatus');
  const controller=new AbortController();
  const timer=window.setTimeout(()=>controller.abort('health_timeout'),10000);
  try{
    const response=await fetch('/health',{cache:'no-store',credentials:'same-origin',signal:controller.signal});
    const data=await response.json().catch(()=>({}));
    if(!response.ok)throw new Error(data.error||data.details||`HTTP ${response.status}`);
    const arvis=data.arvis||{};
    const raw=text(arvis.pipeline_status||arvis.status||data.status||'unknown').toLowerCase();
    const ready=['ready','healthy','live','connected','ok','manual'].some(state=>raw.includes(state));
    if(pipeline){pipeline.textContent=ready?'ARVIS PIPELINE READY':'DEGRADED / UNVERIFIED';pipeline.closest('.status-row')?.setAttribute('data-tone',ready?'ready':'unknown');}
    if(top){top.dataset.state=ready?'live':'degraded';top.querySelector('span').textContent=ready?'Production pipeline ready':'Pipeline degraded / unverified';}
  }catch(error){
    if(pipeline){pipeline.textContent='UNAVAILABLE';pipeline.closest('.status-row')?.setAttribute('data-tone','unknown');}
    if(top){top.dataset.state='degraded';top.querySelector('span').textContent='Evidence service unavailable';top.title=text(error?.message||error);}
  }finally{window.clearTimeout(timer);}
}

function syncAccountState(){
  const source=$('workspaceLiveState');
  const target=$('commandAccountState');
  if(target){
    target.textContent=text(source?.textContent)||'UNAVAILABLE';
    const tone=source?.dataset?.state==='live'?'ready':'unknown';
    target.closest('.status-row')?.setAttribute('data-tone',tone);
  }
  const jobs=$('workspaceReportsKpi')?.querySelector('strong');
  const jobsTarget=$('commandInvestigationState');
  if(jobsTarget)jobsTarget.textContent=text(jobs?.textContent)||'NOT LIVE';
}

function watchAccountState(){
  syncAccountState();
  const observer=new MutationObserver(syncAccountState);
  for(const id of ['workspaceLiveState','workspaceReportsKpi']){
    const item=$(id);
    if(item)observer.observe(item,{subtree:true,childList:true,characterData:true,attributes:true});
  }
}

function installSectionTracking(){
  if(!('IntersectionObserver'in window))return;
  const links=[...document.querySelectorAll('.side-nav a[href^="#"]')];
  const byId=new Map(links.map(link=>[link.getAttribute('href').slice(1),link]));
  const observer=new IntersectionObserver(entries=>{
    const visible=entries.filter(entry=>entry.isIntersecting).sort((a,b)=>b.intersectionRatio-a.intersectionRatio)[0];
    if(!visible)return;
    links.forEach(link=>link.removeAttribute('aria-current'));
    byId.get(visible.target.id)?.setAttribute('aria-current','page');
  },{rootMargin:'-20% 0px -65% 0px',threshold:[.05,.2,.5]});
  byId.forEach((_,id)=>{const section=$(id);if(section)observer.observe(section);});
}

function appendMetric(grid,label,value){
  const item=node('div','preflight-metric');
  item.append(node('span','',label),node('strong','',value));
  grid.append(item);
}

function appendEvidenceList(parent,title,items,renderItem){
  if(!Array.isArray(items)||items.length===0)return;
  const section=node('section','preflight-evidence');
  section.append(node('h3','',title));
  const list=node('div','preflight-evidence-list');
  items.forEach(item=>list.append(renderItem(item)));
  section.append(list);
  parent.append(section);
}

function resultTone(data){
  const action=text(data?.action).toLowerCase();
  const risk=text(data?.risk_level).toLowerCase();
  if(action==='block'||risk==='critical'||risk==='high')return 'danger';
  if(action==='warn'||action==='withhold'||risk==='medium'||risk==='unknown')return 'warn';
  return 'good';
}

function renderPreflightError(message){
  const root=$('transactionPreflightResult');
  if(!root)return;
  root.dataset.state='error';
  root.replaceChildren();
  const box=node('div','preflight-empty');
  box.append(node('strong','','Simulation unavailable.'),node('span','',message||'No safety decision was produced.'));
  root.append(box);
}

function renderPreflightResult(data,httpStatus){
  const root=$('transactionPreflightResult');
  if(!root)return;
  const tone=resultTone(data);
  root.dataset.state=tone;
  root.replaceChildren();

  const card=node('article','preflight-assessment');
  const heading=node('div','preflight-assessment-head');
  const title=node('div');
  title.append(node('span','',text(data.product)||'Koschei Transaction Firewall'),node('strong','',text(data.summary)||'Simulation completed.'));
  const decision=node('div','preflight-decision');
  decision.dataset.tone=tone;
  decision.append(node('span','',text(data.risk_level)||'unknown'),node('strong','',text(data.action)||'withhold'));
  heading.append(title,decision);
  card.append(heading);

  const metrics=node('div','preflight-metrics');
  appendMetric(metrics,'Policy outcome',text(data.policy_outcome)||'unknown');
  appendMetric(metrics,'Risk level',text(data.risk_level)||'unknown');
  const riskKnown=text(data.risk_level).toLowerCase()!=='unknown';
  appendMetric(metrics,'Risk index',riskKnown&&Number.isFinite(Number(data.risk_index))?String(Number(data.risk_index)):'WITHHELD');
  appendMetric(metrics,'Compute units',Number.isFinite(Number(data?.simulation?.units_consumed))?String(Number(data.simulation.units_consumed)):'—');
  appendMetric(metrics,'HTTP outcome',String(httpStatus));
  appendMetric(metrics,'Mode',text(data.mode)||'unknown');
  card.append(metrics);

  const provenance=node('div','preflight-provenance');
  provenance.append(node('span','','Request ID'),node('code','',text(data.request_id)||'—'),node('span','','Transaction fingerprint'),node('code','',text(data.transaction_fingerprint)||'—'));
  card.append(provenance);

  appendEvidenceList(card,'Findings',data.findings,item=>{
    const finding=node('div','preflight-finding');
    finding.dataset.severity=text(item?.severity).toLowerCase()||'unknown';
    const head=node('div');
    head.append(node('strong','',text(item?.title)||text(item?.code)||'Finding'),node('span','',text(item?.severity)||'unknown'));
    finding.append(head,node('p','',text(item?.evidence)||'Evidence detail unavailable.'));
    return finding;
  });

  appendEvidenceList(card,'Invoked programs',data.program_ids,item=>{
    const row=node('code','preflight-program',item);
    return row;
  });

  const logs=Array.isArray(data?.simulation?.logs)?data.simulation.logs:[];
  if(logs.length){
    const details=node('details','preflight-logs');
    details.append(node('summary','',`Simulation logs · ${logs.length}`));
    const pre=node('pre');
    pre.textContent=logs.map(text).join('\n');
    details.append(pre);
    card.append(details);
  }

  if(data?.simulation?.error){
    const simulationError=node('div','preflight-warning');
    simulationError.dataset.tone='danger';
    const value=typeof data.simulation.error==='string'?data.simulation.error:JSON.stringify(data.simulation.error);
    simulationError.textContent=`Simulation error: ${value}`;
    card.append(simulationError);
  }
  if(text(data.warning))card.append(node('div','preflight-warning',data.warning));
  root.append(card);
}

function containsSecretLanguage(value){
  return /\b(seed phrase|recovery phrase|mnemonic|private key)\b/i.test(value);
}

function installTransactionPreflight(){
  const form=$('transactionPreflightForm');
  const transaction=$('transactionPreflightTransaction');
  const wallet=$('transactionPreflightWallet');
  const button=$('transactionPreflightSubmit');
  if(!form||!transaction||!button)return;

  form.addEventListener('submit',async event=>{
    event.preventDefault();
    const serialized=text(transaction.value);
    const walletValue=text(wallet?.value);
    if(!serialized){renderPreflightError('A base64 serialized Solana transaction is required.');return;}
    if(containsSecretLanguage(serialized)||containsSecretLanguage(walletValue)){
      renderPreflightError('Remove any seed phrase, recovery phrase, mnemonic or private key. Koschei never needs those secrets.');
      return;
    }

    const root=$('transactionPreflightResult');
    if(root){root.dataset.state='loading';root.replaceChildren(node('div','preflight-empty','Simulating against Solana mainnet…'));}
    button.disabled=true;
    const controller=new AbortController();
    const timer=window.setTimeout(()=>controller.abort('preflight_timeout'),30000);
    try{
      const response=await fetch('/api/public/transaction-simulate',{
        method:'POST',
        credentials:'same-origin',
        headers:{'Content-Type':'application/json'},
        signal:controller.signal,
        body:JSON.stringify({network:'solana-mainnet',encoding:'base64',transaction:serialized,wallet:walletValue})
      });
      const data=await response.json().catch(()=>({}));
      if(data&&data.request_id&&data.product){
        renderPreflightResult(data,response.status);
        return;
      }
      renderPreflightError(text(data.message||data.error||data.code)||`Simulation failed (HTTP ${response.status}).`);
    }catch(error){
      const timedOut=controller.signal.aborted;
      renderPreflightError(timedOut?'Simulation timed out. No safety decision was produced.':text(error?.message||error)||'Simulation request failed.');
    }finally{
      window.clearTimeout(timer);
      button.disabled=false;
    }
  });
}

function mount(){
  installNavigation();
  installSectionTracking();
  watchAccountState();
  installTransactionPreflight();
  hydrateHealth();
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',mount,{once:true});else mount();
})();