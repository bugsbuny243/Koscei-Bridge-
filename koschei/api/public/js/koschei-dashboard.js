(()=>{
'use strict';
if(window.__koscheiDashboard)return;
window.__koscheiDashboard=true;

const $=id=>document.getElementById(id);
const text=value=>String(value??'').trim();

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
    const node=$(id);
    if(node)observer.observe(node,{subtree:true,childList:true,characterData:true,attributes:true});
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

function setNotice(node,message,tone='info'){
  if(!node)return;
  node.textContent=text(message);
  node.dataset.tone=tone;
  node.hidden=!text(message);
}

function feedbackContainsSecretLanguage(value){
  return /\b(seed phrase|private key|mnemonic phrase|recovery phrase)\b/i.test(value);
}

function installFeedback(){
  const form=$('feedbackForm');
  const message=$('feedbackMessage');
  const counter=$('feedbackCounter');
  if(!form||!message)return;
  const updateCounter=()=>{if(counter)counter.textContent=`${message.value.length} / 5000`;};
  message.addEventListener('input',updateCounter);
  updateCounter();
  form.addEventListener('submit',async event=>{
    event.preventDefault();
    const notice=$('feedbackNotice');
    const category=text($('feedbackCategory')?.value);
    const subject=text($('feedbackSubject')?.value);
    const body=text(message.value);
    const button=form.querySelector('button[type="submit"]');
    if(!category){setNotice(notice,'Choose a feedback category.','warn');return;}
    if(subject.length<3||body.length<10){setNotice(notice,'Add a short title and enough detail to investigate the issue.','warn');return;}
    if(feedbackContainsSecretLanguage(body)){
      setNotice(notice,'Remove any seed phrase, recovery phrase or private key before sending feedback.','bad');
      return;
    }
    button.disabled=true;
    setNotice(notice,'Sending feedback…','info');
    try{
      let email='';
      if(window.KoscheiAuth){try{await KoscheiAuth.init();email=text(KoscheiAuth.getEmail?.());}catch{}}
      const response=await fetch('/api/analytics/event',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({event_name:'customer_feedback',email,path:location.pathname,metadata:{category,subject,message:body,source:'customer_panel'}})});
      const data=await response.json().catch(()=>({}));
      if(!response.ok||data.ok===false)throw new Error(text(data.message||data.error)||`Feedback failed (HTTP ${response.status}).`);
      form.reset();
      updateCounter();
      setNotice(notice,'Feedback received.','ok');
    }catch(error){setNotice(notice,text(error?.message||error)||'Feedback could not be sent.','bad');}
    finally{button.disabled=false;}
  });
}

function mount(){
  installNavigation();
  installSectionTracking();
  watchAccountState();
  installFeedback();
  hydrateHealth();
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',mount,{once:true});else mount();
})();