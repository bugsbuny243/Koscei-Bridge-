(()=>{
'use strict';
if(window.__koscheiCommandUniverseV2)return;
window.__koscheiCommandUniverseV2=true;
const text=v=>String(v??'').trim();
function sync(){
  const live=document.querySelector('[data-koschei-live]');
  const liveOut=document.getElementById('commandPipelineState');
  if(liveOut){const t=text(live?.textContent)||'Unavailable';liveOut.textContent=t;liveOut.closest('.command-status-row')?.setAttribute('data-tone',/operational|ready|live/i.test(t)?'ready':'unknown');}
  const account=document.getElementById('workspaceLiveState');
  const accountOut=document.getElementById('commandAccountState');
  if(accountOut){const t=text(account?.textContent)||'Unavailable';accountOut.textContent=t;accountOut.closest('.command-status-row')?.setAttribute('data-tone',account?.dataset?.state==='ready'?'ready':'unknown');}
  const report=document.querySelector('#workspaceReportsKpi strong');
  const reportOut=document.getElementById('commandInvestigationState');
  if(reportOut)reportOut.textContent=text(report?.textContent)||'—';
}
document.addEventListener('DOMContentLoaded',()=>{document.body.classList.add('koschei-command-universe');sync();const observer=new MutationObserver(sync);['workspaceLiveState','workspaceReportsKpi'].forEach(id=>{const el=document.getElementById(id);if(el)observer.observe(el,{subtree:true,childList:true,characterData:true,attributes:true});});const live=document.querySelector('[data-koschei-live]');if(live)observer.observe(live,{subtree:true,childList:true,characterData:true});});
})();