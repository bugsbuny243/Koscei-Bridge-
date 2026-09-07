(()=>{
'use strict';
if(window.__koscheiCustomerWorkspaceV2)return;
window.__koscheiCustomerWorkspaceV2=true;

const $=id=>document.getElementById(id);
const text=value=>String(value??'').trim();

async function read(path){
  try{
    const response=await KoscheiAuth.apiCall(path,{method:'GET'});
    const data=await response.json().catch(()=>({}));
    return {ok:response.ok,status:response.status,data};
  }catch(error){
    return {ok:false,status:0,data:{},error};
  }
}

function setKPI(id,value,detail,tone=''){
  const node=$(id);if(!node)return;
  node.dataset.tone=tone;
  const strong=node.querySelector('strong'),small=node.querySelector('small');
  if(strong)strong.textContent=value;
  if(small)small.textContent=detail;
}

function setRuntimeMessage(id,message){
  const node=$(id);if(node)node.innerHTML=`<div class="workspace-command-empty">${message}</div>`;
}

function renderPersistenceBoundary(){
  setKPI('workspaceReportsKpi','NOT LIVE','Durable investigation history is disabled in the stateless production runtime.','warn');
  setKPI('workspaceWatchKpi','NOT LIVE','Continuous watchlist persistence is disabled in the stateless production runtime.','warn');
  setKPI('workspaceAlertsKpi','NOT LIVE','Persisted monitoring alerts require the retired application persistence plane.','warn');
  setRuntimeMessage('workspaceLatestReport','Durable investigation history is not enabled in the current production runtime. Use Deep Scan for a live synchronous investigation; no missing history is represented as an empty vault.');
  setRuntimeMessage('workspaceAlerts','Continuous monitoring and persisted alerts are not enabled in the current production runtime. Koschei does not fabricate alert history while persistence is absent.');
}

function renderSignedOut(){
  const state=$('workspaceLiveState');if(state){state.dataset.state='signed_out';state.textContent='SIGN IN FOR ACCOUNT IDENTITY';}
  setKPI('workspaceAccessKpi','SIGNED OUT','Account identity is private.');
  renderPersistenceBoundary();
  const signIn=$('workspaceSignIn');if(signIn)signIn.hidden=false;
}

async function load(){
  if(!window.KoscheiAuth)return;
  try{await KoscheiAuth.init();}catch{}
  const link=$('sessionLink');
  if(!KoscheiAuth.isLoggedIn()){
    renderSignedOut();return;
  }
  if(link){link.href='/account';link.textContent='Account';}
  const signIn=$('workspaceSignIn');if(signIn)signIn.hidden=true;
  const state=$('workspaceLiveState');if(state){state.dataset.state='partial';state.textContent='VERIFYING SESSION';}

  renderPersistenceBoundary();
  const me=await read('/api/me');
  const user=me?.data?.user&&typeof me.data.user==='object'?me.data.user:{};
  const email=text(user.email||KoscheiAuth.getEmail?.());
  const subject=text(user.auth_subject||user.id);

  if(me.ok&&me.data?.ok===true&&subject){
    setKPI('workspaceAccessKpi','AUTHENTICATED',email||'Neon session verified','good');
    if(state){state.dataset.state='live';state.textContent='LIVE STATELESS ACCOUNT IDENTITY';}
  }else{
    setKPI('workspaceAccessKpi','UNAVAILABLE','Authenticated account identity could not be verified.','bad');
    if(state){state.dataset.state='partial';state.textContent='ACCOUNT IDENTITY UNAVAILABLE';}
  }
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',load);else load();
})();