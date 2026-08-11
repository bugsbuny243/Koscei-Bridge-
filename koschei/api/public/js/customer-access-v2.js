(()=>{
'use strict';
if(window.__koscheiCustomerAccessV2)return;
window.__koscheiCustomerAccessV2=true;

const $=id=>document.getElementById(id);
const obj=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
const text=value=>String(value??'').trim();
let currentNetwork='solana-mainnet';

function setText(id,value){const node=$(id);if(node)node.textContent=value;}
function setBadge(id,label,tone=''){const node=$(id);if(!node)return;node.textContent=label;node.className=`access-badge${tone?` ${tone}`:''}`;}
function showMessage(message,tone='warn'){const node=$('accessMessage');if(!node)return;node.textContent=message;node.className=`access-message show ${tone}`;}
function clearMessage(){const node=$('accessMessage');if(node)node.className='access-message';}
function setState(state,title,detail){const card=$('accessStateCard');if(card)card.dataset.state=state;setText('accessState',title);setText('accessDetail',detail);}
function phantom(){return window.phantom?.solana||window.solana||null;}
function signatureBase64(signature){let value='';for(const byte of signature)value+=String.fromCharCode(byte);return btoa(value);}

async function read(path){
  try{
    const response=await KoscheiAuth.apiCall(path,{method:'GET'}),data=await response.json().catch(()=>({}));
    return {ok:response.ok,status:response.status,data};
  }catch(error){return {ok:false,status:0,data:{},error};}
}

async function write(path,options={}){
  const response=await KoscheiAuth.apiCall(path,{...options,headers:{'Content-Type':'application/json',...(options.headers||{})}});
  const data=await response.json().catch(()=>({}));
  if(!response.ok)throw new Error(data.message||data.error||'The access operation could not be completed.');
  return data;
}

function renderThresholds(access){
  const host=$('accessThresholds');if(!host)return;
  const thresholds=obj(access?.thresholds),order=['basic','pro','enterprise'],keys=[...order.filter(key=>thresholds[key]!==undefined),...Object.keys(thresholds).filter(key=>!order.includes(key)).sort()];
  if(!keys.length){host.innerHTML='<div class="ops-empty">Tier thresholds are unavailable from the current token-access policy. No legacy threshold is guessed by the UI.</div>';return;}
  host.innerHTML=keys.map(key=>{const value=text(thresholds[key]);return`<article class="access-threshold"><span>${key}</span><strong>${value||'—'} KOSCH</strong><small>Threshold returned by the current token-access policy.</small></article>`;}).join('');
}

function renderWallet(result){
  const unlink=$('accessUnlink'),connect=$('accessConnect');
  if(!result.ok){setText('wallet','Unavailable');setBadge('walletState','status unavailable','bad');if(unlink)unlink.hidden=true;if(connect)connect.textContent='Verify with Phantom';return {available:false,linked:false,address:''};}
  const linked=result.data?.linked===true,address=text(result.data?.wallet_address);
  if(linked&&address){setText('wallet',address);setBadge('walletState','verified','good');if(unlink)unlink.hidden=false;if(connect)connect.textContent='Change wallet';return {available:true,linked:true,address};}
  setText('wallet','Not linked');setBadge('walletState','verification required','warn');if(unlink)unlink.hidden=true;if(connect)connect.textContent='Verify with Phantom';return {available:true,linked:false,address:''};
}

function renderToken(result){
  if(!result.ok){setText('tier','—');setText('balance','—');setText('network','—');setText('mint','—');setText('checkedAt','—');setText('expiresAt','—');setBadge('gateState','policy unavailable','bad');renderThresholds({});return {available:false,access:{}};}
  const access=obj(result.data?.access);currentNetwork=text(access.network)||currentNetwork;
  setText('tier',(text(access.tier)||'none').toUpperCase());setText('balance',access.amount!==undefined?`${text(access.amount)} KOSCH`:'—');setText('network',text(access.network)||'—');setText('mint',text(access.mint_address)||'—');setText('checkedAt',text(access.checked_at)||'—');setText('expiresAt',text(access.snapshot_expires_at)||'—');
  const gate=access.gate_enabled===true,configured=access.configured===true;
  setBadge('gateState',!configured?'mint not configured':gate?'gate active':'gate disabled',configured&&gate?'good':configured?'warn':'bad');renderThresholds(access);
  return {available:true,access};
}

function renderPremium(result){
  if(!result.ok){setState('unavailable','UNAVAILABLE','Premium access could not be resolved. Missing access evidence is not converted into an inactive or active state.');setBadge('premiumState','unavailable','bad');setText('accessSource','—');return {available:false,active:false,access:{}};}
  const access=obj(result.data?.access),active=access.active===true,tier=(text(access.token_tier)||'none').toUpperCase();
  setState(active?'active':'inactive',active?'ACTIVE':'INACTIVE',active?`KOSCH ${tier} holder access is active.`:'A verified wallet and the current token policy are required for holder access.');setBadge('premiumState',active?'access active':'hold / verify',active?'good':'warn');setText('accessSource',text(access.source)||'—');
  if(!$('tier')?.textContent||$('tier').textContent==='—')setText('tier',tier);
  if(($('balance')?.textContent||'')==='—'&&access.token_amount!==undefined)setText('balance',`${text(access.token_amount)} KOSCH`);
  return {available:true,active,access};
}

function renderConsistency(wallet,token,premium){
  if(wallet.available&&wallet.linked&&token.available&&token.access.wallet_verified===true){
    const tokenWallet=text(token.access.wallet_address);
    if(tokenWallet&&wallet.address&&tokenWallet!==wallet.address){
      setState('unavailable','CONFLICT','Wallet-link and token-access sources returned different wallet addresses. Refresh or re-verify before relying on holder access.');showMessage('Access source mismatch detected. Koschei is not treating conflicting wallet evidence as a clean access state.','bad');return false;
    }
  }
  if(!premium.available&&!wallet.available&&!token.available)showMessage('Wallet, token policy, and premium-access sources are unavailable. No access state was inferred.','bad');
  return true;
}

async function load({preserveMessage=false}={}){
  if(!preserveMessage)clearMessage();
  setText('email',KoscheiAuth.getEmail?.()||'—');
  const [walletResult,tokenResult,premiumResult]=await Promise.all([read('/api/auth/wallet/status'),read('/api/auth/token-access'),read('/api/auth/premium-access')]);
  const wallet=renderWallet(walletResult),token=renderToken(tokenResult),premium=renderPremium(premiumResult);renderConsistency(wallet,token,premium);
  if(!preserveMessage&&walletResult.ok&&tokenResult.ok&&premiumResult.ok){showMessage(premium.active?'Wallet and KOSCH access evidence resolved successfully.':'Access evidence resolved. Verify/hold requirements remain unsatisfied. ',premium.active?'good':'warn');}
}

async function runButton(button,label,work){if(!button||button.disabled)return;const previous=button.textContent;button.disabled=true;button.textContent=label;try{await work();}finally{button.disabled=false;button.textContent=previous;}}

async function connectWallet(){
  const button=$('accessConnect');
  await runButton(button,'Waiting for wallet…',async()=>{
    try{
      const provider=phantom();if(!provider||provider.isPhantom!==true)throw new Error('Phantom wallet was not found in this browser.');
      const connection=await provider.connect(),wallet=text(connection?.publicKey?.toString());if(!wallet)throw new Error('Phantom did not return a wallet address.');
      const challenge=await write('/api/auth/wallet/challenge',{method:'POST',body:JSON.stringify({wallet_address:wallet,network:currentNetwork})});
      if(!text(challenge.message)||!text(challenge.challenge_id))throw new Error('Wallet verification challenge is incomplete.');
      button.textContent='Sign verification message…';
      const signed=await provider.signMessage(new TextEncoder().encode(challenge.message),'utf8');if(!signed?.signature)throw new Error('Phantom did not return a verification signature.');
      await write('/api/auth/wallet/verify',{method:'POST',body:JSON.stringify({challenge_id:challenge.challenge_id,signature:signatureBase64(signed.signature)})});
      showMessage('Wallet verified. Refreshing the official KOSCH balance and access policy.','good');await load({preserveMessage:true});
    }catch(error){showMessage(error.message||'Wallet verification failed.','bad');}
  });
}

async function unlinkWallet(){
  if(!confirm('Remove the verified wallet link from this account?'))return;
  const button=$('accessUnlink');
  await runButton(button,'Removing…',async()=>{try{await write('/api/auth/wallet/unlink',{method:'POST',body:'{}'});showMessage('Wallet link removed. Holder access will be re-evaluated.','warn');await load({preserveMessage:true});}catch(error){showMessage(error.message||'Wallet unlink failed.','bad');}});
}

async function bootstrap(){
  try{await KoscheiAuth.init();}catch{}
  if(!KoscheiAuth.requireAuth('/login'))return;
  $('accessConnect')?.addEventListener('click',connectWallet);$('accessRefresh')?.addEventListener('click',()=>load());$('accessUnlink')?.addEventListener('click',unlinkWallet);$('accessSignOut')?.addEventListener('click',()=>KoscheiAuth.signOut());
  await load();
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bootstrap);else bootstrap();
})();
