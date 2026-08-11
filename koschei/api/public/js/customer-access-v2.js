(()=>{
'use strict';
if(window.__koscheiCustomerAccessV2)return;
window.__koscheiCustomerAccessV2=true;

const $=id=>document.getElementById(id);
const text=value=>String(value??'').trim();
const hasValue=value=>value!==null&&value!==undefined&&String(value).trim()!=='';
const isObject=value=>Boolean(value)&&typeof value==='object'&&!Array.isArray(value);
const tiers=new Set(['none','basic','pro','enterprise']);
const tierRank=value=>({none:0,basic:1,pro:2,enterprise:3})[String(value||'').toLowerCase()]??-1;
const el=(tag,className,content)=>{const node=document.createElement(tag);if(className)node.className=className;if(content!==undefined)node.textContent=String(content);return node;};
let currentNetwork='solana-mainnet';

function setText(id,value){const node=$(id);if(node)node.textContent=String(value);}
function setBadge(id,label,tone=''){const node=$(id);if(!node)return;node.textContent=label;node.className=`access-badge${tone?` ${tone}`:''}`;}
function showMessage(message,tone='warn'){const node=$('accessMessage');if(!node)return;node.textContent=message;node.className=`access-message show ${tone}`;}
function clearMessage(){const node=$('accessMessage');if(node){node.textContent='';node.className='access-message';}}
function setState(state,title,detail){const card=$('accessStateCard');if(card)card.dataset.state=state;setText('accessState',title);setText('accessDetail',detail);}
function phantom(){return window.phantom?.solana||window.solana||null;}
function signatureBase64(signature){let value='';for(const byte of signature)value+=String.fromCharCode(byte);return btoa(value);}
function bool(value){return typeof value==='boolean'?value:null;}
function validTier(value){const normalized=text(value).toLowerCase();return tiers.has(normalized)?normalized:null;}
function validDate(value){if(!hasValue(value))return null;const parsed=new Date(value);return Number.isNaN(parsed.getTime())?null:parsed;}
function displayDate(value){const parsed=validDate(value);return parsed?parsed.toLocaleString():'—';}
function resetTokenFields(){for(const id of ['tier','balance','network','mint','checkedAt','expiresAt','accessSource'])setText(id,'—');setBadge('gateState','policy unavailable','bad');}

async function read(path){
  try{
    const response=await KoscheiAuth.apiCall(path,{method:'GET'});
    const raw=await response.text();let data={};
    if(raw){try{data=JSON.parse(raw);}catch{return {ok:false,status:response.status,data:{},error:new Error('invalid_json_response')};}}
    return {ok:response.ok,status:response.status,data};
  }catch(error){return {ok:false,status:0,data:{},error};}
}

async function write(path,options={}){
  const headers={...(options.headers||{})};if(options.body!==undefined&&!headers['Content-Type'])headers['Content-Type']='application/json';
  const response=await KoscheiAuth.apiCall(path,{...options,headers});
  const raw=await response.text();let data={};if(raw){try{data=JSON.parse(raw);}catch{throw new Error('The access service returned invalid JSON.');}}
  if(!response.ok)throw new Error(data?.message||data?.error||'The access operation could not be completed.');
  return data;
}

function renderThresholds(access){
  const host=$('accessThresholds');if(!host)return;host.textContent='';
  const thresholds=isObject(access?.thresholds)?access.thresholds:null;
  if(!thresholds){host.appendChild(el('div','ops-empty','Tier thresholds are unavailable from the current token-access policy. No legacy threshold is guessed by the UI.'));return;}
  const order=['basic','pro','enterprise'];const keys=[...order.filter(key=>hasValue(thresholds[key])),...Object.keys(thresholds).filter(key=>!order.includes(key)&&hasValue(thresholds[key])).sort()];
  if(!keys.length){host.appendChild(el('div','ops-empty','Tier thresholds are unavailable from the current token-access policy. No legacy threshold is guessed by the UI.'));return;}
  for(const key of keys){const card=el('article','access-threshold');card.append(el('span','',key),el('strong','',`${text(thresholds[key])} KOSCH`),el('small','','Threshold returned by the current token-access policy.'));host.appendChild(card);}
}

function parseWallet(result){
  const data=result?.data;
  if(!result?.ok||!isObject(data)||data.ok!==true||typeof data.linked!=='boolean')return {available:false,linked:false,address:'',network:''};
  if(data.linked===false)return {available:true,linked:false,address:'',network:''};
  const address=text(data.wallet_address),network=text(data.network);
  if(!address||!network)return {available:false,linked:false,address:'',network:''};
  return {available:true,linked:true,address,network};
}

function renderWallet(wallet){
  const unlink=$('accessUnlink'),connect=$('accessConnect');
  if(!wallet.available){setText('wallet','Unavailable');setBadge('walletState','status unavailable','bad');if(unlink)unlink.hidden=true;if(connect)connect.textContent='Verify with Phantom';return;}
  if(wallet.linked){currentNetwork=wallet.network||currentNetwork;setText('wallet',wallet.address);setBadge('walletState','verified','good');if(unlink)unlink.hidden=false;if(connect)connect.textContent='Change wallet';return;}
  setText('wallet','Not linked');setBadge('walletState','verification required','warn');if(unlink)unlink.hidden=true;if(connect)connect.textContent='Verify with Phantom';
}

function parseToken(result){
  const data=result?.data,access=isObject(data?.access)?data.access:null;
  if(!result?.ok||!isObject(data)||data.ok!==true||!access)return {available:false,access:null,tier:null};
  const gate=bool(access.gate_enabled),configured=bool(access.configured),walletVerified=bool(access.wallet_verified),network=text(access.network),tier=validTier(access.tier);
  if(gate===null||configured===null||walletVerified===null||!network||tier===null||!hasValue(access.amount))return {available:false,access:null,tier:null};
  if(walletVerified&&!text(access.wallet_address))return {available:false,access:null,tier:null};
  if(configured&&!text(access.mint_address))return {available:false,access:null,tier:null};
  return {available:true,access,tier,gate,configured,walletVerified,network,walletAddress:text(access.wallet_address)};
}

function renderToken(token){
  if(!token.available){resetTokenFields();renderThresholds(null);return;}
  const access=token.access;currentNetwork=token.network||currentNetwork;
  setText('tier',token.tier.toUpperCase());setText('balance',`${text(access.amount)} KOSCH`);setText('network',token.network);setText('mint',text(access.mint_address)||'—');setText('checkedAt',displayDate(access.checked_at));setText('expiresAt',displayDate(access.snapshot_expires_at));
  setBadge('gateState',!token.configured?'mint not configured':token.gate?'gate active':'gate disabled',token.configured&&token.gate?'good':token.configured?'warn':'bad');renderThresholds(access);
}

function parsePremium(result){
  const data=result?.data,access=isObject(data?.access)?data.access:null;
  if(!result?.ok||!isObject(data)||data.ok!==true||!access)return {available:false,access:null};
  const active=bool(access.active),gate=bool(access.token_gate_enabled),configured=bool(access.token_configured),walletVerified=bool(access.wallet_verified),tier=validTier(access.token_tier),required=validTier(access.required_token_tier),source=text(access.source);
  if(active===null||gate===null||configured===null||walletVerified===null||tier===null||required===null||!hasValue(access.token_amount)||!source)return {available:false,access:null};
  if(active&&source!=='token')return {available:false,access:null};
  return {available:true,access,active,gate,configured,walletVerified,tier,required,source};
}

function renderPremium(premium){
  if(!premium.available){setBadge('premiumState','unavailable','bad');setText('accessSource','—');return;}
  setBadge('premiumState',premium.active?'access active':'inactive',premium.active?'good':'warn');setText('accessSource',premium.source);
}

function resolveOverall(wallet,token,premium){
  if(!wallet.available||!token.available||!premium.available){setState('unavailable','UNAVAILABLE','Wallet-link, token-access, and premium-access evidence must all be structurally complete before this page claims an access state.');showMessage('One or more access sources are incomplete or unavailable. No ACTIVE or INACTIVE state was inferred.','bad');return false;}
  if(token.gate!==premium.gate||token.configured!==premium.configured||token.walletVerified!==premium.walletVerified||token.tier!==premium.tier){setState('unavailable','CONFLICT','Token-access and premium-access sources returned inconsistent gate, wallet, or tier evidence.');showMessage('Access source mismatch detected. Conflicting evidence is not treated as a clean access state.','bad');return false;}
  if(wallet.linked!==token.walletVerified||wallet.linked!==premium.walletVerified){setState('unavailable','CONFLICT','Wallet-link status disagrees with token/premium wallet-verification evidence.');showMessage('Wallet verification sources disagree. Re-verify or refresh before relying on access.','bad');return false;}
  if(wallet.linked&&token.walletAddress!==wallet.address){setState('unavailable','CONFLICT','Wallet-link and token-access sources returned different wallet addresses.');showMessage('Wallet address mismatch detected. No clean holder-access state was inferred.','bad');return false;}
  const shouldBeActive=token.gate&&token.configured&&token.walletVerified&&tierRank(token.tier)>=tierRank(premium.required);
  if(premium.active!==shouldBeActive){setState('unavailable','CONFLICT','Premium active state does not match the complete token-access eligibility evidence.');showMessage('Premium and token-access decisions disagree. No clean access state was inferred.','bad');return false;}
  if(premium.active){setState('active','ACTIVE',`KOSCH ${token.tier.toUpperCase()} holder access is active and all three account sources agree.`);showMessage('Wallet-link, token policy, and premium-access evidence are complete and consistent.','good');return true;}
  setState('inactive','INACTIVE',wallet.linked?'Current wallet/token evidence does not satisfy the required KOSCH tier or gate policy.':'No verified wallet is linked to this account.');showMessage('Access evidence is complete and consistently inactive.','warn');return true;
}

async function load({preserveMessage=false}={}){
  if(!preserveMessage)clearMessage();setText('email',KoscheiAuth.getEmail?.()||'—');
  const [walletResult,tokenResult,premiumResult]=await Promise.all([read('/api/auth/wallet/status'),read('/api/auth/token-access'),read('/api/auth/premium-access')]);
  const wallet=parseWallet(walletResult),token=parseToken(tokenResult),premium=parsePremium(premiumResult);renderWallet(wallet);renderToken(token);renderPremium(premium);const clean=resolveOverall(wallet,token,premium);
  if(preserveMessage&&!clean)return;
}

async function runButton(button,label,work){if(!button||button.disabled)return;const previous=button.textContent;button.disabled=true;button.textContent=label;try{await work();}finally{button.disabled=false;button.textContent=previous;}}

async function connectWallet(){
  const button=$('accessConnect');
  await runButton(button,'Waiting for wallet…',async()=>{
    try{
      const provider=phantom();if(!provider||provider.isPhantom!==true)throw new Error('Phantom wallet was not found in this browser.');
      const connection=await provider.connect(),wallet=text(connection?.publicKey?.toString());if(!wallet)throw new Error('Phantom did not return a wallet address.');
      const challenge=await write('/api/auth/wallet/challenge',{method:'POST',body:JSON.stringify({wallet_address:wallet,network:currentNetwork})});
      if(!text(challenge?.message)||!text(challenge?.challenge_id)||text(challenge?.wallet_address)!==wallet||!text(challenge?.network))throw new Error('Wallet verification challenge is incomplete or inconsistent.');
      button.textContent='Sign verification message…';
      const signed=await provider.signMessage(new TextEncoder().encode(challenge.message),'utf8');if(!signed?.signature)throw new Error('Phantom did not return a verification message signature.');
      const verified=await write('/api/auth/wallet/verify',{method:'POST',body:JSON.stringify({challenge_id:challenge.challenge_id,signature:signatureBase64(signed.signature)})});
      if(verified?.ok!==true||verified?.verified!==true||text(verified?.wallet_address)!==wallet)throw new Error('Wallet verification response is incomplete or inconsistent.');
      showMessage('Wallet verification completed. Reloading token and premium-access evidence.','good');await load({preserveMessage:true});
    }catch(error){showMessage(error.message||'Wallet verification failed.','bad');}
  });
}

async function unlinkWallet(){
  if(!window.confirm('Remove the verified wallet link from this account?'))return;
  const button=$('accessUnlink');
  await runButton(button,'Removing…',async()=>{try{const data=await write('/api/auth/wallet/unlink',{method:'POST',body:'{}'});if(data?.ok!==true||data?.unlinked!==true)throw new Error('Wallet unlink response is incomplete.');showMessage('Wallet link removed. Reloading holder-access evidence.','warn');await load({preserveMessage:true});}catch(error){showMessage(error.message||'Wallet unlink failed.','bad');}});
}

async function bootstrap(){
  try{await KoscheiAuth.init();}catch{}
  if(!KoscheiAuth.requireAuth('/login.html'))return;
  $('accessConnect')?.addEventListener('click',connectWallet);$('accessRefresh')?.addEventListener('click',()=>load());$('accessUnlink')?.addEventListener('click',unlinkWallet);$('accessSignOut')?.addEventListener('click',()=>KoscheiAuth.signOut());
  await load();
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bootstrap);else bootstrap();
})();
