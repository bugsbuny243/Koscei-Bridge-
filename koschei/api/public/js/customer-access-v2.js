(()=>{
'use strict';
if(window.__koscheiCustomerAccessV2)return;
window.__koscheiCustomerAccessV2=true;

const $=id=>document.getElementById(id);
const text=value=>String(value??'').trim();
const isObject=value=>Boolean(value)&&typeof value==='object'&&!Array.isArray(value);
let currentNetwork='solana-mainnet';

function setText(id,value){const node=$(id);if(node)node.textContent=String(value);}
function setBadge(id,label,tone=''){const node=$(id);if(!node)return;node.textContent=label;node.className=`access-badge${tone?` ${tone}`:''}`;}
function showMessage(message,tone='warn'){const node=$('accessMessage');if(!node)return;node.textContent=message;node.className=`access-message show ${tone}`;}
function clearMessage(){const node=$('accessMessage');if(node){node.textContent='';node.className='access-message';}}
function setState(state,title,detail){const card=$('accessStateCard');if(card)card.dataset.state=state;setText('accessState',title);setText('accessDetail',detail);}
function phantom(){return window.phantom?.solana||window.solana||null;}
function signatureBase64(signature){let value='';for(const byte of signature)value+=String.fromCharCode(byte);return btoa(value);}
function displayDate(value){if(!value)return'—';const parsed=new Date(value);return Number.isNaN(parsed.getTime())?'—':parsed.toLocaleString();}
function displayCount(value){const parsed=Number(value);return Number.isFinite(parsed)?new Intl.NumberFormat('en-US').format(parsed):'—';}

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
  const raw=await response.text();let data={};if(raw){try{data=JSON.parse(raw);}catch{throw new Error('The account service returned invalid JSON.');}}
  if(!response.ok)throw new Error(data?.message||data?.error||'The account operation could not be completed.');
  return data;
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
  if(!wallet.available){setText('wallet','Unavailable');setBadge('walletState','status unavailable','bad');if(unlink)unlink.hidden=true;return;}
  if(wallet.linked){currentNetwork=wallet.network||currentNetwork;setText('wallet',wallet.address);setBadge('walletState','verified identity','good');if(unlink)unlink.hidden=false;if(connect)connect.textContent='Change wallet';return;}
  setText('wallet','Not linked');setBadge('walletState','optional','warn');if(unlink)unlink.hidden=true;if(connect)connect.textContent='Verify with Phantom';
}

function parsePremium(result){
  const data=result?.data,access=isObject(data?.access)?data.access:null;
  if(!result?.ok||!isObject(data)||data.ok!==true||!access)return {available:false,access:null};
  if(typeof access.active!=='boolean'||text(access.source)!=='entitlement'||!text(access.plan))return {available:false,access:null};
  return {available:true,access,active:access.active===true};
}

function renderPremium(premium){
  if(!premium.available){setBadge('premiumState','unavailable','bad');setText('plan','—');setText('accessSource','—');setText('outputCapacity','—');setText('planExpiresAt','—');setState('unavailable','UNAVAILABLE','SaaS entitlement status could not be verified.');return;}
  const access=premium.access,plan=text(access.plan||'none').toUpperCase();
  setText('plan',plan);setText('accessSource','entitlement');setText('outputCapacity',`${displayCount(access.outputs_remaining)} / ${displayCount(access.outputs_total)}`);setText('planExpiresAt',displayDate(access.expires_at));
  if(premium.active){setBadge('premiumState','active','good');setState('active','ACTIVE',`${plan} SaaS entitlement is active. Token holdings are not part of this decision.`);return;}
  setBadge('premiumState','inactive','warn');setState('inactive','INACTIVE','No active paid SaaS entitlement is attached to this account.');
}

async function load({preserveMessage=false}={}){
  if(!preserveMessage)clearMessage();setText('email',KoscheiAuth.getEmail?.()||'—');
  const [walletResult,premiumResult]=await Promise.all([read('/api/auth/wallet/status'),read('/api/auth/premium-access')]);
  renderWallet(parseWallet(walletResult));renderPremium(parsePremium(premiumResult));
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
      showMessage('Wallet identity verification completed. This does not change your SaaS plan.','good');await load({preserveMessage:true});
    }catch(error){showMessage(error.message||'Wallet verification failed.','bad');}
  });
}

async function unlinkWallet(){
  if(!window.confirm('Remove the verified wallet link from this account?'))return;
  const button=$('accessUnlink');
  await runButton(button,'Removing…',async()=>{try{const data=await write('/api/auth/wallet/unlink',{method:'POST',body:'{}'});if(data?.ok!==true||data?.unlinked!==true)throw new Error('Wallet unlink response is incomplete.');showMessage('Wallet identity link removed. Your SaaS entitlement is unchanged.','warn');await load({preserveMessage:true});}catch(error){showMessage(error.message||'Wallet unlink failed.','bad');}});
}

async function bootstrap(){
  try{await KoscheiAuth.init();}catch{}
  if(!KoscheiAuth.requireAuth('/login.html'))return;
  $('accessConnect')?.addEventListener('click',connectWallet);$('accessRefresh')?.addEventListener('click',()=>load());$('accessUnlink')?.addEventListener('click',unlinkWallet);$('accessSignOut')?.addEventListener('click',()=>KoscheiAuth.signOut());
  await load();
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bootstrap);else bootstrap();
})();