(()=>{
'use strict';
if(window.__koscheiChainHealthV2)return;
window.__koscheiChainHealthV2=true;

const CHAINS=[['solana','Solana'],['ethereum','Ethereum'],['base','Base'],['arbitrum','Arbitrum'],['polygon','Polygon'],['optimism','Optimism']];
const REQUEST_TIMEOUT_MS=10000;
const REFRESH_MS=30000;
const $=id=>document.getElementById(id);
let timer=null,inFlight=false;

function el(tag,className,value){const node=document.createElement(tag);if(className)node.className=className;if(value!==undefined)node.textContent=String(value);return node;}
function text(value){return String(value??'').trim();}
function safeStatus(data){return data?.ok===true?'online':text(data?.status)||'unavailable';}
function safeValue(value){const clean=text(value);return clean||'UNAVAILABLE';}
function setSummary(message,tone='neutral'){const node=$('chainSummary');if(!node)return;node.textContent=message;node.className=`chain-summary ${tone}`;}
function statusTone(data){return data?.ok===true?'good':safeStatus(data)==='unavailable'?'neutral':'bad';}
function checkedLabel(date){return `UI refreshed ${date.toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',second:'2-digit'})}`;}
function card(name,data){
  const tone=statusTone(data),article=el('article',`chain-card ${tone}`),top=el('div','chain-card-head');
  top.append(el('b','',name),el('span',`chain-dot ${tone}`));
  article.append(top,el('div',`chain-status ${tone}`,data?.ok===true?'ONLINE':safeStatus(data).toUpperCase()));
  const facts=el('dl','chain-facts');
  for(const [label,value] of [['Network',safeValue(data?.network)],['Provider',safeValue(data?.provider)],['Result',safeValue(data?.result)]]){const row=el('div');row.append(el('dt','',label),el('dd','',value));facts.append(row);}
  article.append(facts);
  if(text(data?.error))article.append(el('p','chain-error',data.error));
  return article;
}
function row(name,data,refreshedAt){
  const tone=statusTone(data),node=el('div','chain-row');
  node.append(el('b','',name),el('span','',safeValue(data?.network)),el('span',`chain-status ${tone}`,data?.ok===true?'ONLINE':safeStatus(data).toUpperCase()),el('span','',`${safeValue(data?.provider)} · ${checkedLabel(refreshedAt)}`));
  return node;
}
function unavailable(chain,error){return{ok:false,status:'unavailable',chain:chain,network:'',provider:'',result:'',error:text(error?.message)||'Health evidence unavailable.'};}
async function fetchHealth(chain){
  const controller=new AbortController(),timeout=setTimeout(()=>controller.abort('chain_health_timeout'),REQUEST_TIMEOUT_MS);
  try{
    const response=await fetch(`/api/web3/health?chain=${encodeURIComponent(chain)}`,{cache:'no-store',signal:controller.signal});
    const data=await response.json().catch(()=>null);
    if(!response.ok||!data||typeof data!=='object')throw new Error(data?.error||`Health endpoint returned HTTP ${response.status}.`);
    return data;
  }catch(error){if(error?.name==='AbortError')return unavailable(chain,new Error(`Health check exceeded ${REQUEST_TIMEOUT_MS/1000} seconds.`));return unavailable(chain,error);}
  finally{clearTimeout(timeout);}
}
function render(results,refreshedAt){
  const cards=$('chainCards'),rows=$('chainRows');if(!cards||!rows)return;
  cards.replaceChildren(...results.map(([name,data])=>card(name,data)));
  rows.replaceChildren(...results.map(([name,data])=>row(name,data,refreshedAt)));
  const online=results.filter(([,data])=>data?.ok===true).length,unavailableCount=results.filter(([,data])=>safeStatus(data)==='unavailable').length;
  setSummary(`${online}/${results.length} configured chain checks returned ONLINE. ${unavailableCount?`${unavailableCount} check(s) were unavailable. `:''}A non-online state is not rewritten as healthy.`,online===results.length?'good':online===0?'bad':'warn');
  const stamp=$('chainUpdated');if(stamp)stamp.textContent=checkedLabel(refreshedAt);
}
async function load(){
  if(inFlight)return;inFlight=true;if(timer){clearTimeout(timer);timer=null;}
  const button=$('chainRefresh');if(button){button.disabled=true;button.textContent='Checking…';}
  setSummary('Collecting current chain-provider health evidence…','neutral');
  try{
    const values=await Promise.all(CHAINS.map(async([id,name])=>[name,await fetchHealth(id)]));
    render(values,new Date());
  }finally{
    if(button){button.disabled=false;button.textContent='Refresh now';}
    inFlight=false;timer=setTimeout(load,REFRESH_MS);
  }
}

$('chainRefresh')?.addEventListener('click',load);
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',load);else load();
})();
