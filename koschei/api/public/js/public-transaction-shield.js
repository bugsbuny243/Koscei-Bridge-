(()=>{
'use strict';
const REQUEST_TIMEOUT_MS=30000;
const $=id=>document.getElementById(id);
const form=$('txForm'),submit=$('submitTx'),empty=$('empty'),result=$('result');
const labelAction=value=>({allow:'DEVAM EDEBİLİRSİN',warn:'İMZALAMADAN İNCELE',block:'İMZALAMA',withhold:'KARAR BEKLETİLDİ'}[String(value||'').toLowerCase()]||'İNCELE');
const classFor=value=>{value=String(value||'unknown').toLowerCase();return value==='low'?'low':value==='medium'?'medium':value==='high'?'high':'critical'};
function renderList(id,items,formatter,fallback){const el=$(id);el.innerHTML='';const list=Array.isArray(items)&&items.length?items:[fallback];list.forEach(item=>{const li=document.createElement('li');li.textContent=formatter?formatter(item):String(item||'');el.appendChild(li)})}
async function fetchJSON(url,options={}){const controller=new AbortController();const timer=setTimeout(()=>controller.abort('koschei_api_timeout'),REQUEST_TIMEOUT_MS);try{const response=await fetch(url,{...options,signal:controller.signal});const data=await response.json().catch(()=>({}));if(!response.ok){const error=new Error(data.message||data.code||`HTTP ${response.status}`);error.data=data;throw error}return data}catch(error){if(error?.name==='AbortError')throw new Error(`Kanıt servisi ${REQUEST_TIMEOUT_MS/1000} saniyede yanıt vermedi.`);throw error}finally{clearTimeout(timer)}}
form.addEventListener('submit',async event=>{
 event.preventDefault();const transaction=$('transaction').value.trim();if(!transaction)return;
 submit.disabled=true;submit.textContent='Solana simülasyonu çalışıyor…';result.hidden=true;empty.hidden=false;empty.innerHTML='<h2>İşlem zincir üzerinde simüle ediliyor</h2><p>İşlem gönderilmiyor ve imzalanmıyor.</p>';
 try{
  const data=await fetchJSON('/api/public/transaction-simulate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({transaction,encoding:'base64',network:'solana-mainnet',wallet:$('wallet').value.trim()})});
  empty.hidden=true;result.hidden=false;
  $('action').textContent=labelAction(data.action);$('action').className='action '+classFor(data.risk_level);
  $('risk').textContent=`${Number(data.risk_index||0)}/100`;$('summary').textContent=data.summary||'Simülasyon tamamlandı.';
  $('fingerprint').textContent=data.transaction_fingerprint||'—';$('units').textContent=data.simulation&&Number.isFinite(Number(data.simulation.units_consumed))?Number(data.simulation.units_consumed).toLocaleString('tr-TR'):'DOĞRULANAMADI';
  $('programCount').textContent=Array.isArray(data.program_ids)?data.program_ids.length:'DOĞRULANAMADI';
  renderList('findings',data.findings,item=>`${String(item.severity||'').toUpperCase()} · ${item.title||item.code}: ${item.evidence||''}`,'Yüksek güvenli tehlikeli instruction sinyali bulunmadı.');
  renderList('programs',data.program_ids,null,'Çağrılan program kimliği loglardan çıkarılamadı.');
  $('warning').textContent=data.warning||'Read-only shadow mode.';
 }catch(error){
  result.hidden=true;empty.hidden=false;empty.innerHTML=`<h2>DEGRADED DEPENDENCY — simülasyon sonucu yok</h2><p>${String(error.message||'Solana RPC veya kanıt servisine erişilemedi.')}</p><p>0 compute unit veya 0 program sonucu üretilmedi; bu işlem güvenli kabul edilmemeli.</p>`;
 }finally{submit.disabled=false;submit.textContent='İşlemi simüle et'}
});
})();
