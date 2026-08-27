(()=>{
'use strict';
if(window.__ownerWeb3LabInstalled)return;
window.__ownerWeb3LabInstalled=true;

const TOOL_DEFS={
  shield:{label:'Shield Preflight',endpoint:'/api/owner/web3/shield/preflight',template:{target:'',target_mint:'',address:'',network:'solana-mainnet',wallet:'',transaction:'',encoding:'base64',expected_programs:[],context:{}}},
  guard:{label:'Transaction Guard V2',endpoint:'/api/owner/web3/transaction-guard',template:{transaction:'',encoding:'base64',network:'solana-mainnet',wallet:'',expected_programs:[],required_programs:[],blocked_programs:[],accounts:[]}},
  defense:{label:'Defense Validation',endpoint:'/api/owner/web3/defense-validation',template:{run_ref:'',scenario:{},controls:[],cases:[]}},
  safe:{label:'Safe Execution Assurance',endpoint:'/api/owner/web3/execution-assurance/safe/verify',template:{execution_proof:{},proof_attestation:{},transaction:{chain_id:0,safe:'',to:'',value:'',data:'0x',operation:0,safe_tx_gas:'',base_gas:'',gas_price:'',gas_token:'',refund_receiver:'',nonce:''},presented_safe_tx_hash:''}}
};
const state={tool:'guard',latestResult:null,latestType:'',latestSocialPayload:null,busy:false};
const $=id=>document.getElementById(id);
const arr=value=>Array.isArray(value)?value:[];
const obj=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
const clean=value=>String(value??'').trim();
const esc=value=>String(value??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const owner=()=>window.KoscheiOwner;

function ensurePage(){
  let page=$('page-owner-web3-lab');
  if(page)return page;
  page=document.createElement('section');
  page.className='page';
  page.id='page-owner-web3-lab';
  page.innerHTML='<div id="ownerWeb3LabContent"></div>';
  document.querySelector('.owner-app>.main')?.appendChild(page);
  return page;
}
function navButton(mobile=false){
  const button=document.createElement('button');
  button.type='button';
  button.dataset.ownerWeb3LabNav='1';
  button.className=mobile?'':'nav-item';
  button.innerHTML=mobile?'<span>🛡</span>Web3 Lab':'<span class="nav-icon">🛡</span><span>Web3 Lab</span>';
  button.onclick=activate;
  return button;
}
function ensureNav(){
  const desktop=$('desktopNav'),mobile=$('mobileNav');
  if(desktop&&!desktop.querySelector('[data-owner-web3-lab-nav]'))desktop.appendChild(navButton());
  if(mobile&&!mobile.querySelector('[data-owner-web3-lab-nav]'))mobile.appendChild(navButton(true));
}
function activate(){
  const page=ensurePage();
  document.querySelectorAll('.page').forEach(section=>section.classList.toggle('active',section===page));
  document.querySelectorAll('[data-nav],[data-publishing-nav],[data-social-studio-nav],[data-owner-web3-lab-nav]').forEach(button=>button.classList.toggle('active',button.dataset.ownerWeb3LabNav==='1'));
  if($('pageTitle'))$('pageTitle').textContent='Owner Web3 Validation Lab';
  if($('pageEyebrow'))$('pageEyebrow').textContent='ARVIS · PREFLIGHT · DEFENSE VALIDATION · EXECUTION ASSURANCE';
  render();
}
function templateFor(type){return JSON.stringify(TOOL_DEFS[type]?.template||{},null,2);}
function currentEditorValue(){return $('ownerWeb3Request')?.value||'';}
function selectTool(type){
  if(!TOOL_DEFS[type])return;
  state.tool=type;
  render();
}
function importantFields(result){
  const report=obj(result?.report),final=obj(result?.final_verdict),program=obj(result?.program_policy),intent=obj(result?.intent_policy);
  const rows=[];
  const push=(label,value)=>{if(value!==undefined&&value!==null&&clean(value)!=='')rows.push([label,value]);};
  push('Product',result?.product);
  push('Decision',result?.decision||result?.action||result?.policy_outcome||report.decision||report.status);
  push('Status',result?.status||result?.report_status||report.status);
  push('Network',result?.network||report.network||report.chain);
  push('Request',result?.request_id||result?.run_ref||report.run_ref);
  push('Evidence model',result?.evidence_model);
  push('Scenario hash',result?.scenario_contract_hash);
  push('Safe tx hash',result?.computed_safe_tx_hash);
  push('Attestation verified',result?.attestation_verified);
  push('Verified executions',result?.verified_executions);
  push('Verified observations',result?.verified_observations);
  push('Programs complete',program.complete);
  push('Intent complete',intent.complete);
  push('Signed',result?.signed||final.signed);
  return rows;
}
function evidenceLines(result){
  const report=obj(result?.report),attack=obj(result?.attack_path||report.attack_path),program=obj(result?.program_policy),intent=obj(result?.intent_policy);
  const out=[];
  arr(result?.findings).forEach(item=>out.push(typeof item==='string'?item:[item.code,item.title,item.evidence].filter(Boolean).join(' · ')));
  arr(result?.reason_codes).forEach(item=>out.push(clean(item)));
  arr(program.blocked_invoked).forEach(item=>out.push(`Blocked program invoked: ${item}`));
  arr(program.unexpected).forEach(item=>out.push(`Unexpected program: ${item}`));
  arr(program.missing_required).forEach(item=>out.push(`Required program missing: ${item}`));
  arr(intent.accounts).forEach(item=>out.push([item.address,item.role,item.policy_status,item.evidence_status,item.delta_raw?`delta ${item.delta_raw}`:''].filter(Boolean).join(' · ')));
  arr(attack.paths).forEach(path=>out.push([path.label||path.id,path.status,path.evidence_status,path.summary].filter(Boolean).join(' · ')));
  return out.filter(Boolean).slice(0,40);
}
function sanitizeSocialResult(type,result){
  const report=obj(result?.report),attack=obj(result?.attack_path||report.attack_path),program=obj(result?.program_policy),intent=obj(result?.intent_policy),final=obj(result?.final_verdict);
  return {
    source_type:type,
    source_label:TOOL_DEFS[type]?.label||type,
    product:clean(result?.product)||TOOL_DEFS[type]?.label||'Koschei Web3',
    target:clean(result?.target||result?.wallet||result?.computed_safe_tx_hash||result?.scenario_contract_hash||result?.request_id||report.target||report.run_ref),
    network:clean(result?.network||report.network||report.chain),
    decision:clean(result?.decision||result?.action||result?.policy_outcome||report.decision||report.status),
    status:clean(result?.status||result?.report_status||report.status),
    summary:clean(result?.summary||result?.verdict||final.verdict||report.summary),
    signed:result?.signed===true||final.signed===true,
    evidence_model:clean(result?.evidence_model),
    request_id:clean(result?.request_id),
    scenario_contract_hash:clean(result?.scenario_contract_hash),
    computed_safe_tx_hash:clean(result?.computed_safe_tx_hash),
    presented_safe_tx_hash:clean(result?.presented_safe_tx_hash),
    attestation_verified:result?.attestation_verified===true,
    verified_executions:Number(result?.verified_executions||0),
    verified_observations:Number(result?.verified_observations||0),
    program_policy:{complete:program.complete===true,invoked:arr(program.invoked).slice(0,32),unexpected:arr(program.unexpected).slice(0,32),missing_required:arr(program.missing_required).slice(0,32),blocked_invoked:arr(program.blocked_invoked).slice(0,32)},
    intent_policy:{requested:intent.requested===true,complete:intent.complete===true,accounts:arr(intent.accounts).slice(0,24).map(item=>({address:clean(item.address),mint:clean(item.mint),role:clean(item.role),delta_raw:clean(item.delta_raw),spent_raw:clean(item.spent_raw),received_raw:clean(item.received_raw),policy_status:clean(item.policy_status),evidence_status:clean(item.evidence_status)}))},
    attack_path:{status:clean(attack.status),primary_exposure:clean(attack.primary_exposure),paths:arr(attack.paths).slice(0,12).map(path=>({id:clean(path.id),label:clean(path.label),status:clean(path.status),evidence_status:clean(path.evidence_status),summary:clean(path.summary),required_evidence:arr(path.required_evidence).slice(0,8),limitations:arr(path.limitations).slice(0,8)})),evidence_references:obj(attack.evidence_references)},
    evidence:evidenceLines(result),
    limitations:arr(result?.limitations||report.limitations).map(clean).filter(Boolean).slice(0,20)
  };
}
function socialPayload(type,result){
  const safe=sanitizeSocialResult(type,result);
  const label=safe.product||safe.source_label;
  const decision=safe.decision||safe.status||'evidence review';
  return {
    target:safe.target||safe.request_id||safe.source_type,
    symbol:safe.source_type==='arvis'?'ARVIS':'KOSCHEI',
    token_symbol:safe.source_type==='arvis'?'ARVIS':'KOSCHEI',
    network:safe.network,
    verdict:safe.summary||decision,
    signed:safe.signed,
    evidence:safe.evidence,
    owner_web3_evidence:safe,
    owner_web3_product:label,
    owner_web3_decision:decision
  };
}
function resultHTML(){
  if(!state.latestResult)return '<div class="arvis-empty">Henüz Web3 Lab sonucu yok. Gerçek bir request çalıştırdığında response burada kanıtlarıyla görünür.</div>';
  const rows=importantFields(state.latestResult);
  const evidence=evidenceLines(state.latestResult);
  const limitations=arr(state.latestResult.limitations||obj(state.latestResult.report).limitations);
  return `<section class="panel full"><div class="arvis-social-top"><div><span class="arvis-kicker">LATEST VERIFIED RESPONSE</span><h3>${esc(TOOL_DEFS[state.latestType]?.label||state.latestType)}</h3></div><button class="arvis-action primary" id="ownerWeb3Studio" type="button">Sosyal Stüdyoya Gönder</button></div><div class="statgrid">${rows.map(([label,value])=>`<article class="stat"><label>${esc(label)}</label><strong>${esc(String(value))}</strong></article>`).join('')}</div>${evidence.length?`<div class="evidence-list">${evidence.map(line=>`<div class="evidence-row verified"><b>EVIDENCE</b><span>${esc(line)}</span></div>`).join('')}</div>`:'<div class="arvis-empty">Response içinde normalize edilmiş evidence satırı yok; ham response aşağıda korunuyor.</div>'}${limitations.length?`<details><summary>Limitations</summary><ul>${limitations.map(item=>`<li>${esc(item)}</li>`).join('')}</ul></details>`:''}<details><summary>Owner-only raw response</summary><pre>${esc(JSON.stringify(state.latestResult,null,2))}</pre></details></section>`;
}
function render(){
  ensureNav();
  const root=$('ownerWeb3LabContent');if(!root)return;
  const def=TOOL_DEFS[state.tool];
  root.innerHTML=`<section class="arvis-social-studio"><div class="arvis-social-top"><div><span class="arvis-kicker">OWNER ONLY · WEB3 VALIDATION LAB</span><h2>Web3 çekirdeğinin çalışan güvenlik araçları tek panelde.</h2><p>ARVIS ayrı canonical investigation akışını korur. Bu laboratuvar Shield Preflight, Transaction Guard V2, Defense Validation ve Safe Execution Assurance endpoint'lerini owner session üzerinden çalıştırır. API key frontend'e taşınmaz.</p></div><div class="arvis-chip-row"><span class="arvis-chip good">OWNER SESSION</span><span class="arvis-chip info">EVIDENCE FIRST</span><span class="arvis-chip">NO SIGNING</span></div></div><div class="arvis-social-tabs">${Object.entries(TOOL_DEFS).map(([id,item])=>`<button class="arvis-social-tab ${state.tool===id?'active':''}" data-owner-web3-tool="${id}" type="button">${esc(item.label)}</button>`).join('')}</div><div class="social-pack-grid"><div class="social-pack-panel"><h3>${esc(def.label)}</h3><p class="muted">Aşağıdaki JSON bir TEMPLATE'tir; boş alanlar gerçek kanıt/request ile doldurulmalıdır. Koschei burada örnek transaction veya proof uydurmaz.</p><textarea class="arvis-caption mono" id="ownerWeb3Request" style="min-height:420px">${esc(templateFor(state.tool))}</textarea><div class="social-action-stack"><button class="arvis-action primary" id="ownerWeb3Run" type="button" ${state.busy?'disabled':''}>${state.busy?'Doğrulanıyor…':'Gerçek Request Çalıştır'}</button><button class="arvis-action" id="ownerWeb3Reset" type="button">Template'i Sıfırla</button></div><p class="social-evidence-note">Başarılı response sonrası request editor buffer'ı temizlenir. Raw serialized transaction, proof veya canonical action sosyal medya state'ine kopyalanmaz.</p></div><div class="social-pack-panel"><h3>Kanıt görünümü</h3>${resultHTML()}</div></div></section>`;
  document.querySelectorAll('[data-owner-web3-tool]').forEach(button=>button.onclick=()=>selectTool(button.dataset.ownerWeb3Tool));
  $('ownerWeb3Reset')?.addEventListener('click',()=>{const editor=$('ownerWeb3Request');if(editor)editor.value=templateFor(state.tool);});
  $('ownerWeb3Run')?.addEventListener('click',runCurrent);
  $('ownerWeb3Studio')?.addEventListener('click',sendToStudio);
}
async function runCurrent(){
  if(state.busy)return;
  const def=TOOL_DEFS[state.tool],raw=currentEditorValue();
  let parsed;
  try{parsed=JSON.parse(raw);}catch{alert('Request JSON geçerli değil.');return;}
  state.busy=true;render();
  try{
    const result=await owner().api(def.endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(parsed)});
    state.latestResult=result;
    state.latestType=state.tool;
    state.latestSocialPayload=socialPayload(state.tool,result);
    window.dispatchEvent(new CustomEvent('koschei:owner-web3-result',{detail:{type:state.tool,result,socialPayload:state.latestSocialPayload}}));
    render();
    const editor=$('ownerWeb3Request');if(editor)editor.value='';
  }catch(error){alert(error.message||'Web3 validation request başarısız.');}
  finally{state.busy=false;render();}
}
function sendToStudio(){
  if(!state.latestSocialPayload)return;
  window.dispatchEvent(new CustomEvent('koschei:open-social-studio',{detail:{payload:state.latestSocialPayload,platform:'x',source:'owner-web3-lab'}}));
}
function isPayload(payload){return Boolean(obj(payload).owner_web3_evidence);}
function socialEvidence(payload){return obj(payload?.owner_web3_evidence);}
function defaultPack(payload,platform='x'){
  const evidence=socialEvidence(payload),product=clean(evidence.product||payload?.owner_web3_product||'Koschei Web3'),decision=clean(evidence.decision||evidence.status||payload?.owner_web3_decision||'EVIDENCE REVIEW').toUpperCase(),target=clean(evidence.target||payload?.target);
  const shortTarget=target.length>28?`${target.slice(0,12)}…${target.slice(-10)}`:target;
  const fact=evidence.summary||arr(evidence.evidence)[0]||'Evidence-backed validation result available.';
  const caption=`${product}: ${decision}${shortTarget?` · ${shortTarget}`:''}\n\n${fact}\n\nKoschei reports observed evidence and explicit limitations; capability is not intent.`;
  return {title:`${product} · ${decision}`,caption,description:caption,hashtags:['#Koschei','#Web3Security','#SecurityValidation'],mentions:[],voiceover:`${product} returned ${decision}. ${fact} This result is tied to the supplied evidence and its stated limitations. Koschei does not infer intent from capability.`,hook:`${product}: ${decision}`,cta:'Review the evidence and limitations before execution.'};
}
function canvasSize(format){return format==='x'?{w:1600,h:900}:{w:1080,h:1920};}
function drawMediaCanvas(payload,format='x',progress=1){
  const evidence=socialEvidence(payload),size=canvasSize(format),canvas=document.createElement('canvas');canvas.width=size.w;canvas.height=size.h;const ctx=canvas.getContext('2d');
  ctx.fillStyle='#02070d';ctx.fillRect(0,0,size.w,size.h);
  const pad=Math.round(size.w*.07),max=size.w-pad*2;
  ctx.fillStyle='#18ffb2';ctx.font=`900 ${Math.round(size.w*.032)}px system-ui`;ctx.fillText('KOSCHEI WEB3 · OWNER EVIDENCE STUDIO',pad,Math.round(size.h*.09));
  ctx.fillStyle='#f4fbff';ctx.font=`900 ${Math.round(size.w*.065)}px system-ui`;wrap(ctx,clean(evidence.product||'Koschei Web3'),pad,Math.round(size.h*.18),max,Math.round(size.w*.078));
  const decision=clean(evidence.decision||evidence.status||'EVIDENCE REVIEW').toUpperCase();ctx.fillStyle=decision.includes('BLOCK')||decision.includes('FAIL')?'#ff5577':decision.includes('ALLOW')||decision.includes('PASS')?'#18ffb2':'#ffcc66';ctx.font=`900 ${Math.round(size.w*.085)}px system-ui`;ctx.fillText(decision,pad,Math.round(size.h*.34));
  ctx.fillStyle='#98adba';ctx.font=`600 ${Math.round(size.w*.029)}px system-ui`;const target=clean(evidence.target);if(target)wrap(ctx,target,pad,Math.round(size.h*.41),max,Math.round(size.w*.042));
  ctx.fillStyle='#f4fbff';ctx.font=`700 ${Math.round(size.w*.032)}px system-ui`;const facts=arr(evidence.evidence).slice(0,format==='x'?3:6);let y=Math.round(size.h*.53);facts.forEach((fact,index)=>{ctx.fillStyle=index===0?'#f4fbff':'#c8d7df';y=wrap(ctx,`• ${fact}`,pad,y,max,Math.round(size.w*.044))+Math.round(size.h*.018);});
  ctx.fillStyle='#98adba';ctx.font=`600 ${Math.round(size.w*.024)}px system-ui`;wrap(ctx,'Evidence-backed result · Missing evidence is not a safe signal · Capability is not intent',pad,size.h-Math.round(size.h*.09),max,Math.round(size.w*.034));
  if(progress<1){ctx.fillStyle='#24eaff';ctx.fillRect(pad,size.h-Math.round(size.h*.035),Math.round(max*Math.max(0,Math.min(1,progress))),8);}
  return canvas;
}
function wrap(ctx,text,x,y,maxWidth,lineHeight){const words=String(text||'').split(/\s+/),lines=[];let line='';for(const word of words){const test=line?`${line} ${word}`:word;if(ctx.measureText(test).width>maxWidth&&line){lines.push(line);line=word;}else line=test;}if(line)lines.push(line);for(const item of lines.slice(0,8)){ctx.fillText(item,x,y);y+=lineHeight;}return y;}
async function canvasBlob(payload,format='x'){const canvas=drawMediaCanvas(payload,format,1);return new Promise((resolve,reject)=>canvas.toBlob(blob=>blob?resolve(blob):reject(new Error('Canvas export failed')),'image/png'));}
function supportedVideoType(){for(const type of ['video/mp4;codecs=avc1','video/webm;codecs=vp9','video/webm;codecs=vp8','video/webm']){if(window.MediaRecorder?.isTypeSupported?.(type))return type;}return '';}
async function recordVideo(payload,{duration=12000,onProgress=()=>{}}={}){if(!window.MediaRecorder)throw new Error('Bu tarayıcı MediaRecorder desteklemiyor.');const format='tiktok',canvas=drawMediaCanvas(payload,format,0),ctx=canvas.getContext('2d'),stream=canvas.captureStream(30),type=supportedVideoType(),recorder=new MediaRecorder(stream,type?{mimeType:type}:undefined),chunks=[];recorder.ondataavailable=e=>{if(e.data?.size)chunks.push(e.data);};const started=performance.now();const timer=setInterval(()=>{const p=Math.min(1,(performance.now()-started)/duration),frame=drawMediaCanvas(payload,format,p);ctx.clearRect(0,0,canvas.width,canvas.height);ctx.drawImage(frame,0,0);onProgress(p);},80);const done=new Promise((resolve,reject)=>{recorder.onerror=e=>reject(e.error||new Error('Video recorder failed'));recorder.onstop=()=>resolve(new Blob(chunks,{type:recorder.mimeType||'video/webm'}));});recorder.start(250);setTimeout(()=>recorder.state!=='inactive'&&recorder.stop(),duration);const blob=await done;clearInterval(timer);stream.getTracks().forEach(track=>track.stop());onProgress(1);return blob;}

window.OwnerWeb3Lab={activate,get latestResult(){return state.latestResult;},get latestType(){return state.latestType;},get latestSocialPayload(){return state.latestSocialPayload;},isPayload,socialEvidence,defaultPack,drawMediaCanvas,canvasBlob,recordVideo,sanitizeSocialResult};
window.addEventListener('koschei:owner-arvis-premium-mounted',event=>{const payload=event.detail?.payload;if(!payload)return;state.latestType='arvis';state.latestResult=payload;state.latestSocialPayload=payload;});
const boot=setInterval(()=>{ensurePage();ensureNav();if(window.KoscheiOwner){clearInterval(boot);render();}},100);setTimeout(()=>clearInterval(boot),15000);
})();