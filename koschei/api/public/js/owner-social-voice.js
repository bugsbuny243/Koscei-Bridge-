(()=>{
'use strict';
if(window.__koscheiOwnerSocialVoiceInstalled)return;
window.__koscheiOwnerSocialVoiceInstalled=true;

const state={audioBlob:null,audioURL:'',sourceText:'',busy:false,patched:false};
const $=id=>document.getElementById(id);

function clearAudio(){
  if(state.audioURL)URL.revokeObjectURL(state.audioURL);
  state.audioURL='';state.audioBlob=null;state.sourceText='';
}
function fromBase64(value,type='audio/mpeg'){
  const raw=atob(String(value||''));
  const bytes=new Uint8Array(raw.length);
  for(let i=0;i<raw.length;i++)bytes[i]=raw.charCodeAt(i);
  return new Blob([bytes],{type:type||'audio/mpeg'});
}
function download(blob,name){
  if(!blob)return;
  if(window.KoscheiARVISPremium?.downloadBlob)return window.KoscheiARVISPremium.downloadBlob(blob,name);
  const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),2500);
}
function voiceText(){return String($('socialVoiceover')?.value||'').trim();}

async function generateVoice(){
  const text=voiceText();
  if(!text||state.busy)return;
  state.busy=true;renderControls();
  try{
    const response=await window.KoscheiOwner.api('/api/owner/chat?mode=tts&language=en',{method:'POST',body:JSON.stringify({message:text})});
    if(!response?.audio_base64)throw new Error('Together TTS ses verisi döndürmedi.');
    clearAudio();
    state.audioBlob=fromBase64(response.audio_base64,response.content_type||'audio/mpeg');
    state.audioURL=URL.createObjectURL(state.audioBlob);
    state.sourceText=text;
  }catch(error){
    alert(`AI seslendirme üretilemedi: ${error.message||'Bilinmeyen hata'}`);
  }finally{
    state.busy=false;renderControls();
  }
}

function renderControls(){
  const textarea=$('socialVoiceover');if(!textarea)return;
  const current=voiceText();
  if(state.audioBlob&&state.sourceText!==current)clearAudio();
  let root=$('socialVoiceControls');
  if(!root){
    root=document.createElement('div');root.id='socialVoiceControls';root.className='social-action-stack';
    textarea.parentElement?.appendChild(root);
  }
  root.innerHTML=`<button class="arvis-action primary" id="socialGenerateVoice" type="button" ${current&&!state.busy?'':'disabled'}>${state.busy?'Together AI ses üretiyor…':state.audioBlob?'Sesi yeniden üret':'AI seslendirme oluştur'}</button>${state.audioURL?`<audio id="socialVoicePreview" controls preload="metadata" src="${state.audioURL}" style="width:100%"></audio><button class="arvis-action" id="socialVoiceDownload" type="button">MP3 seslendirmeyi indir</button><span class="arvis-chip good">Ses hazır · Video oluşturunca otomatik eklenir</span>`:'<span class="arvis-chip info">Together TTS · Owner only · API key server-side</span>'}`;
  $('socialGenerateVoice')?.addEventListener('click',generateVoice);
  $('socialVoiceDownload')?.addEventListener('click',()=>download(state.audioBlob,'koschei-arvis-voiceover.mp3'));
}

async function recordWithAudio(input,options,audioBlob){
  const renderer=window.KoscheiOwnerStudioRenderer;
  if(!renderer?.recordARVIS)throw new Error('Mobil güvenli video renderer henüz hazır değil. Sayfayı yenileyip tekrar deneyin.');
  return renderer.recordARVIS(input,{...options,audioBlob});
}

function patchRecorder(){
  const api=window.KoscheiARVISPremium;if(!api||state.patched||typeof api.recordVerticalVideo!=='function')return false;
  const original=api.recordVerticalVideo.bind(api);
  api.recordVerticalVideo=async(input,options={})=>state.audioBlob?recordWithAudio(input,options,state.audioBlob):original(input,options);
  api.recordVerticalVideo.__koscheiOwnerVoiceWrapper=true;
  state.patched=true;return true;
}
function sync(){patchRecorder();renderControls();}
const observer=new MutationObserver(sync);observer.observe(document.documentElement,{subtree:true,childList:true});
const timer=setInterval(()=>{sync();if(state.patched&&$('socialVoiceover'))clearInterval(timer);},120);setTimeout(()=>clearInterval(timer),20000);
window.addEventListener('beforeunload',clearAudio);
window.KoscheiOwnerSocialVoice={get audioBlob(){return state.audioBlob;},clear:clearAudio,generate:generateVoice};
})();