(()=>{
'use strict';
if(window.__koscheiOwnerSocialVoiceInstalled)return;
window.__koscheiOwnerSocialVoiceInstalled=true;

const state={audioBlob:null,audioURL:'',sourceText:'',busy:false,patched:false};
const $=id=>document.getElementById(id);
const clamp=(value,min,max)=>Math.max(min,Math.min(max,value));

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

function preferredVideoType(){
  const candidates=[
    'video/mp4;codecs=avc1.42E01E,mp4a.40.2',
    'video/webm;codecs=vp9,opus',
    'video/webm;codecs=vp8,opus',
    'video/webm'
  ];
  return candidates.find(type=>typeof MediaRecorder!=='undefined'&&MediaRecorder.isTypeSupported?.(type))||'';
}
function waitAudio(audio){
  return new Promise((resolve,reject)=>{
    if(Number.isFinite(audio.duration)&&audio.duration>0)return resolve();
    const done=()=>{cleanup();resolve();},bad=()=>{cleanup();reject(new Error('Ses dosyası açılamadı.'));};
    const cleanup=()=>{audio.removeEventListener('loadedmetadata',done);audio.removeEventListener('error',bad);};
    audio.addEventListener('loadedmetadata',done,{once:true});audio.addEventListener('error',bad,{once:true});audio.load();
  });
}
async function recordWithAudio(input,options,audioBlob,api){
  if(typeof MediaRecorder==='undefined')throw new Error('Video recording is not supported in this browser.');
  const audioURL=URL.createObjectURL(audioBlob),audio=new Audio(audioURL);audio.preload='auto';
  let audioContext=null;
  try{
    await waitAudio(audio);
    const audioDuration=Number.isFinite(audio.duration)&&audio.duration>0?Math.ceil(audio.duration*1000+400):0;
    const duration=clamp(audioDuration||Number(options.duration)||15000,6000,60000),fps=30;
    const canvas=document.createElement('canvas');canvas.width=1080;canvas.height=1920;
    const ctx=canvas.getContext('2d');if(!ctx)throw new Error('Canvas unavailable');
    const stream=canvas.captureStream(fps);
    const AudioCtx=window.AudioContext||window.webkitAudioContext;if(!AudioCtx)throw new Error('Audio mixing is not supported in this browser.');
    audioContext=new AudioCtx();
    const source=audioContext.createMediaElementSource(audio),destination=audioContext.createMediaStreamDestination();
    source.connect(destination);
    destination.stream.getAudioTracks().forEach(track=>stream.addTrack(track));
    const type=preferredVideoType();
    const recorder=new MediaRecorder(stream,type?{mimeType:type,videoBitsPerSecond:9000000,audioBitsPerSecond:192000}:{videoBitsPerSecond:9000000,audioBitsPerSecond:192000});
    const chunks=[];recorder.ondataavailable=event=>{if(event.data?.size)chunks.push(event.data);};
    const stopped=new Promise((resolve,reject)=>{recorder.onstop=()=>resolve(new Blob(chunks,{type:recorder.mimeType||type||'video/webm'}));recorder.onerror=event=>reject(event.error||new Error('Video recorder failed'));});
    recorder.start(250);await audioContext.resume();audio.currentTime=0;await audio.play();
    const start=performance.now();
    await new Promise(resolve=>{
      const frame=now=>{
        const elapsed=now-start,progress=Math.min(1,elapsed/duration),scene=Math.min(4,Math.floor(progress*5));
        const sourceCanvas=api.drawCardCanvas(input,'tiktok',scene,progress);
        ctx.clearRect(0,0,canvas.width,canvas.height);ctx.drawImage(sourceCanvas,0,0);
        options.onProgress?.(progress);
        if(progress<1)requestAnimationFrame(frame);else resolve();
      };
      requestAnimationFrame(frame);
    });
    audio.pause();recorder.stop();
    return await stopped;
  }finally{
    audio.pause();URL.revokeObjectURL(audioURL);if(audioContext)await audioContext.close().catch(()=>{});
  }
}

function patchRecorder(){
  const api=window.KoscheiARVISPremium;if(!api||state.patched||typeof api.recordVerticalVideo!=='function')return false;
  const original=api.recordVerticalVideo.bind(api);
  api.recordVerticalVideo=async(input,options={})=>state.audioBlob?recordWithAudio(input,options,state.audioBlob,api):original(input,options);
  state.patched=true;return true;
}
function sync(){patchRecorder();renderControls();}
const observer=new MutationObserver(sync);observer.observe(document.documentElement,{subtree:true,childList:true});
const timer=setInterval(()=>{sync();if(state.patched&&$('socialVoiceover'))clearInterval(timer);},120);setTimeout(()=>clearInterval(timer),20000);
window.addEventListener('beforeunload',clearAudio);
window.KoscheiOwnerSocialVoice={get audioBlob(){return state.audioBlob;},clear:clearAudio,generate:generateVoice};
})();
