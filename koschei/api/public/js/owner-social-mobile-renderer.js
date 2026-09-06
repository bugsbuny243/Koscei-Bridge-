(()=>{
'use strict';
if(window.__koscheiOwnerStudioRendererInstalled)return;
window.__koscheiOwnerStudioRendererInstalled=true;

const clamp=(value,min,max)=>Math.max(min,Math.min(max,Number(value)||0));

function isMobileRuntime(){
  const ua=String(navigator.userAgent||'');
  return /Android|iPhone|iPad|iPod|Mobile/i.test(ua)||(navigator.maxTouchPoints>1&&Math.min(window.innerWidth||9999,window.innerHeight||9999)<900);
}
function profile(){
  const mobile=isMobileRuntime(),memory=Number(navigator.deviceMemory||0),lowMemory=mobile&&memory>0&&memory<=4;
  if(lowMemory)return{mobile:true,width:540,height:960,fps:10,bitrate:1800000,tick:140};
  if(mobile)return{mobile:true,width:720,height:1280,fps:12,bitrate:2800000,tick:110};
  return{mobile:false,width:1080,height:1920,fps:24,bitrate:6000000,tick:80};
}
function preferredVideoType(withAudio=false){
  const candidates=withAudio?[
    'video/mp4;codecs=avc1.42E01E,mp4a.40.2',
    'video/webm;codecs=vp8,opus',
    'video/webm;codecs=vp9,opus',
    'video/webm'
  ]:[
    'video/mp4;codecs=avc1.42E01E',
    'video/webm;codecs=vp8',
    'video/webm;codecs=vp9',
    'video/webm'
  ];
  return candidates.find(type=>typeof MediaRecorder!=='undefined'&&MediaRecorder.isTypeSupported?.(type))||'';
}
function waitAudio(audio){
  return new Promise((resolve,reject)=>{
    if(Number.isFinite(audio.duration)&&audio.duration>0)return resolve();
    const done=()=>{cleanup();resolve();};
    const bad=()=>{cleanup();reject(new Error('Ses dosyası açılamadı.'));};
    const cleanup=()=>{audio.removeEventListener('loadedmetadata',done);audio.removeEventListener('error',bad);};
    audio.addEventListener('loadedmetadata',done,{once:true});
    audio.addEventListener('error',bad,{once:true});
    audio.load();
  });
}
async function recordSequence({duration=12000,onProgress=()=>{},sceneCount=5,drawScene,audioBlob=null}={}){
  if(typeof MediaRecorder==='undefined')throw new Error('Video recording is not supported in this browser.');
  if(typeof HTMLCanvasElement==='undefined'||typeof HTMLCanvasElement.prototype.captureStream!=='function')throw new Error('Canvas video capture is not supported in this browser.');
  if(typeof drawScene!=='function')throw new Error('Studio renderer is unavailable.');

  const p=profile(),canvas=document.createElement('canvas');
  canvas.width=p.width;canvas.height=p.height;
  const ctx=canvas.getContext('2d',{alpha:false});
  if(!ctx)throw new Error('Canvas unavailable');

  let audio=null,audioURL='',audioContext=null,stream=null,timer=0,stopTimer=0,recorder=null,lastScene=-1;
  let settled=false;
  const cleanup=async()=>{
    clearInterval(timer);clearTimeout(stopTimer);
    if(stream)stream.getTracks().forEach(track=>{try{track.stop();}catch{}});
    if(audio){try{audio.pause();}catch{}}
    if(audioURL)URL.revokeObjectURL(audioURL);
    if(audioContext)await audioContext.close().catch(()=>{});
  };

  try{
    if(audioBlob){
      audioURL=URL.createObjectURL(audioBlob);
      audio=new Audio(audioURL);audio.preload='auto';
      await waitAudio(audio);
      const audioDuration=Number.isFinite(audio.duration)&&audio.duration>0?Math.ceil(audio.duration*1000+400):0;
      duration=clamp(audioDuration||duration,6000,60000);
    }else{
      duration=clamp(duration,6000,20000);
    }

    stream=canvas.captureStream(p.fps);
    if(audioBlob){
      const AudioCtx=window.AudioContext||window.webkitAudioContext;
      if(!AudioCtx)throw new Error('Audio mixing is not supported in this browser.');
      audioContext=new AudioCtx();
      const source=audioContext.createMediaElementSource(audio),destination=audioContext.createMediaStreamDestination();
      source.connect(destination);
      destination.stream.getAudioTracks().forEach(track=>stream.addTrack(track));
    }

    const type=preferredVideoType(Boolean(audioBlob));
    const recorderOptions=type?{mimeType:type,videoBitsPerSecond:p.bitrate}:{videoBitsPerSecond:p.bitrate};
    if(audioBlob)recorderOptions.audioBitsPerSecond=p.mobile?128000:160000;
    recorder=new MediaRecorder(stream,recorderOptions);
    const chunks=[];
    recorder.ondataavailable=event=>{if(event.data?.size)chunks.push(event.data);};
    const stopped=new Promise((resolve,reject)=>{
      recorder.onstop=()=>{settled=true;resolve(new Blob(chunks,{type:recorder.mimeType||type||'video/webm'}));};
      recorder.onerror=event=>{settled=true;reject(event.error||new Error('Video recorder failed'));};
    });

    const paint=(scene,progress)=>{
      const source=drawScene(scene,progress);
      if(!source)throw new Error('Studio frame renderer returned no canvas.');
      ctx.clearRect(0,0,canvas.width,canvas.height);
      ctx.drawImage(source,0,0,canvas.width,canvas.height);
      if(source!==canvas){try{source.width=1;source.height=1;}catch{}}
    };

    paint(0,0);
    recorder.start(500);
    if(audioBlob){await audioContext.resume();audio.currentTime=0;await audio.play();}
    const started=performance.now();
    const tick=()=>{
      const progress=Math.min(1,(performance.now()-started)/duration);
      const scene=Math.min(Math.max(0,sceneCount-1),Math.floor(progress*Math.max(1,sceneCount)));
      if(scene!==lastScene){paint(scene,progress);lastScene=scene;}
      onProgress(progress);
    };
    tick();
    timer=setInterval(tick,p.tick);
    stopTimer=setTimeout(()=>{if(recorder&&recorder.state!=='inactive')recorder.stop();},duration+80);
    const blob=await stopped;
    onProgress(1);
    return blob;
  }finally{
    if(recorder&&!settled&&recorder.state!=='inactive'){try{recorder.stop();}catch{}}
    await cleanup();
  }
}

async function recordARVIS(input,options={}){
  const api=window.KoscheiARVISPremium;
  if(!api?.drawCardCanvas)throw new Error('ARVIS media renderer is unavailable.');
  return recordSequence({
    duration:Number(options.duration)||12000,
    onProgress:options.onProgress||(()=>{}),
    audioBlob:options.audioBlob||null,
    sceneCount:5,
    drawScene:(scene,progress)=>api.drawCardCanvas(input,'tiktok',scene,progress)
  });
}
async function recordLab(input,options={}){
  const lab=window.OwnerWeb3Lab;
  if(!lab?.drawMediaCanvas)throw new Error('Owner Web3 Lab renderer is unavailable.');
  return recordSequence({
    duration:Number(options.duration)||12000,
    onProgress:options.onProgress||(()=>{}),
    sceneCount:1,
    drawScene:()=>lab.drawMediaCanvas(input,'tiktok',1)
  });
}
function patchARVIS(){
  const api=window.KoscheiARVISPremium;
  if(!api?.drawCardCanvas||api.recordVerticalVideo?.__koscheiOwnerMobileSafe)return Boolean(api?.recordVerticalVideo?.__koscheiOwnerMobileSafe);
  const safe=async(input,options={})=>recordARVIS(input,options);
  safe.__koscheiOwnerMobileSafe=true;
  api.recordVerticalVideo=safe;
  return true;
}
function patchLab(){
  const lab=window.OwnerWeb3Lab;
  if(!lab?.drawMediaCanvas||lab.recordVideo?.__koscheiOwnerMobileSafe)return Boolean(lab?.recordVideo?.__koscheiOwnerMobileSafe);
  const safe=async(input,options={})=>recordLab(input,options);
  safe.__koscheiOwnerMobileSafe=true;
  lab.recordVideo=safe;
  return true;
}
function patch(){return{arvis:patchARVIS(),lab:patchLab()};}

window.KoscheiOwnerStudioRenderer={profile,recordSequence,recordARVIS,recordLab,patch};
patch();
const timer=setInterval(()=>{const result=patch();if(result.arvis&&result.lab)clearInterval(timer);},120);
setTimeout(()=>clearInterval(timer),20000);
})();