(()=>{
'use strict';
if(window.__koscheiHomeUniverseV2)return;
window.__koscheiHomeUniverseV2=true;
const root=document.querySelector('.home-universe');
if(!root)return;

const reduce=window.matchMedia('(prefers-reduced-motion: reduce)').matches;
root.classList.add('cinematic-ready');

/* Deep-space starfield: stars do not fall. They remain anchored and only twinkle subtly. */
const canvas=document.createElement('canvas');
canvas.className='universe-starfield';
canvas.setAttribute('aria-hidden','true');
root.prepend(canvas);
const ctx=canvas.getContext('2d',{alpha:true});
let w=0,h=0,dpr=1,stars=[],raf=0;

function seedStars(){
  const count=Math.max(70,Math.min(220,Math.round((w*h)/10500)));
  stars=Array.from({length:count},()=>({
    x:Math.random()*w,
    y:Math.random()*h,
    r:.25+Math.random()*.85,
    a:.16+Math.random()*.42,
    phase:Math.random()*Math.PI*2,
    speed:.00018+Math.random()*.00042
  }));
}

function resize(){
  dpr=Math.min(window.devicePixelRatio||1,1.75);
  w=root.clientWidth;
  h=Math.max(root.clientHeight,window.innerHeight);
  canvas.width=Math.floor(w*dpr);
  canvas.height=Math.floor(h*dpr);
  canvas.style.width=w+'px';
  canvas.style.height=h+'px';
  ctx.setTransform(dpr,0,0,dpr,0,0);
  seedStars();
}

function paint(t=0){
  ctx.clearRect(0,0,w,h);
  for(const s of stars){
    const twinkle=reduce?0:Math.sin(t*s.speed+s.phase)*.09;
    ctx.globalAlpha=Math.max(.08,s.a+twinkle);
    ctx.beginPath();
    ctx.arc(s.x,s.y,s.r,0,Math.PI*2);
    ctx.fillStyle='#bfe8ff';
    ctx.fill();
  }
  ctx.globalAlpha=1;
  if(!reduce)raf=requestAnimationFrame(paint);
}

resize();
window.addEventListener('resize',resize,{passive:true});
paint();

/* Desktop-only cinematic parallax; no vertical particle drift. */
let mx=.5,my=.5,pending=false;
function applyParallax(){
  pending=false;
  root.style.setProperty('--mx',(mx-.5).toFixed(3));
  root.style.setProperty('--my',(my-.5).toFixed(3));
}
window.addEventListener('pointermove',e=>{
  if(reduce||window.innerWidth<900)return;
  mx=e.clientX/Math.max(1,innerWidth);
  my=e.clientY/Math.max(1,innerHeight);
  if(!pending){pending=true;requestAnimationFrame(applyParallax);}
},{passive:true});

document.querySelectorAll('.chain-node').forEach((node,index)=>node.style.setProperty('--orbit-delay',`${index*-.47}s`));
const enter=document.querySelector('.home-enter');
enter?.addEventListener('pointerenter',()=>root.classList.add('portal-armed'));
enter?.addEventListener('pointerleave',()=>root.classList.remove('portal-armed'));
window.addEventListener('pagehide',()=>{if(raf)cancelAnimationFrame(raf);},{once:true});
})();