(()=>{
'use strict';
if(window.__koscheiHomeUniverseV2)return;
window.__koscheiHomeUniverseV2=true;
const root=document.querySelector('.home-universe');
if(!root)return;
const reduce=window.matchMedia('(prefers-reduced-motion: reduce)').matches;
root.classList.add('cinematic-ready');
const canvas=document.createElement('canvas');
canvas.className='universe-starfield';
canvas.setAttribute('aria-hidden','true');
root.prepend(canvas);
const ctx=canvas.getContext('2d',{alpha:true});
let w=0,h=0,dpr=1,stars=[],raf=0,last=0;
function resize(){dpr=Math.min(window.devicePixelRatio||1,1.75);w=root.clientWidth;h=Math.max(root.clientHeight,window.innerHeight);canvas.width=Math.floor(w*dpr);canvas.height=Math.floor(h*dpr);canvas.style.width=w+'px';canvas.style.height=h+'px';ctx.setTransform(dpr,0,0,dpr,0,0);const count=Math.max(90,Math.min(320,Math.round((w*h)/6500)));stars=Array.from({length:count},()=>({x:Math.random()*w,y:Math.random()*h,z:.25+Math.random()*.9,r:.3+Math.random()*1.1,v:.015+Math.random()*.05}));}
function draw(t){if(reduce){drawStatic();return;}const dt=Math.min(40,t-last||16);last=t;ctx.clearRect(0,0,w,h);const cx=w*.5,cy=h*.46;for(const s of stars){s.y+=s.v*dt*s.z;if(s.y>h+8){s.y=-8;s.x=Math.random()*w;}const dx=s.x-cx,dy=s.y-cy;const glow=Math.max(0,1-Math.hypot(dx,dy)/Math.max(w,h));ctx.globalAlpha=.25+s.z*.55+glow*.16;ctx.beginPath();ctx.arc(s.x,s.y,s.r*s.z,0,Math.PI*2);ctx.fillStyle='#dff5ff';ctx.fill();}ctx.globalAlpha=1;raf=requestAnimationFrame(draw);}
function drawStatic(){ctx.clearRect(0,0,w,h);for(const s of stars){ctx.globalAlpha=.35+s.z*.45;ctx.beginPath();ctx.arc(s.x,s.y,s.r*s.z,0,Math.PI*2);ctx.fillStyle='#dff5ff';ctx.fill();}ctx.globalAlpha=1;}
resize();window.addEventListener('resize',resize,{passive:true});if(reduce)drawStatic();else raf=requestAnimationFrame(draw);
let mx=.5,my=.5,pending=false;
function applyParallax(){pending=false;const x=(mx-.5),y=(my-.5);root.style.setProperty('--mx',x.toFixed(3));root.style.setProperty('--my',y.toFixed(3));}
window.addEventListener('pointermove',e=>{if(reduce)return;mx=e.clientX/Math.max(1,innerWidth);my=e.clientY/Math.max(1,innerHeight);if(!pending){pending=true;requestAnimationFrame(applyParallax);}},{passive:true});
document.querySelectorAll('.chain-node').forEach((node,index)=>node.style.setProperty('--orbit-delay',`${index*-.47}s`));
const enter=document.querySelector('.home-enter');
enter?.addEventListener('pointerenter',()=>root.classList.add('portal-armed'));
enter?.addEventListener('pointerleave',()=>root.classList.remove('portal-armed'));
window.addEventListener('pagehide',()=>{if(raf)cancelAnimationFrame(raf);},{once:true});
})();