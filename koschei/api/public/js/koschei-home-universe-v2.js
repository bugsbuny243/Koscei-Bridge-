(()=>{
'use strict';
if(window.__koscheiHomeUniverseV2)return;
window.__koscheiHomeUniverseV2=true;
const root=document.querySelector('.home-universe');
if(!root)return;
const reduce=window.matchMedia('(prefers-reduced-motion: reduce)').matches;
root.classList.add('cinematic-ready');

/* WebGL owns the animated visual field. This runtime only coordinates DOM parallax and portal state. */
let mx=.5,my=.5,pending=false;
function applyParallax(){pending=false;root.style.setProperty('--mx',(mx-.5).toFixed(3));root.style.setProperty('--my',(my-.5).toFixed(3));}
window.addEventListener('pointermove',e=>{if(reduce||window.innerWidth<900)return;mx=e.clientX/Math.max(1,innerWidth);my=e.clientY/Math.max(1,innerHeight);if(!pending){pending=true;requestAnimationFrame(applyParallax);}},{passive:true});
document.querySelectorAll('.chain-node').forEach((node,index)=>node.style.setProperty('--orbit-delay',`${index*-.47}s`));
const enter=document.querySelector('.home-enter');
enter?.addEventListener('pointerenter',()=>root.classList.add('portal-armed'));
enter?.addEventListener('pointerleave',()=>root.classList.remove('portal-armed'));
})();