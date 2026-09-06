(()=>{
'use strict';
if(window.__koscheiHomeUniverseV2)return;
window.__koscheiHomeUniverseV2=true;
const root=document.querySelector('.home-universe');
if(!root)return;

/* Universe v2.1 visual correction: the chain planets orbit the main world instead of clustering above it. */
const layoutFix=document.createElement('style');
layoutFix.textContent=`
.chain-node{overflow:hidden;isolation:isolate;transition:border-color .3s ease,box-shadow .3s ease,filter .3s ease}
.chain-node:before{content:"";position:absolute;inset:0;border-radius:inherit;z-index:-1;opacity:.9}
.n-sol:before{background:radial-gradient(circle at 34% 25%,#62ffd3 0 5%,#9945ff 24%,#14f195 47%,#07131d 76%)}
.n-eth:before{background:radial-gradient(circle at 34% 25%,#dce7ff 0 4%,#627eea 27%,#263b85 52%,#07101f 78%)}
.n-tron:before{background:radial-gradient(circle at 34% 25%,#ffb0b6 0 4%,#ff2d3d 27%,#7e0d18 53%,#17070b 79%)}
.n-base:before{background:radial-gradient(circle at 34% 25%,#b8d3ff 0 4%,#0052ff 28%,#07327f 54%,#06101f 79%)}
.n-bnb:before{background:radial-gradient(circle at 34% 25%,#fff0a8 0 4%,#f3ba2f 28%,#815f00 54%,#171205 79%)}
.n-arb:before{background:radial-gradient(circle at 34% 25%,#b5e7ff 0 4%,#28a0f0 26%,#174f9b 53%,#07111c 79%)}
.n-poly:before{background:radial-gradient(circle at 34% 25%,#ead2ff 0 4%,#8247e5 27%,#432185 54%,#11091e 79%)}
.n-avax:before{background:radial-gradient(circle at 34% 25%,#ffd0d0 0 4%,#e84142 27%,#7e1718 54%,#170909 79%)}
.n-op:before{background:radial-gradient(circle at 34% 25%,#ffd0d4 0 4%,#ff0420 27%,#840012 54%,#17060a 79%)}
.n-more:before{background:radial-gradient(circle at 34% 25%,#c8f6ff 0 4%,#38bdf8 27%,#155e75 54%,#07131b 79%)}
.chain-node b,.chain-node small{position:relative;z-index:1;text-shadow:0 1px 8px #000,0 0 12px #000}.chain-node small{color:#d1dce5}.chain-node.live small{color:#dffef7}
.n-sol{border-color:rgba(20,241,149,.58);box-shadow:0 0 35px rgba(153,69,255,.28),0 0 64px rgba(20,241,149,.16)}
.n-eth{border-color:rgba(98,126,234,.58);box-shadow:0 0 30px rgba(98,126,234,.22)}
.n-tron{border-color:rgba(255,45,61,.58);box-shadow:0 0 30px rgba(255,45,61,.22)}
.n-base{border-color:rgba(0,82,255,.62);box-shadow:0 0 30px rgba(0,82,255,.24)}
.n-bnb{border-color:rgba(243,186,47,.62);box-shadow:0 0 30px rgba(243,186,47,.22)}
.n-arb{border-color:rgba(40,160,240,.58);box-shadow:0 0 30px rgba(40,160,240,.22)}
.n-poly{border-color:rgba(130,71,229,.6);box-shadow:0 0 30px rgba(130,71,229,.23)}
.n-avax{border-color:rgba(232,65,66,.6);box-shadow:0 0 30px rgba(232,65,66,.22)}
.n-op{border-color:rgba(255,4,32,.6);box-shadow:0 0 30px rgba(255,4,32,.22)}
.n-more{border-color:rgba(56,189,248,.48);box-shadow:0 0 26px rgba(56,189,248,.18)}

@media(min-width:901px){
  .orbit-system{width:min(880px,96%);aspect-ratio:1.28;min-height:620px;margin-top:2px}
  .core-sphere{width:330px;height:330px;top:54%;background:radial-gradient(circle at 36% 28%,rgba(176,226,255,.28) 0 3%,rgba(73,142,197,.24) 8%,rgba(12,35,55,.98) 38%,#030a13 70%);box-shadow:0 0 90px rgba(82,175,235,.27),0 0 0 35px rgba(62,145,204,.03),inset 0 0 75px rgba(84,164,214,.12)}
  .orbit-system:before{width:82%;height:60%;top:54%}.orbit-system:after{width:100%;height:78%;top:54%}
  .n-sol{left:44%;top:0}.n-eth{left:13%;top:17%}.n-tron{right:12%;top:18%}.n-base{left:1%;top:44%}.n-bnb{right:0;top:44%}.n-arb{left:8%;bottom:9%}.n-poly{left:27%;bottom:-1%}.n-avax{left:45%;bottom:-7%}.n-op{right:19%;bottom:-1%}.n-more{right:5%;bottom:12%}
}

@media(max-width:900px){
  .home-universe:after{display:none}
  .universe-core{min-height:980px;padding-bottom:150px}
  .orbit-system{width:min(94vw,620px);height:min(94vw,620px);min-height:0;aspect-ratio:1;margin:28px auto 0}
  .orbit-system:before{width:82%;height:82%;top:50%;border-color:rgba(127,184,220,.14)}
  .orbit-system:after{width:98%;height:98%;top:50%;border-color:rgba(127,184,220,.08)}
  .core-sphere{top:50%;width:min(48vw,290px);height:min(48vw,290px);background:radial-gradient(circle at 34% 27%,rgba(186,231,255,.28) 0 4%,rgba(65,132,187,.22) 10%,rgba(11,31,49,.98) 39%,#030a13 72%);box-shadow:0 0 80px rgba(81,171,229,.28),0 0 0 22px rgba(69,157,218,.035),inset 0 0 65px rgba(84,164,214,.13)}
  .chain-node{width:74px;height:74px;transform:none!important}
  .chain-node.live{width:84px;height:84px}
  .chain-node b{font-size:9px}.chain-node small{font-size:6px}
  .n-sol{left:50%;top:-4%;transform:translateX(-50%)!important}
  .n-eth{left:4%;top:14%}.n-tron{right:4%;top:14%}
  .n-base{left:-3%;top:43%}.n-bnb{right:-3%;top:43%}
  .n-arb{left:5%;bottom:13%}.n-more{display:grid;right:5%;bottom:13%;width:68px;height:68px}
  .n-poly{left:24%;bottom:-3%}.n-op{right:24%;bottom:-3%}.n-avax{left:50%;bottom:-10%;transform:translateX(-50%)!important}
}

@media(max-width:640px){
  .universe-core{min-height:900px;padding-bottom:150px}
  .universe-title{margin-top:20px}
  .orbit-system{width:92vw;height:92vw;max-width:430px;max-height:430px;margin-top:34px;overflow:visible}
  .core-sphere{width:52vw;height:52vw;max-width:245px;max-height:245px;min-width:205px;min-height:205px}
  .core-sphere b{font-size:46px}.core-sphere span{font-size:14px}.core-sphere small{font-size:7px}
  .chain-node{width:66px;height:66px}.chain-node.live{width:76px;height:76px}
  .n-sol{top:-8%}.n-eth{left:1%;top:11%}.n-tron{right:1%;top:11%}.n-base{left:-5%;top:41%}.n-bnb{right:-5%;top:41%}.n-arb{left:2%;bottom:11%}.n-more{right:2%;bottom:11%;width:62px;height:62px}.n-poly{left:22%;bottom:-5%}.n-op{right:22%;bottom:-5%}.n-avax{bottom:-13%}
}
`;
document.head.appendChild(layoutFix);

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