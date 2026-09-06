(()=>{
'use strict';
const host=document.querySelector('.intelligence-graph');
if(!host||host.querySelector('.koschei-structural-mesh'))return;
const canvas=document.createElement('canvas');
canvas.className='koschei-structural-mesh';
canvas.setAttribute('aria-hidden','true');
host.appendChild(canvas);
const ctx=canvas.getContext('2d',{alpha:true});
const reduce=window.matchMedia('(prefers-reduced-motion: reduce)').matches;
let w=0,h=0,dpr=1,raf=0,t0=0;
const seed=1731;
function rand(i){const x=Math.sin((i+1)*12.9898+seed)*43758.5453;return x-Math.floor(x)}
let nodes=[];let edges=[];
function build(){
  const count=w<520?44:74;
  nodes=[];
  const cx=w/2,cy=h/2;
  for(let i=0;i<count;i++){
    const a=(Math.PI*2*i/count)+(rand(i)*.34);
    const ring=i%5;
    const rr=[.18,.29,.40,.48,.56][ring]*(Math.min(w,h));
    const jitter=(rand(i+100)-.5)*Math.min(w,h)*.055;
    nodes.push({x:cx+Math.cos(a)*(rr+jitter),y:cy+Math.sin(a)*(rr*.82+jitter*.45),r:1.1+rand(i+200)*2.3,p:rand(i+300)*Math.PI*2,c:i%11===0?'warm':(i%7===0?'hot':'cool')});
  }
  edges=[];
  for(let i=0;i<nodes.length;i++){
    const a=nodes[i];
    const near=[];
    for(let j=0;j<nodes.length;j++)if(i!==j){const b=nodes[j];const d=Math.hypot(a.x-b.x,a.y-b.y);near.push([d,j]);}
    near.sort((x,y)=>x[0]-y[0]);
    for(let k=0;k<Math.min(3,near.length);k++){const j=near[k][1];if(j>i)edges.push([i,j]);}
  }
}
function resize(){
  const rect=host.getBoundingClientRect();w=Math.max(1,rect.width);h=Math.max(1,rect.height);dpr=Math.min(devicePixelRatio||1,1.6);
  canvas.width=Math.floor(w*dpr);canvas.height=Math.floor(h*dpr);canvas.style.width=w+'px';canvas.style.height=h+'px';ctx.setTransform(dpr,0,0,dpr,0,0);build();
}
function draw(ts){
  if(!t0)t0=ts;const t=(ts-t0)/1000;ctx.clearRect(0,0,w,h);
  ctx.globalCompositeOperation='lighter';
  for(const [ia,ib] of edges){const a=nodes[ia],b=nodes[ib];const hot=a.c==='hot'||b.c==='hot';const warm=a.c==='warm'||b.c==='warm';ctx.strokeStyle=hot?'rgba(255,74,90,.19)':warm?'rgba(255,153,67,.16)':'rgba(71,179,238,.18)';ctx.lineWidth=.7;ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke();}
  for(let i=0;i<nodes.length;i++){
    const n=nodes[i];const pulse=reduce?1:(.82+.18*Math.sin(t*1.6+n.p));
    const col=n.c==='hot'?'255,72,88':n.c==='warm'?'255,153,64':'68,191,244';
    ctx.fillStyle=`rgba(${col},${.28*pulse})`;ctx.beginPath();ctx.arc(n.x,n.y,n.r*3.4,0,Math.PI*2);ctx.fill();
    ctx.fillStyle=`rgba(${col},${.88*pulse})`;ctx.beginPath();ctx.arc(n.x,n.y,n.r,0,Math.PI*2);ctx.fill();
  }
  const cx=w/2,cy=h/2;ctx.strokeStyle='rgba(84,188,239,.11)';ctx.lineWidth=1;for(const s of [.24,.36,.48,.58]){ctx.beginPath();ctx.ellipse(cx,cy,Math.min(w,h)*s,Math.min(w,h)*s*.82,0,0,Math.PI*2);ctx.stroke();}
  ctx.globalCompositeOperation='source-over';if(!reduce)raf=requestAnimationFrame(draw);
}
resize();window.addEventListener('resize',resize,{passive:true});if(reduce)draw(0);else raf=requestAnimationFrame(draw);window.addEventListener('pagehide',()=>raf&&cancelAnimationFrame(raf),{once:true});
})();
