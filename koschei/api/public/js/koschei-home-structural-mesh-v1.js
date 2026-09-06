(()=>{
'use strict';
const host=document.querySelector('.intelligence-graph');
if(!host||host.querySelector('.koschei-webgl-intelligence'))return;
const surface=document.createElement('canvas');
surface.className='koschei-webgl-intelligence';
surface.setAttribute('aria-hidden','true');
host.appendChild(surface);
const gl=surface.getContext('webgl',{alpha:true,antialias:true,premultipliedAlpha:false,preserveDrawingBuffer:false});
if(!gl){host.classList.add('webgl-unavailable');return;}
const reduce=matchMedia('(prefers-reduced-motion: reduce)').matches;
let w=1,h=1,dpr=1,raf=0,start=performance.now();

const bgVS=`attribute vec2 p;varying vec2 uv;void main(){uv=p*.5+.5;gl_Position=vec4(p,0.,1.);}`;
const bgFS=`precision mediump float;varying vec2 uv;uniform vec2 res;uniform float t;
float grid(float v,float n){float a=abs(fract(v*n)-.5);return 1.-smoothstep(.47,.5,a);} 
void main(){vec2 p=(uv-.5)*vec2(res.x/res.y,1.);float r=length(p);float sphere=1.-smoothstep(.49,.505,r);float z=sqrt(max(0.,.25-r*r));float lat=grid(atan(p.y,z)/3.14159+.5,18.);float lon=grid(atan(p.x,z)/6.28318+.5,28.);float rings=1.-smoothstep(.012,.02,abs(fract(r*12.)-.5));float scan=.5+.5*sin((p.y+t*.025)*90.);vec3 base=vec3(.012,.055,.09);vec3 cyan=vec3(.08,.55,.9);vec3 col=base+sphere*cyan*(lat*.18+lon*.22+rings*.07+scan*.018);float halo=(1.-smoothstep(.5,.68,r))*(smoothstep(.42,.5,r));col+=cyan*halo*.12;float vign=1.-smoothstep(.62,.92,length((uv-.5)*vec2(1.1,1.)));gl_FragColor=vec4(col*vign,sphere*.72+halo*.28);}`;
const netVS=`attribute vec2 p;attribute vec3 c;uniform vec2 res;uniform float t;varying vec3 vc;void main(){vec2 q=p;float asp=res.x/res.y;q.x/=asp;gl_Position=vec4(q,0.,1.);vc=c;gl_PointSize=2.5+1.4*sin(t*1.2+p.x*9.+p.y*7.);}`;
const netFS=`precision mediump float;varying vec3 vc;void main(){float a=1.;if(gl_PointCoord.x>0.){float d=length(gl_PointCoord-.5);a=1.-smoothstep(.18,.5,d);}gl_FragColor=vec4(vc,a*.78);}`;
function shader(type,src){const s=gl.createShader(type);gl.shaderSource(s,src);gl.compileShader(s);if(!gl.getShaderParameter(s,gl.COMPILE_STATUS))throw new Error(gl.getShaderInfoLog(s)||'shader');return s;}
function program(vs,fs){const p=gl.createProgram();gl.attachShader(p,shader(gl.VERTEX_SHADER,vs));gl.attachShader(p,shader(gl.FRAGMENT_SHADER,fs));gl.linkProgram(p);if(!gl.getProgramParameter(p,gl.LINK_STATUS))throw new Error(gl.getProgramInfoLog(p)||'program');return p;}
let bg,net;
try{bg=program(bgVS,bgFS);net=program(netVS,netFS);}catch(e){host.classList.add('webgl-unavailable');return;}
const quad=gl.createBuffer();gl.bindBuffer(gl.ARRAY_BUFFER,quad);gl.bufferData(gl.ARRAY_BUFFER,new Float32Array([-1,-1,1,-1,-1,1,-1,1,1,-1,1,1]),gl.STATIC_DRAW);
const posBuf=gl.createBuffer(), colBuf=gl.createBuffer(), edgeBuf=gl.createBuffer();
let points=0,edges=0;
function rand(i){const x=Math.sin((i+3)*91.733)*43758.5453;return x-Math.floor(x)}
function rebuild(){const count=w<620?82:150;const P=[],C=[];const nodes=[];for(let i=0;i<count;i++){const a=6.28318*rand(i*3),rr=.08+.39*Math.sqrt(rand(i*3+1));const y=(rand(i*3+2)-.5)*.78;const x=Math.cos(a)*rr;const yy=Math.sin(a)*rr*.78+y*.2;nodes.push([x,yy]);P.push(x,yy);const m=i%13===0?[1.,.22,.32]:i%9===0?[1.,.56,.18]:[.12,.7,1.];C.push(...m);}const E=[];for(let i=0;i<nodes.length;i++){const ds=[];for(let j=0;j<nodes.length;j++)if(i!==j){const dx=nodes[i][0]-nodes[j][0],dy=nodes[i][1]-nodes[j][1];ds.push([dx*dx+dy*dy,j]);}ds.sort((a,b)=>a[0]-b[0]);for(let k=0;k<2;k++){const j=ds[k][1];if(j>i)E.push(...nodes[i],...nodes[j]);}}gl.bindBuffer(gl.ARRAY_BUFFER,posBuf);gl.bufferData(gl.ARRAY_BUFFER,new Float32Array(P),gl.STATIC_DRAW);gl.bindBuffer(gl.ARRAY_BUFFER,colBuf);gl.bufferData(gl.ARRAY_BUFFER,new Float32Array(C),gl.STATIC_DRAW);gl.bindBuffer(gl.ARRAY_BUFFER,edgeBuf);gl.bufferData(gl.ARRAY_BUFFER,new Float32Array(E),gl.STATIC_DRAW);points=P.length/2;edges=E.length/2;}
function resize(){const r=host.getBoundingClientRect();w=Math.max(1,r.width);h=Math.max(1,r.height);dpr=Math.min(devicePixelRatio||1,1.5);surface.width=Math.floor(w*dpr);surface.height=Math.floor(h*dpr);surface.style.width=w+'px';surface.style.height=h+'px';gl.viewport(0,0,surface.width,surface.height);rebuild();}
function attr(pr,name,buf,size){const a=gl.getAttribLocation(pr,name);gl.bindBuffer(gl.ARRAY_BUFFER,buf);gl.enableVertexAttribArray(a);gl.vertexAttribPointer(a,size,gl.FLOAT,false,0,0);}
function draw(now){const t=(now-start)/1000;gl.clearColor(0,0,0,0);gl.clear(gl.COLOR_BUFFER_BIT);gl.enable(gl.BLEND);gl.blendFunc(gl.SRC_ALPHA,gl.ONE);
 gl.useProgram(bg);attr(bg,'p',quad,2);gl.uniform2f(gl.getUniformLocation(bg,'res'),surface.width,surface.height);gl.uniform1f(gl.getUniformLocation(bg,'t'),reduce?0:t);gl.drawArrays(gl.TRIANGLES,0,6);
 gl.useProgram(net);gl.uniform2f(gl.getUniformLocation(net,'res'),surface.width,surface.height);gl.uniform1f(gl.getUniformLocation(net,'t'),reduce?0:t);attr(net,'p',edgeBuf,2);const c=gl.getAttribLocation(net,'c');gl.disableVertexAttribArray(c);gl.vertexAttrib3f(c,.08,.55,.9);gl.lineWidth(1);gl.drawArrays(gl.LINES,0,edges);attr(net,'p',posBuf,2);attr(net,'c',colBuf,3);gl.drawArrays(gl.POINTS,0,points);
 if(!reduce)raf=requestAnimationFrame(draw);
}
resize();addEventListener('resize',resize,{passive:true});draw(performance.now());addEventListener('pagehide',()=>raf&&cancelAnimationFrame(raf),{once:true});
})();