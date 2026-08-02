(()=>{
'use strict';
let installed=false;
function rootFor(value){return typeof value==='string'?document.getElementById(value):value;}
function install(){
  if(installed||!window.OwnerRadarKit||!window.KoscheiARVISPremium)return false;
  installed=true;
  const kit=window.OwnerRadarKit;
  const baseScan=kit.scan?.bind(kit),baseRender=kit.render?.bind(kit),baseUnified=kit.renderUnified?.bind(kit);
  const mount=(root,payload)=>{const node=rootFor(root);if(!node||!payload)return;window.KoscheiARVISPremium.mountPremiumCard(node,payload);};
  const scan=async(target,root)=>{const payload=await baseScan(target,root);mount(root,payload);return payload;};
  const render=(root,payload)=>{const result=baseRender?.(root,payload);mount(root,payload);return result;};
  const renderUnified=(root,payload)=>{const result=baseUnified?.(root,payload);mount(root,payload);return result;};
  window.OwnerRadarKit={...kit,scan,render,renderUnified,get lastScan(){return kit.lastScan;}};
  document.querySelectorAll('#ownerRadarResult').forEach(root=>{const payload=window.OwnerRadarKit.lastScan;if(payload)mount(root,payload);});
  return true;
}
if(!install()){
  const timer=setInterval(()=>{if(install())clearInterval(timer);},40);
  setTimeout(()=>clearInterval(timer),12000);
}
})();