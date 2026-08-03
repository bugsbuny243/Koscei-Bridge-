(()=>{
'use strict';
if(window.__koscheiUnifiedScanNavigation)return;
window.__koscheiUnifiedScanNavigation=true;
const legacyModes=new Map([
  ['/safe-check','quick'],['/safe-check.html','quick'],
  ['/transaction-shield','transaction'],['/transaction-shield.html','transaction'],
  ['/security-radar','deep'],['/security-radar.html','deep']
]);
const navSelector='nav,.koschei-global-nav,.product-footer';

function normalizedPath(anchor){
  try{return new URL(anchor.getAttribute('href')||'',location.origin).pathname.replace(/\/$/,'')||'/'}catch{return''}
}
function modeURL(anchor,mode){
  let url;
  try{url=new URL(anchor.getAttribute('href')||'',location.origin)}catch{url=new URL('/scan',location.origin)}
  const query=new URLSearchParams(url.search);
  query.set('mode',mode);
  return `/scan?${query.toString()}`;
}
function normalizeLinks(root=document){
  const anchors=[...root.querySelectorAll('a[href]')];
  anchors.forEach(anchor=>{
    const path=normalizedPath(anchor);
    const mode=legacyModes.get(path);
    if(!mode)return;
    anchor.href=modeURL(anchor,mode);
  });

  const navigationGroups=[...root.querySelectorAll(navSelector)];
  navigationGroups.forEach(group=>{
    const scanLinks=[...group.querySelectorAll('a[href]')].filter(anchor=>normalizedPath(anchor)==='/scan');
    if(!scanLinks.length)return;
    const keep=scanLinks[0];
    keep.href='/scan';
    keep.textContent='Scan Center';
    keep.setAttribute('data-canonical-scan-link','1');
    scanLinks.slice(1).forEach(anchor=>anchor.remove());
  });
}

function run(){normalizeLinks(document)}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',run,{once:true});else run();
const observer=new MutationObserver(records=>{
  if(records.some(record=>[...record.addedNodes].some(node=>node.nodeType===1)))normalizeLinks(document);
});
observer.observe(document.documentElement,{childList:true,subtree:true});
})();
