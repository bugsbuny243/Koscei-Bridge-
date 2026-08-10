'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','owner-production.html'),'utf8');
const js=fs.readFileSync(path.join(root,'public','js','owner-investigation-ux.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','owner-investigation-ux.css'),'utf8');

function requireText(source,needle,label){
  if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);
}

requireText(html,'/css/owner-investigation-ux.css?v=1','owner html');
requireText(html,'/js/owner-investigation-ux.js?v=1','owner html');
requireText(js,'No deterministic blocking rule fired','policy explanation');
requireText(js,'ALLOW is not a safety guarantee','allow boundary');
requireText(js,"['Findings','MATERIAL FINDINGS']",'evidence navigator');
requireText(js,"['Rule trace','EXPLAINABLE VERDICT']",'rule trace navigator');
requireText(js,"section.classList.add('is-collapsed')",'rule disclosure');
requireText(css,'.koschei-decision-lens','decision lens styles');
requireText(css,'.koschei-rule-section.is-collapsed .arvis-rule:nth-child(n+5)','mobile rule compaction');

const premiumIndex=html.indexOf('/js/owner-arvis-premium-suite.js?v=1');
const uxIndex=html.indexOf('/js/owner-investigation-ux.js?v=1');
if(premiumIndex<0||uxIndex<premiumIndex)throw new Error('owner html: investigation UX must load after the premium card renderer');

console.log('owner investigation UX v1 contract: ok');
