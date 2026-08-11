'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','owner-production.html'),'utf8');
const js=fs.readFileSync(path.join(root,'public','js','owner-evidence-explorer-v2.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','owner-evidence-explorer-v2.css'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}

requireText(html,'/css/owner-evidence-explorer-v2.css?v=1','owner html');
requireText(html,'/js/owner-evidence-explorer-v2.js?v=1','owner html');
requireText(js,'funding_trajectory_graph','trajectory source');
requireText(js,'Trajectory graph','graph tab');
requireText(js,'Timeline','timeline tab');
requireText(js,'Evidence records','evidence tab');
requireText(js,'visualization never creates attribution, identity, intent, wrongdoing, rug, or safety claims','authority boundary');
requireText(js,'Raw technical payload','raw payload disclosure');
requireText(js,"graph.verified_evidence_edge_count",'verified edge metric');
requireText(js,"final_verdict.triggered_rules",'verdict evidence source');
requireText(js,"capability_integration.capabilities",'coverage evidence source');
requireText(js,"behavioral_signatures.matches",'behavior evidence source');
requireText(js,"raw.includes('unverified')",'unverified fail-closed mapping');
requireText(css,'.koschei-trajectory-svg','trajectory styles');
requireText(css,'.koschei-evidence-record','evidence record styles');
requireText(css,'.koschei-raw-payload','raw payload styles');

const premium=html.indexOf('/js/owner-arvis-premium-suite.js?v=1');
const ux=html.indexOf('/js/owner-investigation-ux.js?v=1');
const explorer=html.indexOf('/js/owner-evidence-explorer-v2.js?v=1');
if(premium<0||ux<premium||explorer<ux)throw new Error('owner html: explorer must load after premium renderer and investigation UX v1');

const unverifiedIndex=js.indexOf("raw.includes('unverified')");
const verifiedIndex=js.indexOf("raw.includes('verified')");
if(unverifiedIndex<0||verifiedIndex<0||unverifiedIndex>verifiedIndex)throw new Error('state mapper must classify unverified before verified');
if(/verdict_authority\s*=\s*true|grade_authority\s*=\s*true/.test(js))throw new Error('explorer must not grant verdict or grade authority');
console.log('owner evidence explorer v2 contract: ok');
