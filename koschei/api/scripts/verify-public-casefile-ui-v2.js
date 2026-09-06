'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const css=fs.readFileSync(path.join(root,'public','css','public-casefile.css'),'utf8');
const handler=fs.readFileSync(path.join(root,'internal','handlers','public_case_page.go'),'utf8');

function requireText(source,needle,label){
  if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);
}

requireText(handler,'/css/koschei.css?v=1','case handler stylesheet contract');
requireText(handler,'func (h *Handler) PublicCasePage','public case handler');
requireText(handler,'publicCaseHTML.Execute(w, data)','case HTML template renderer');
requireText(handler,'buildPublicCasePageData','canonical case presentation mapper');
requireText(handler,'bundle.CaseRef != caseRef || bundle.BundleHash == ""','immutable bundle integrity gate');
requireText(handler,'p.status=\'public\'','explicit publication gate');

requireText(css,'.case-nav{position:sticky','sticky case navigation');
requireText(css,'.verdict-card{position:sticky','sticky verdict hierarchy');
requireText(css,'.evidence-table-wrap thead{position:sticky','sticky evidence header');
requireText(css,'.state.verified','verified evidence state');
requireText(css,'.state.failed','failed evidence state');
requireText(css,'.coverage-grid','coverage layout');
requireText(css,'.rule-list','rule trace layout');
requireText(css,'.evidence-panel','evidence panel layout');
requireText(css,'content-visibility:auto','large casefile rendering optimization');
requireText(css,'@media(max-width:780px)','mobile layout contract');

const forbiddenEvidenceHides=[
  /\.evidence-panel[^{}]*\{[^}]*display\s*:\s*none/i,
  /\.evidence-table-wrap[^{}]*\{[^}]*display\s*:\s*none/i,
  /\.coverage-grid[^{}]*\{[^}]*display\s*:\s*none/i,
  /\.rule-list[^{}]*\{[^}]*display\s*:\s*none/i,
  /\.decision-grid[^{}]*\{[^}]*display\s*:\s*none/i
];
for(const pattern of forbiddenEvidenceHides){
  if(pattern.test(css))throw new Error(`casefile UI must not hide canonical evidence: ${pattern}`);
}

if(/url\(\s*['"]?javascript:/i.test(css))throw new Error('casefile stylesheet must not contain javascript URLs');
if(/expression\s*\(/i.test(css))throw new Error('casefile stylesheet must not contain CSS expressions');
console.log('public casefile UI v2 contract: ok');
