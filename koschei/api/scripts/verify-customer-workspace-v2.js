'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','dashboard.html'),'utf8');
const js=fs.readFileSync(path.join(root,'public','js','customer-workspace-v2.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','customer-workspace-v2.css'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden ${pattern}`);}

requireText(html,'/css/customer-workspace-v2.css?v=1','dashboard html');
requireText(html,'/css/koschei-enterprise-v3.css?v=1','enterprise dashboard style');
requireText(html,'/css/customer-command-center-v1.css?v=1','premium customer command center style');
requireText(html,'/js/customer-command-center-v1.js?v=1','premium customer command center behavior');
requireText(html,'/js/customer-workspace-v2.js?v=2','dashboard html');
requireText(html,'id="workspaceMissionControl"','operations mount');
requireText(html,'id="workspaceLatestReport"','latest investigation mount');
requireText(html,'id="workspaceAlerts"','alerts mount');
requireText(html,'RECENT INVESTIGATION','recent investigation copy');
requireText(html,'Investigation jobs','history KPI copy');
requireText(html,'SaaS plan','SaaS access KPI');
requireText(html,'ARVIS early access','ARVIS readiness disclosure');
requireText(html,'Preview monitored targets','watchlist preview disclosure');
requireText(html,'Their presence in the workspace is not a claim of full production readiness.','unfinished surface boundary');
forbid(html,/KOSCH access|KOSCH Account|KOSCH holder access|Checking holder access/i,'legacy holder access workspace copy');

requireText(js,"read('/api/auth/premium-access')",'SaaS access source');
requireText(js,"read('/api/v1/radar/jobs/')",'canonical history source');
requireText(js,"read('/api/watchlist')",'watchlist source');
requireText(js,"read('/api/watchlist/alerts')",'alerts source');
requireText(js,'if(!KoscheiAuth.isLoggedIn())','signed-out privacy boundary');
requireText(js,"state.dataset.state='signed_out'",'signed-out UI state');
requireText(js,"data.schema_version!=='koschei-customer-investigation-history-v1'",'history schema boundary');
requireText(js,"data.source!=='web3_jobs'",'history source boundary');
requireText(js,"data.job_type!=='canonical_investigation'",'history job-type boundary');
requireText(js,"if(signed===true&&signature&&ruleset)return'SIGNED'",'strict signed evidence state');
requireText(js,"if(signed===true)return'SIGNATURE INCOMPLETE'",'incomplete signed evidence state');
requireText(js,'historyAvailable=Array.isArray(investigationHistory)','history unavailable-not-empty boundary');
requireText(js,"const plan=text(access.plan||'none').toUpperCase()",'SaaS plan projection');
requireText(js,'access.outputs_remaining','remaining SaaS capacity');
requireText(js,'access.outputs_total','total SaaS capacity');
requireText(js,'No active paid SaaS entitlement.','inactive SaaS boundary');
requireText(js,'Professional plan required.','Professional watchlist boundary');
requireText(js,"encodeURIComponent(target)",'safe target navigation');
requireText(js,"!text(item.read_at)",'existing alert unread handling');
requireText(css,'.workspace-live','operations styles');
requireText(css,'.workspace-alert','alert styles');
requireText(css,'.workspace-report-card','investigation card styles');
const shellCss=fs.readFileSync(path.join(root,'public','css','customer-command-center-v1.css'),'utf8');
const shellJs=fs.readFileSync(path.join(root,'public','js','customer-command-center-v1.js'),'utf8');
requireText(shellCss,'.customer-app-shell','premium app shell');
requireText(shellCss,'.customer-sidebar','premium sidebar');
requireText(shellJs,"['Deep Investigation','/scan?mode=deep','primary']",'canonical investigation nav');
requireText(shellJs,"['Account & Plan','/account']",'account entitlement nav');
requireText(shellJs,"main.wrap, main.page, main.ops-page",'shared customer surface mount');
requireText(shellJs,".top, .ops-nav",'shared customer header mount');
for(const page of ['scan.html','reports.html','watchlist.html','account.html']){const pageHtml=fs.readFileSync(path.join(root,'public',page),'utf8');requireText(pageHtml,'/css/customer-command-center-v1.css?v=1',page+' shared shell style');requireText(pageHtml,'/js/customer-command-center-v1.js?v=2',page+' shared shell behavior');}
if(/fetch\s*\(/.test(shellJs))throw new Error('command center shell must not create parallel unauthenticated data calls');
if(shellJs.includes('Math.random('))throw new Error('command center shell must not fabricate product state');

if(js.includes('/api/v1/unified/reports'))throw new Error('workspace must not call removed unified-reports frontend contract');
if(js.includes('/api/v1/investigations/history'))throw new Error('workspace must use the canonical radar jobs collection');
if(/token_tier|token_amount|KOSCH holder access/i.test(js))throw new Error('workspace must not derive access from token holdings');
if(js.includes('Math.random('))throw new Error('workspace must not fabricate live metrics');
if(/fetch\s*\(/.test(js))throw new Error('workspace account data must use KoscheiAuth.apiCall instead of unauthenticated fetch');
if(!html.includes('If a source is unavailable, the workspace leaves it unavailable instead of inventing a status.'))throw new Error('dashboard must expose the no-fake-data boundary');
console.log('customer workspace evidence + SaaS access contract: ok');
