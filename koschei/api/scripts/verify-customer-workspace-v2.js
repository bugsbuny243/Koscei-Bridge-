'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','dashboard.html'),'utf8');
const js=fs.readFileSync(path.join(root,'public','js','customer-workspace-v2.js'),'utf8');
const dashboardJs=fs.readFileSync(path.join(root,'public','js','koschei-dashboard.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','koschei-dashboard.css'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function rejectText(source,needle,label){if(source.includes(needle))throw new Error(`${label}: contains retired ${needle}`);}

requireText(html,'/css/koschei-dashboard.css?v=1','dashboard stylesheet');
requireText(html,'/js/koschei-auth.js?v=33','authenticated session runtime');
requireText(html,'/js/customer-workspace-v2.js?v=2','account workspace data runtime');
requireText(html,'/js/koschei-dashboard.js?v=1','dashboard behavior');
requireText(html,'id="workspaceLiveState"','account state mount');
requireText(html,'id="workspaceLatestReport"','latest investigation mount');
requireText(html,'id="workspaceAlerts"','alerts mount');
requireText(html,'id="workspaceAccessKpi"','access KPI');
requireText(html,'id="workspaceReportsKpi"','history KPI');
requireText(html,'id="workspaceWatchKpi"','watchlist KPI');
requireText(html,'id="workspaceAlertsKpi"','alerts KPI');
requireText(html,'No fake telemetry','no synthetic telemetry boundary');
requireText(html,'Solana is the live chain core','live-chain boundary');
requireText(html,'Other chains','future-chain boundary');
requireText(html,'NOT LIVE','future-chain truth label');
requireText(html,'Production truth only.','sidebar truth boundary');

if((html.match(/<link rel="stylesheet"/g)||[]).length!==1)throw new Error('dashboard must load exactly one stylesheet');
if(/<style[\s>]/i.test(html))throw new Error('dashboard must not contain inline style patches');
for(const retired of [
  'koschei.css',
  'koschei-global-shell.css',
  'koschei-product-v2.css',
  'customer-workspace-v2.css',
  'koschei-enterprise-v3.css',
  'customer-command-center-v1.css',
  'customer-command-universe-v2.css',
  'customer-command-center-v1.js',
  'customer-command-universe-v2.js',
  'koschei-global-shell.js',
  'koschei-product-v2.js'
])rejectText(html,retired,'dashboard layered-shell contract');

requireText(js,"read('/api/auth/premium-access')",'Professional access source');
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
requireText(js,"const plan=text(access.plan||'none').toUpperCase()",'plan projection');
requireText(js,'No active paid SaaS entitlement.','inactive server entitlement boundary');
requireText(js,'Professional plan required.','Professional watchlist boundary');
requireText(js,"encodeURIComponent(target)",'safe target navigation');
requireText(js,"!text(item.read_at)",'existing alert unread handling');
requireText(css,'.workspace-live','operations styles');
requireText(css,'.workspace-alert','alert styles');
requireText(css,'.workspace-report-card','investigation card styles');
requireText(css,'.sidebar','single dashboard navigation style');
requireText(dashboardJs,"fetch('/health'",'production health source');
requireText(dashboardJs,"document.body.classList.toggle('nav-open'",'mobile navigation');

if(js.includes('/api/v1/unified/reports'))throw new Error('workspace must not call removed unified-reports frontend contract');
if(js.includes('/api/v1/investigations/history'))throw new Error('workspace must use the canonical radar jobs collection');
if(/token_tier|token_amount|holder access/i.test(js))throw new Error('workspace must not derive access from token holdings');
if(js.includes('Math.random(')||dashboardJs.includes('Math.random('))throw new Error('customer panel must not fabricate live metrics');
if(/fetch\s*\(/.test(js))throw new Error('workspace account data must use KoscheiAuth.apiCall instead of unauthenticated fetch');
if(/loadStyle|createElement\(['\"]link['\"]\)|stylesheet.*append/i.test(dashboardJs))throw new Error('dashboard runtime must not inject stylesheet layers');

console.log('customer panel two-surface evidence contract: ok');
