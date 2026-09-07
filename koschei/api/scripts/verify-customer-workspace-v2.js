'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','dashboard.html'),'utf8');
const workspaceJs=fs.readFileSync(path.join(root,'public','js','customer-workspace-v2.js'),'utf8');
const dashboardJs=fs.readFileSync(path.join(root,'public','js','koschei-dashboard.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','koschei-dashboard.css'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function rejectText(source,needle,label){if(source.includes(needle))throw new Error(`${label}: contains retired ${needle}`);}

requireText(html,'/css/koschei-dashboard.css?v=2','single dashboard stylesheet');
requireText(html,'/js/koschei-auth.js?v=33','authenticated session runtime');
requireText(html,'/js/customer-workspace-v2.js?v=2','account workspace runtime');
requireText(html,'/js/koschei-dashboard.js?v=2','dashboard runtime');
requireText(html,'id="workspaceLiveState"','account state mount');
requireText(html,'id="workspaceLatestReport"','latest investigation mount');
requireText(html,'id="workspaceAlerts"','alerts mount');
requireText(html,'id="workspaceAccessKpi"','access KPI');
requireText(html,'id="workspaceReportsKpi"','history KPI');
requireText(html,'id="workspaceWatchKpi"','watchlist KPI');
requireText(html,'id="workspaceAlertsKpi"','alerts KPI');
requireText(html,'RECENT CANONICAL INVESTIGATION','canonical history label');
requireText(html,'No fake telemetry','no synthetic telemetry boundary');
requireText(html,'Solana is the live chain core','live-chain boundary');
requireText(html,'NOT LIVE','future-chain truth label');
requireText(html,'id="exposureForm"','integrated exposure form');
requireText(html,'id="feedbackForm"','integrated feedback form');
requireText(html,'does not sign, submit, relay or broadcast customer transactions','no transaction authority boundary');

if((html.match(/<link rel="stylesheet"/g)||[]).length!==1)throw new Error('dashboard must load exactly one stylesheet');
if(/<style[\s>]/i.test(html))throw new Error('dashboard must not contain inline style patches');
for(const retired of [
  'koschei.css',
  'customer-command-center-v1.css',
  'customer-command-universe-v2.css',
  'customer-command-center-v1.js',
  'customer-command-universe-v2.js',
  'koschei-global-shell.js',
  'koschei-product-v2.js'
])rejectText(html,retired,'dashboard layered-shell contract');
for(const retiredCopy of ['KOSCH holder','KOSCH Premium','Free Safe Check'])rejectText(html,retiredCopy,'retired commercial copy');

requireText(workspaceJs,"read('/api/auth/premium-access')",'Professional access source');
requireText(workspaceJs,"read('/api/v1/radar/jobs/')",'canonical history source');
requireText(workspaceJs,"read('/api/watchlist')",'watchlist source');
requireText(workspaceJs,"read('/api/watchlist/alerts')",'alerts source');
requireText(workspaceJs,'if(!KoscheiAuth.isLoggedIn())','signed-out privacy boundary');
requireText(workspaceJs,"state.dataset.state='signed_out'",'signed-out UI state');
requireText(workspaceJs,"data.schema_version!=='koschei-customer-investigation-history-v1'",'history schema boundary');
requireText(workspaceJs,"data.source!=='web3_jobs'",'history source boundary');
requireText(workspaceJs,"data.job_type!=='canonical_investigation'",'history job-type boundary');
requireText(workspaceJs,"if(signed===true&&signature&&ruleset)return'SIGNED'",'strict signed evidence state');
requireText(workspaceJs,"if(signed===true)return'SIGNATURE INCOMPLETE'",'incomplete signed evidence state');
requireText(workspaceJs,'historyAvailable=Array.isArray(investigationHistory)','history unavailable-not-empty boundary');
requireText(workspaceJs,"const plan=text(access.plan||'none').toUpperCase()",'plan projection');
requireText(workspaceJs,'No active paid SaaS entitlement.','inactive entitlement boundary');
requireText(workspaceJs,'Professional plan required.','Professional watchlist boundary');
requireText(workspaceJs,"encodeURIComponent(target)",'safe target navigation');
requireText(workspaceJs,"!text(item.read_at)",'existing alert unread handling');
requireText(css,'.workspace-live','operations styles');
requireText(css,'.workspace-alert','alert styles');
requireText(css,'.workspace-report-card','investigation card styles');
requireText(css,'.operations-panel','integrated operations styles');
requireText(css,'.exposure-result','exposure styles');
requireText(css,'.feedback-form','feedback styles');
requireText(dashboardJs,"fetch('/health'",'production health source');
requireText(dashboardJs,"KoscheiAuth.apiCall('/api/v1/radar/exposure?target='",'canonical exposure source');
requireText(dashboardJs,"fetch('/api/analytics/event'",'feedback source');
requireText(dashboardJs,'feedbackContainsSecretLanguage','feedback secret guard');
requireText(dashboardJs,"document.body.classList.toggle('nav-open'",'mobile navigation');

if(workspaceJs.includes('/api/v1/unified/reports'))throw new Error('workspace must not call removed unified-reports frontend contract');
if(workspaceJs.includes('/api/v1/investigations/history'))throw new Error('workspace must use the canonical radar jobs collection');
if(/token_tier|token_amount|holder access/i.test(workspaceJs))throw new Error('workspace must not derive access from token holdings');
if(workspaceJs.includes('Math.random(')||dashboardJs.includes('Math.random('))throw new Error('customer panel must not fabricate live metrics');
if(/fetch\s*\(/.test(workspaceJs))throw new Error('account workspace data must use KoscheiAuth.apiCall instead of unauthenticated fetch');
if(/sendBundle|JITO_BUNDLE_URL|signAndSendTransaction|sendTransaction/.test(dashboardJs))throw new Error('dashboard must not gain transaction submission authority');
if(/loadStyle|createElement\(['\"]link['\"]\)|stylesheet.*append/i.test(dashboardJs))throw new Error('dashboard runtime must not inject stylesheet layers');

console.log('customer panel hardened evidence contract: ok');
