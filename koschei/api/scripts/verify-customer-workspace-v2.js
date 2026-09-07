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
requireText(html,'/js/customer-workspace-v2.js?v=3','stateless account workspace runtime');
requireText(html,'/js/koschei-dashboard.js?v=4','dashboard runtime');
requireText(html,'id="workspaceLiveState"','account state mount');
requireText(html,'id="workspaceLatestReport"','persistence truth mount');
requireText(html,'id="workspaceAlerts"','monitoring truth mount');
requireText(html,'id="workspaceAccessKpi"','identity KPI');
requireText(html,'id="workspaceReportsKpi"','history capability KPI');
requireText(html,'id="workspaceWatchKpi"','watchlist capability KPI');
requireText(html,'id="workspaceAlertsKpi"','alerts capability KPI');
requireText(html,'The current production process is intentionally stateless','stateless runtime disclosure');
requireText(html,'PERSISTENCE OFF','disabled persistence boundary');
requireText(html,'Feedback storage','feedback persistence boundary');
requireText(html,'No fake telemetry','no synthetic telemetry boundary');
requireText(html,'Solana is the live chain core','live-chain boundary');
requireText(html,'NOT LIVE','non-live capability truth label');
requireText(html,'does not sign, submit, relay or broadcast customer transactions','no transaction authority boundary');
for(const forbiddenControl of ['id="exposureForm"','id="feedbackForm"'])rejectText(html,forbiddenControl,'non-live persistence-backed control');

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

requireText(workspaceJs,"read('/api/me')",'stateless authenticated identity source');
requireText(workspaceJs,'renderPersistenceBoundary','explicit disabled persistence projection');
requireText(workspaceJs,"setKPI('workspaceReportsKpi','NOT LIVE'",'durable-history disabled state');
requireText(workspaceJs,"setKPI('workspaceWatchKpi','NOT LIVE'",'watchlist disabled state');
requireText(workspaceJs,"setKPI('workspaceAlertsKpi','NOT LIVE'",'alerts disabled state');
requireText(workspaceJs,"if(!KoscheiAuth.isLoggedIn())",'signed-out privacy boundary');
requireText(workspaceJs,"state.dataset.state='signed_out'",'signed-out UI state');
requireText(workspaceJs,'LIVE STATELESS ACCOUNT IDENTITY','stateless account truth');
for(const forbiddenRoute of [
  "/api/auth/premium-access",
  "/api/v1/radar/jobs/",
  "/api/watchlist",
  "/api/watchlist/alerts",
  "/api/v1/radar/exposure"
])rejectText(workspaceJs,forbiddenRoute,'stateless workspace must not call persistence-backed route');

requireText(css,'.workspace-live','runtime-truth styles');
requireText(css,'.workspace-command-empty','disabled capability styles');
requireText(dashboardJs,"fetch('/health'",'production health source');
requireText(dashboardJs,"document.body.classList.toggle('nav-open'",'mobile navigation');
for(const forbiddenRoute of ['/api/v1/radar/exposure','/api/analytics/event'])rejectText(dashboardJs,forbiddenRoute,'stateless dashboard must not call persistence-backed route');
rejectText(dashboardJs,'feedbackContainsSecretLanguage','retired feedback form runtime');

if(workspaceJs.includes('/api/v1/unified/reports'))throw new Error('workspace must not call removed unified-reports frontend contract');
if(workspaceJs.includes('/api/v1/investigations/history'))throw new Error('workspace must not call retired investigation-history contract');
if(/token_tier|token_amount|holder access/i.test(workspaceJs))throw new Error('workspace must not derive access from token holdings');
if(workspaceJs.includes('Math.random(')||dashboardJs.includes('Math.random('))throw new Error('customer panel must not fabricate live metrics');
if(/fetch\s*\(/.test(workspaceJs))throw new Error('account workspace data must use KoscheiAuth.apiCall instead of unauthenticated fetch');
if(/sendBundle|JITO_BUNDLE_URL|signAndSendTransaction|sendTransaction/.test(dashboardJs))throw new Error('dashboard must not gain transaction submission authority');
if(/loadStyle|createElement\(['\"]link['\"]\)|stylesheet.*append/i.test(dashboardJs))throw new Error('dashboard runtime must not inject stylesheet layers');

console.log('customer panel stateless evidence contract: ok');