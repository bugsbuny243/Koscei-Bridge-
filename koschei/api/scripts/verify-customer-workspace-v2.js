'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','dashboard.html'),'utf8');
const js=fs.readFileSync(path.join(root,'public','js','customer-workspace-v2.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','customer-workspace-v2.css'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}

requireText(html,'/css/customer-workspace-v2.css?v=1','dashboard html');
requireText(html,'/js/customer-workspace-v2.js?v=1','dashboard html');
requireText(html,'id="workspaceMissionControl"','mission control mount');
requireText(html,'id="workspaceLatestReport"','latest report mount');
requireText(html,'id="workspaceAlerts"','alerts mount');
requireText(js,"read('/api/auth/premium-access')",'access source');
requireText(js,"read('/api/v1/unified/reports')",'reports source');
requireText(js,"read('/api/watchlist')",'watchlist source');
requireText(js,"read('/api/watchlist/alerts')",'alerts source');
requireText(js,'if(!KoscheiAuth.isLoggedIn())','signed-out privacy boundary');
requireText(js,"state.dataset.state='signed_out'",'signed-out UI state');
requireText(js,"encodeURIComponent(target)",'safe target navigation');
requireText(js,"kind==='token'||kind==='mint'",'token continuation');
requireText(js,"kind==='wallet'",'wallet continuation');
requireText(js,"kind==='site'||kind==='url'",'site continuation');
requireText(js,"!text(item.read_at)",'empty read-at unread handling');
requireText(css,'.workspace-live','mission control styles');
requireText(css,'.workspace-alert','alert styles');
requireText(css,'.workspace-report-card','report styles');

if(js.includes('Math.random('))throw new Error('workspace must not fabricate live metrics');
if(/fetch\s*\(/.test(js))throw new Error('workspace account data must use KoscheiAuth.apiCall instead of unauthenticated fetch');
if(!html.includes('Unavailable data stays unavailable; the UI does not invent operational state.'))throw new Error('dashboard must expose the no-fake-data boundary');
console.log('customer workspace v2 contract: ok');
