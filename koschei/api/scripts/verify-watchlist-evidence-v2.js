'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','watchlist.html'),'utf8');
const js=fs.readFileSync(path.join(root,'public','js','customer-watchlist-v2.js'),'utf8');
const routes=fs.readFileSync(path.join(root,'internal','http','watchlist_routes.go'),'utf8');
const server=fs.readFileSync(path.join(root,'internal','http','server.go'),'utf8');
const handler=fs.readFileSync(path.join(root,'internal','handlers','watchlist.go'),'utf8');
const monitor=fs.readFileSync(path.join(root,'internal','handlers','watchlist_monitor.go'),'utf8');
const migration=fs.readFileSync(path.join(root,'migrations','046_watchlist_alerts.sql'),'utf8');
const docs=fs.readFileSync(path.resolve(root,'..','..','docs','watchlist-alerts.md'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden pattern ${pattern}`);}

requireText(html,'PROFESSIONAL SAAS · METERED STRUCTURAL MONITORING','Professional metered access copy');
requireText(html,'requires the Professional plan','Professional access boundary');
requireText(html,'Paid monitoring and webhook access are governed by the same Professional entitlement.','single paid-plan boundary');
requireText(html,'href="/scan?mode=deep"','canonical Deep Scan route');
requireText(html,'id="watchThreshold" type="number" min="1" max="100" value="50" required','explicit threshold input');
requireText(html,'id="watchTargetCount">—/—','unknown initial target count');
requireText(html,'id="watchAlertCount">—/—','unknown initial alert count');
requireText(html,'/js/koschei-auth.js?v=33','frozen auth client');
requireText(html,'/js/customer-watchlist-v2.js?v=2','hardened watchlist controller');
forbid(html,/KOSCH tier|holder tier|Enterprise-entitlement/i,'removed package/token-backed watchlist access copy');
forbid(html,/<script(?![^>]*\bsrc=)[^>]*>/i,'inline runtime script');
forbid(html,/\son[a-z]+\s*=/i,'inline event handler');

requireText(routes,'func registerWatchlistRoutes','watchlist route registration function');
for(const route of ['"/api/watchlist", requiresDB(h, proMetered(','"/api/watchlist/refresh", requiresDB(h, proMetered(','"/api/watchlist/alerts", requiresDB(h, proMetered(','"/api/watchlist/", requiresDB(h, proMetered('])requireText(routes,route,`metered watchlist route ${route}`);
requireText(server,'return planTier("professional", next)','Professional watchlist server gate');
requireText(server,'return planTierAccess("professional", next)','Professional watchlist access gate');
requireText(server,'registerWatchlistRoutes(mux, h','watchlist route registration');
forbid(server,/koschTier\(|RequireTokenTier/,'legacy token watchlist authorization');

requireText(handler,'watchlistDefaultThreshold = 50','server threshold default');
requireText(handler,'watchlistMaxTargets       = 100','server target limit');
requireText(handler,'watchlistRefreshBatchMax  = 10','server batch refresh clamp');
requireText(handler,'"max_targets": watchlistMaxTargets','server-owned target capacity response');
requireText(handler,'if req.AlertThreshold == 0 {','zero-as-server-default contract');
requireText(handler,'req.AlertThreshold = watchlistDefaultThreshold','server threshold normalization');
requireText(handler,'if limit > watchlistRefreshBatchMax {','batch refresh clamp');
requireText(handler,'Status     string `json:"status"`','batch result status evidence');
requireText(handler,'"marked_read": count','authoritative reviewed count');

requireText(migration,"watchlist_targets_status_check CHECK (status IN ('active','paused'))",'target status enum');
requireText(migration,"watchlist_alerts_severity_check CHECK (severity IN ('info','low','medium','high','critical'))",'alert severity enum');
requireText(migration,"watchlist_alerts_status_check CHECK (status IN ('new','read'))",'alert review-state enum');

requireText(monitor,'services.AutomaticBackgroundScanningEnabled()','automatic background scanning gate');
requireText(monitor,'os.Getenv("WATCHLIST_MONITOR_ENABLED")','watchlist worker enable gate');
requireText(monitor,"WHERE status='active' AND COALESCE(next_check_at,now())<=now()",'due active target claim');
requireText(docs,'active **Professional SaaS plan**','documented Professional gate');
requireText(docs,'paid output-capacity enforcement remains server-owned','documented watchlist metering');
requireText(docs,'WATCHLIST_MONITOR_ENABLED','documented monitor enable gate');
requireText(docs,'**both** automatic background scanning and the watchlist monitor are explicitly enabled','documented dual background gate');
requireText(docs,'KOSCH holder balances and removed package labels do not grant or upgrade watchlist access.','documented KOSCH separation');

requireText(js,'let targets=null,alerts=null,maxTargets=null;','unknown initial collections');
requireText(js,"return allowedSeverities.has(raw)?raw:'unknown'",'unknown severity boundary');
requireText(js,"if(raw==='new')return'unread';if(raw==='read')return'read';return'unknown'",'authoritative alert review state');
requireText(js,"if(!hasValue(value))return'—'",'missing timestamp boundary');
requireText(js,'Professional SaaS plan or higher, a verified customer session, and available monitoring capacity are required.','Professional metered access error');
requireText(js,"targets=Array.isArray(targetData?.targets)?targetData.targets:null",'missing target collection boundary');
requireText(js,"alerts=Array.isArray(alertData?.alerts)?alertData.alerts:null",'missing alert collection boundary');
requireText(js,"maxTargets=parsedMax!==null&&parsedMax>=0?parsedMax:null",'server-owned target limit boundary');
requireText(js,"if(targets===null||alerts===null)status('Monitoring response is incomplete.",'incomplete collection warning');
requireText(js,"knownStatus=targetStatus==='active'||targetStatus==='paused'",'bounded target status predicate');
requireText(js,'if(knownStatus){const toggle=actionButton','bounded target toggle rendering');
requireText(js,"if(next!=='active'&&next!=='paused')",'bounded target toggle action');
requireText(js,"if(!Number.isInteger(threshold)||threshold<1||threshold>100)",'explicit threshold validation');
requireText(js,'hasValue(data?.refresh_error)','refresh degradation surfaced');
requireText(js,"if(!Array.isArray(data?.results))",'batch refresh collection boundary');
requireText(js,"lower(item?.status)==='failed'",'batch refresh failed-state accounting');
requireText(js,"!['completed','failed'].includes(lower(item?.status))",'batch refresh unknown-state accounting');
requireText(js,'const marked=numberOrNull(data?.marked_read)','reviewed count evidence boundary');
requireText(js,"if(marked===null)status('Review-state response is incomplete; no alert count is inferred.",'reviewed count missing boundary');

forbid(js,/Pro KOSCH|token tier|holder tier/i,'token-backed watchlist access messaging');
forbid(js,/const\s+arr\s*=.*Array\.isArray\(value\)\?value:\[\]/,'missing collection coerced to empty');
forbid(js,/item\??\.status\s*\|\|\s*['"]active['"]/,'unknown target status coerced active');
forbid(js,/last_risk_level\s*\|\|\s*['"]info['"]/,'unknown risk coerced info');
forbid(js,/new Date\(value\s*\|\|\s*0\)/,'missing timestamp coerced epoch');
forbid(js,/watchThreshold['"]?\)?\.value\s*\|\|\s*50/,'explicit zero threshold coerced client-side');
forbid(js,/\.innerHTML\s*=/,'API-derived innerHTML');
forbid(js,/\bfetch\s*\(/,'raw fetch bypassing KoscheiAuth');
forbid(js,/Authorization/i,'manual bearer header');
forbid(js,/\blocalStorage\b|\bsessionStorage\b/,'browser auth state persistence');
forbid(js,/Math\.random\s*\(/,'synthetic monitoring evidence');
forbid(js,/\b(?:signMessage|signTransaction|signAllTransactions|signAndSendTransaction|sendTransaction)\b/,'wallet authority');

console.log('Watchlist evidence-state v2 + Professional SaaS contract: ok');
