'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const migration=fs.readFileSync(path.join(root,'migrations','021_web3_async_jobs.sql'),'utf8');
const jobTypes=fs.readFileSync(path.join(root,'internal','jobs','types.go'),'utf8');
const store=fs.readFileSync(path.join(root,'internal','jobs','history.go'),'utf8');
const handler=fs.readFileSync(path.join(root,'internal','handlers','customer_investigation_history.go'),'utf8');
const jobsHandler=fs.readFileSync(path.join(root,'internal','handlers','web3_jobs.go'),'utf8');
const server=fs.readFileSync(path.join(root,'internal','http','server.go'),'utf8');
const inventory=fs.readFileSync(path.join(root,'internal','http','route_inventory.go'),'utf8');
const reportsHTML=fs.readFileSync(path.join(root,'public','reports.html'),'utf8');
const reportsJS=fs.readFileSync(path.join(root,'public','js','customer-reports-v2.js'),'utf8');
const dashboard=fs.readFileSync(path.join(root,'public','dashboard.html'),'utf8');
const workspaceJS=fs.readFileSync(path.join(root,'public','js','customer-workspace-v2.js'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden pattern ${pattern}`);}

requireText(migration,'CREATE TABLE IF NOT EXISTS web3_jobs','durable job table');
requireText(migration,'result_payload JSONB','durable result payload');
requireText(migration,'CREATE INDEX IF NOT EXISTS web3_jobs_user_created_idx ON web3_jobs (user_id, queued_at DESC);','account history index');
for(const state of ['StatusQueued    = "queued"','StatusRunning   = "running"','StatusCompleted = "completed"','StatusFailed    = "failed"'])requireText(jobTypes,state,`durable job state ${state}`);

requireText(store,'func (s *Store) ListByUser(ctx context.Context, userID, jobType string, limit int) ([]Job, error)','account-scoped history method');
requireText(store,'if userID == ""','required account scope');
requireText(store,'if limit <= 0 {','default history limit');
requireText(store,'if limit > MaxHistoryLimit {','maximum history limit');
requireText(store,"WHERE user_id=$1 AND ($2='' OR job_type=$2)",'user and job-type query scope');
requireText(store,'ORDER BY queued_at DESC,id DESC','canonical history ordering');
requireText(store,'scanJob(rows)','shared job scanner contract');

requireText(handler,'func (h *Handler) CustomerInvestigationHistory','customer history handler');
requireText(handler,'h.RequirePlanTier("starter", h.customerInvestigationHistoryRead)(w, r)','Starter SaaS history gate');
requireText(handler,'h.JobStore.ListByUser(r.Context(), claims.Sub, CanonicalInvestigationJobType, 100)','canonical account history query');
requireText(handler,'ResultAvailable bool','result availability evidence');
requireText(handler,'if json.Unmarshal(job.ResultPayload, &result) == nil && result != nil','result payload parse boundary');
requireText(handler,'"schema_version": "koschei-customer-investigation-history-v1"','versioned history envelope');
requireText(handler,'"source": "web3_jobs"','durable source marker');
requireText(handler,'"job_type": CanonicalInvestigationJobType','canonical job-type marker');
requireText(handler,'"history": items','history collection envelope');
forbid(handler,/RequireTokenTier|KOSCH access|EnforceScanQuota/,'history handler must use SaaS entitlement without token or quota coupling');

requireText(jobsHandler,'if id == "" {','empty job-id dispatch boundary');
requireText(jobsHandler,'if canonicalHistoryCollectionPath(r.URL.Path) {','radar jobs collection isolation');
requireText(jobsHandler,'h.CustomerInvestigationHistory(w, r)','history collection delegation');
requireText(jobsHandler,'func canonicalHistoryCollectionPath(path string) bool','collection path predicate');
requireText(jobsHandler,'return strings.TrimSuffix(strings.TrimSpace(path), "/") == "/api/v1/radar/jobs"','canonical-only collection predicate');
requireText(jobsHandler,'writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})','legacy empty collection remains not found');
requireText(server,'mux.HandleFunc("/api/v1/radar/jobs/", solana(requiresDB(h, handlers.RequireAuth(method("GET", h.GetWeb3Job)))))','existing radar jobs GET route');
if(server.includes('/api/v1/investigations/history'))throw new Error('server: do not add a parallel history endpoint; use the existing radar jobs collection');
requireText(inventory,'"GET /api/v1/radar/jobs/"','machine-readable radar jobs GET route');
if(inventory.includes('/api/v1/investigations/history'))throw new Error('inventory: parallel history endpoint must not be advertised');

requireText(reportsHTML,'STARTER+ SAAS · DURABLE CANONICAL JOB HISTORY','Vault SaaS access copy');
requireText(reportsHTML,'History access requires an active Starter SaaS entitlement or higher.','Vault entitlement boundary');
requireText(reportsHTML,'Reading history does not consume a premium output','Vault read-only quota copy');
requireText(reportsHTML,'Commercial access is determined only by the active SaaS entitlement.','Vault SaaS authority copy');
requireText(reportsHTML,'signed=true','Vault strict signed copy');
requireText(reportsHTML,'/js/customer-reports-v2.js?v=2','Vault history controller');
requireText(reportsHTML,'/scan?mode=deep','Vault canonical investigation route');
forbid(reportsHTML,/KOSCH|token holdings|BASIC\+ KOSCH|Basic KOSCH tier/i,'legacy token-holder authorization copy');

requireText(reportsJS,"KoscheiAuth.apiCall('/api/v1/radar/jobs/'",'Vault history source');
requireText(reportsJS,"data?.schema_version!=='koschei-customer-investigation-history-v1'",'Vault schema gate');
requireText(reportsJS,"data?.source!=='web3_jobs'",'Vault source gate');
requireText(reportsJS,"data?.job_type!=='canonical_investigation'",'Vault job-type gate');
requireText(reportsJS,"if(!Array.isArray(history))",'Vault unavailable-not-empty boundary');
requireText(reportsJS,"if(signed===true&&signature&&ruleset)return {kind:'signed',label:'SIGNED'",'Vault strict signed gate');
requireText(reportsJS,"if(signed===true)return {kind:'incomplete',label:'SIGNATURE INCOMPLETE'}",'Vault incomplete signature state');
requireText(reportsJS,"if(value===null||value===undefined||value==='')return null",'Vault null numeric boundary');
requireText(reportsJS,"state==='completed'&&item?.result_available!==true",'completed-without-result warning');
requireText(reportsJS,"KoscheiAuth.requireAuth('/login.html')",'Vault canonical login continuation');
if(reportsJS.includes('/api/v1/unified/reports'))throw new Error('Vault must not call dead unified-reports frontend contract');
if(reportsJS.includes('/api/v1/investigations/history'))throw new Error('Vault must use the canonical radar jobs collection');
forbid(reportsJS,/\.innerHTML\s*=/,'Vault API-derived innerHTML');
forbid(reportsJS,/\bfetch\s*\(/,'Vault raw fetch');
forbid(reportsJS,/Authorization/i,'Vault manual bearer auth');
forbid(reportsJS,/\blocalStorage\b|\bsessionStorage\b/,'Vault browser auth persistence');
forbid(reportsJS,/Math\.random\s*\(/,'Vault synthetic evidence');
forbid(reportsJS,/\b(?:signMessage|signTransaction|signAllTransactions|signAndSendTransaction|sendTransaction)\b/,'Vault wallet authority');

requireText(dashboard,'Investigation jobs','Workspace history KPI');
requireText(dashboard,'RECENT INVESTIGATION','Workspace latest-history copy');
requireText(dashboard,'Investigation History','Workspace history navigation');
requireText(dashboard,'/js/customer-workspace-v2.js?v=2','Workspace history controller');
if(dashboard.includes('Signed Report Vault'))throw new Error('Workspace must not advertise every durable job as a signed report');

requireText(workspaceJS,"read('/api/v1/radar/jobs/')",'Workspace history source');
requireText(workspaceJS,"data.schema_version!=='koschei-customer-investigation-history-v1'",'Workspace history schema gate');
requireText(workspaceJS,"data.source!=='web3_jobs'",'Workspace history source gate');
requireText(workspaceJS,"data.job_type!=='canonical_investigation'",'Workspace canonical job-type gate');
requireText(workspaceJS,"if(signed===true&&signature&&ruleset)return'SIGNED'",'Workspace strict signed gate');
requireText(workspaceJS,"if(signed===true)return'SIGNATURE INCOMPLETE'",'Workspace incomplete signature state');
requireText(workspaceJS,'renderLatestInvestigation(investigationHistory)','Workspace latest canonical render');
requireText(workspaceJS,'historyAvailable=Array.isArray(investigationHistory)','Workspace availability truth');
requireText(workspaceJS,'availableSources=[accessResult.ok,historyAvailable,watchResult.ok,alertsResult.ok]','Workspace source availability truth');
if(workspaceJS.includes('/api/v1/unified/reports'))throw new Error('Workspace must not call dead unified-reports frontend contract');
if(workspaceJS.includes('/api/v1/investigations/history'))throw new Error('Workspace must use the canonical radar jobs collection');
const latestStart=workspaceJS.indexOf('function renderLatestInvestigation');
const alertsStart=workspaceJS.indexOf('function renderAlerts');
if(latestStart<0||alertsStart<=latestStart)throw new Error('Workspace latest-investigation render boundary missing');
const latestSlice=workspaceJS.slice(latestStart,alertsStart);
forbid(latestSlice,/\.innerHTML\s*=/,'Workspace latest investigation API-derived innerHTML');
forbid(workspaceJS,/Math\.random\s*\(/,'Workspace synthetic history evidence');

console.log('canonical investigation history v1 contract: ok');
