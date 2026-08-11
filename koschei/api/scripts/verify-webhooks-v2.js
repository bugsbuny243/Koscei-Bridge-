'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','webhooks.html'),'utf8');
const js=fs.readFileSync(path.join(root,'public','js','webhooks-v2.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','webhooks-v2.css'),'utf8');
const routes=fs.readFileSync(path.join(root,'internal','http','watchlist_routes.go'),'utf8');
const handler=fs.readFileSync(path.join(root,'internal','handlers','webhooks.go'),'utf8');
const worker=fs.readFileSync(path.join(root,'internal','webhooks','worker.go'),'utf8');
const docs=fs.readFileSync(path.resolve(root,'..','..','docs','webhook-delivery.md'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden pattern ${pattern}`);}

requireText(html,'<html lang="en">','webhook page language');
requireText(html,'Enterprise eligibility required','Enterprise access copy');
requireText(html,'Server-owned endpoint limit','server-owned limit copy');
requireText(html,'One-time plaintext secret','one-time secret copy');
requireText(html,'Delivery transports existing watchlist alert evidence','verdict authority boundary');
requireText(html,'id="webhookSecretPanel"','one-time secret panel');
requireText(html,'id="deliveryStatus"','delivery filter');
for(const status of ['pending','processing','retry','delivered','dead_letter'])requireText(html,`value="${status}"`,`delivery filter ${status}`);
requireText(html,'/kosch','canonical KOSCH route');
requireText(html,'/js/koschei-auth.js?v=33','frozen auth client');
requireText(html,'/js/webhooks-v2.js?v=1','external webhook controller');
if(html.includes('/kosch-access'))throw new Error('webhooks must not advertise legacy kosch-access');
forbid(html,/<script(?![^>]*\bsrc=)[^>]*>/i,'inline runtime script');
forbid(html,/\son[a-z]+\s*=/i,'inline event handler');

requireText(routes,'func registerWatchlistRoutes(mux *http.ServeMux, h *handlers.Handler, proMetered routeGate, enterprise routeGate)','Enterprise route gate parameter');
requireText(routes,'mux.HandleFunc("/api/webhooks", requiresDB(h, enterprise(h.WebhookEndpoints)))','Enterprise webhook management route');
requireText(routes,'mux.HandleFunc("/api/webhooks/", requiresDB(h, enterprise(h.WebhookEndpointItem)))','Enterprise webhook action route');
requireText(routes,'mux.HandleFunc("/api/webhooks/deliveries", requiresDB(h, enterprise(h.WebhookDeliveries)))','Enterprise delivery list route');
requireText(routes,'mux.HandleFunc("/api/webhooks/deliveries/", requiresDB(h, enterprise(h.WebhookDeliveryItem)))','Enterprise delivery action route');

requireText(handler,'const webhookEndpointLimit = 10','server endpoint limit');
requireText(handler,'"max_endpoints": webhookEndpointLimit','server max endpoint response');
requireText(handler,'SecretLast4','list-only secret suffix field');
requireText(handler,'webhooks.GenerateSecret()','one-time secret generation');
requireText(handler,'webhooks.EncryptSecret(secret)','encrypted-at-rest secret storage');
requireText(handler,'"secret_notice": "This secret is shown once','one-time plaintext response notice');
requireText(handler,'"webhook.test"','queued webhook test event');
requireText(handler,'case "pending", "processing", "retry", "delivered", "dead_letter"','delivery status filter contract');
requireText(handler,"status IN ('dead_letter','retry')",'manual requeue backend contract');
requireText(handler,'return []string{"watchlist.alert.created"}, nil','server-owned default event subscription');

requireText(worker,'req.Header.Set("X-Koschei-Signature", Signature(secret, timestamp, payload))','delivery signature header');
requireText(worker,'req.Header.Set("X-Koschei-Timestamp", timestamp)','delivery timestamp header');
requireText(worker,'resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooEarly || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500','retryable HTTP contract');
requireText(worker,"status=CASE WHEN failure_count+1>=20 THEN 'paused' ELSE status END",'automatic endpoint pause threshold');
requireText(docs,'active **Enterprise KOSCH eligibility**','documented Enterprise route gate');
requireText(docs,'Webhook management itself does not consume a scan unit','documented non-metered management contract');
requireText(docs,'Secrets are encrypted at rest with AES-GCM','documented secret storage');
requireText(docs,'A secret is returned only when the endpoint is created or rotated.','documented one-time secret lifecycle');
requireText(docs,'X-Koschei-Signature: v1=HEX_HMAC_SHA256','documented HMAC signature');

requireText(js,'KoscheiAuth.apiCall(path','shared authenticated API client');
for(const route of ["api('/api/webhooks')","api('/api/webhooks/deliveries'","/rotate-secret`","/test`","/retry`"])requireText(js,route,`webhook runtime route ${route}`);
requireText(js,"if(!Array.isArray(items)){count.textContent='UNAVAILABLE'",'missing endpoint collection fail-closed');
requireText(js,"if(!Array.isArray(items)){deliveryList.append",'missing delivery collection fail-closed');
requireText(js,"maxValue===null?'UNAVAILABLE':maxValue",'missing endpoint-limit boundary');
requireText(js,"failureCount===null?'UNAVAILABLE':failureCount",'missing failure-count boundary');
requireText(js,"httpStatus===null?'UNAVAILABLE':httpStatus",'missing HTTP-status boundary');
requireText(js,"if(status==='active'||status==='paused')",'bounded endpoint toggle rendering');
requireText(js,"if(nextStatus!=='active'&&nextStatus!=='paused')",'bounded endpoint toggle action');
requireText(js,'const SECRET_VISIBLE_MS=120000','bounded plaintext secret visibility');
requireText(js,'secretPanel.hidden=true','secret removal from visible DOM');
requireText(js,"if(revealSecret(data?.secret,'Webhook created'))",'create secret required for success copy');
requireText(js,"revealSecret(data?.secret,'Signing secret rotated')",'rotate one-time secret response');
requireText(js,"status==='dead_letter'&&id",'manual requeue shown only for dead-letter');
requireText(js,'JSON.stringify({name,url})','server-owned event subscription defaults');
requireText(js,"endpointList.append(node('div','webhook-error-box','Endpoint state unavailable. No capacity or health value is inferred.'))",'degraded endpoint evidence state');
requireText(js,"deliveryList.append(node('div','webhook-error-box','Delivery state unavailable. A missing delivery response is not treated as delivered.'))",'degraded delivery evidence state');

forbid(js,/Array\.isArray\(items\)\?items:\[\]/,'missing collection coerced to empty');
forbid(js,/\bfetch\s*\(/,'raw fetch bypassing KoscheiAuth');
forbid(js,/Authorization/i,'manual bearer header');
forbid(js,/\blocalStorage\b|\bsessionStorage\b/,'secret/browser state persistence');
forbid(js,/\.innerHTML\s*=/,'API-derived innerHTML');
forbid(js,/Math\.random\s*\(/,'synthetic webhook evidence');
forbid(js,/max(?:Value)?\s*\|\|\s*10|max(?:Value)?\s*\?\?\s*10/,'invented endpoint max');
forbid(js,/failure_count\s*\|\|\s*0|failure_count\s*\?\?\s*0/,'invented failure count');
forbid(js,/last_http_status\s*\|\|\s*0|last_http_status\s*\?\?\s*0/,'invented HTTP status');
forbid(js,/\b(?:signMessage|signTransaction|signAllTransactions|signAndSendTransaction|sendTransaction)\b/,'wallet authority');

requireText(css,'.webhook-secret','secret panel styles');
requireText(css,'.webhook-status.bad','dead-letter/failure styles');
requireText(css,'.webhook-error-box','degraded state styles');
requireText(css,'@media(max-width:620px)','mobile webhook layout');
console.log('Enterprise webhooks v2 contract: ok');
