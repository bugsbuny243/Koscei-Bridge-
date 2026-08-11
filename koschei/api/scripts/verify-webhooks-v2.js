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
requireText(html,'Delivery transports an existing deterministic result','verdict authority boundary');
requireText(html,'id="webhookSecretPanel"','one-time secret panel');
requireText(html,'id="deliveryStatus"','delivery filter');
for(const status of ['pending','retry','delivered','dead_letter'])requireText(html,`value="${status}"`,`delivery filter ${status}`);
requireText(html,'/kosch','canonical KOSCH route');
requireText(html,'/js/koschei-auth.js?v=33','frozen auth client');
requireText(html,'/js/webhooks-v2.js?v=1','external webhook controller');
if(html.includes('/kosch-access'))throw new Error('webhooks must not advertise legacy kosch-access');
forbid(html,/<script(?![^>]*\bsrc=)[^>]*>/i,'inline runtime script');
forbid(html,/\son[a-z]+\s*=/i,'inline event handler');

requireText(routes,'enterprise := h.RequireEnterpriseEligibility','Enterprise webhook middleware');
requireText(routes,'mux.HandleFunc("/api/webhooks", enterprise','Enterprise webhook management route');
requireText(routes,'mux.HandleFunc("/api/webhooks/", enterprise','Enterprise webhook action route');
requireText(routes,'mux.HandleFunc("/api/webhooks/deliveries", enterprise','Enterprise delivery list route');
requireText(routes,'mux.HandleFunc("/api/webhooks/deliveries/", enterprise','Enterprise delivery action route');

requireText(handler,'webhookEndpointLimit','server endpoint limit function');
requireText(handler,'"max_endpoints"','server max endpoint response');
requireText(handler,'SecretLast4','list-only secret suffix field');
requireText(handler,'webhooks.GenerateSecret()','one-time secret generation');
requireText(handler,'webhooks.HashSecret','stored secret hash');
requireText(handler,'"webhook.test"','queued webhook test event');
requireText(handler,'"pending", "retry", "delivered", "dead_letter"','delivery status filter contract');
requireText(handler,'status != "dead_letter"','dead-letter-only retry guard');

requireText(worker,'X-Koschei-Signature','delivery signature header');
requireText(worker,'HMAC','HMAC delivery signing');
requireText(docs,'dead_letter','documented dead-letter state');
requireText(docs,'retry','documented retry state');

requireText(js,"KoscheiAuth.apiCall('/api/webhooks'",'authenticated endpoint list/create contract');
requireText(js,"api('/api/webhooks/deliveries",'authenticated delivery list contract');
requireText(js,"/rotate-secret`",'rotate-secret action');
requireText(js,"/test`",'queued test action');
requireText(js,"/retry`",'dead-letter retry action');
requireText(js,"max===null?'UNAVAILABLE':max",'missing endpoint-limit boundary');
requireText(js,"failureCount===null?'UNAVAILABLE'",'missing failure-count boundary');
requireText(js,"httpStatus===null?'UNAVAILABLE'",'missing HTTP-status boundary');
requireText(js,'SECRET_VISIBLE_MS=120000','bounded plaintext secret visibility');
requireText(js,'secretPanel.hidden=true','secret removal from visible DOM');
requireText(js,"revealSecret(data?.secret,'Webhook created')",'create one-time secret response');
requireText(js,"revealSecret(data?.secret,'Signing secret rotated')",'rotate one-time secret response');
requireText(js,"status==='dead_letter'&&id",'retry button only for dead-letter');
requireText(js,"JSON.stringify({name,url})",'server-owned event subscription defaults');

forbid(js,/\bfetch\s*\(/,'raw fetch bypassing KoscheiAuth');
forbid(js,/Authorization/i,'manual bearer header');
forbid(js,/\blocalStorage\b|\bsessionStorage\b/,'secret/browser state persistence');
forbid(js,/\.innerHTML\s*=/,'API-derived innerHTML');
forbid(js,/Math\.random\s*\(/,'synthetic webhook evidence');
forbid(js,/max\s*\|\|\s*10|max\s*\?\?\s*10/,'invented endpoint max');
forbid(js,/failure_count\s*\|\|\s*0|failure_count\s*\?\?\s*0/,'invented failure count');
forbid(js,/\b(?:signMessage|signTransaction|signAllTransactions|signAndSendTransaction|sendTransaction)\b/,'wallet authority');

requireText(css,'.webhook-secret','secret panel styles');
requireText(css,'.webhook-status.bad','dead-letter/failure styles');
requireText(css,'.webhook-error-box','degraded state styles');
requireText(css,'@media(max-width:620px)','mobile webhook layout');
console.log('Enterprise webhooks v2 contract: ok');
