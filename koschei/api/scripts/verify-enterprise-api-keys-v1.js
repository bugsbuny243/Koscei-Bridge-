'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','account.html'),'utf8');
const js=fs.readFileSync(path.join(root,'public','js','customer-api-keys-v1.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','customer-api-keys-v1.css'),'utf8');
const server=fs.readFileSync(path.join(root,'internal','http','server.go'),'utf8');
const handler=fs.readFileSync(path.join(root,'internal','handlers','api_keys.go'),'utf8');
const caps=fs.readFileSync(path.join(root,'internal','handlers','api_key_tier_caps.go'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden pattern ${pattern}`);}

requireText(html,'ENTERPRISE DEVELOPER CREDENTIALS','Enterprise credential section');
requireText(html,'API-key management requires Enterprise KOSCH eligibility','Enterprise credential boundary');
requireText(html,'Requested limits are only requests; the server applies its current tier defaults and caps','server-owned cap copy');
requireText(html,'Raw keys are returned only at creation','one-time raw-key copy');
requireText(html,'id="apiKeySecretPanel" hidden','hidden one-time key panel');
requireText(html,'id="apiKeyCount">UNAVAILABLE','unknown initial key count');
requireText(html,'/css/customer-api-keys-v1.css?v=1','credential stylesheet');
requireText(html,'/js/customer-api-keys-v1.js?v=1','credential controller');
requireText(html,'Never ship it in browser JavaScript','server-side secret guidance');
forbid(html,/<script(?![^>]*\bsrc=)[^>]*>/i,'inline runtime script');
forbid(html,/\son[a-z]+\s*=/i,'inline event handler');

requireText(server,'mux.HandleFunc("/api/account/api-keys", requiresDB(h, koschTierAccess("enterprise", h.APIKeysCollection)))','Enterprise credential collection route');
requireText(server,'mux.HandleFunc("/api/account/api-keys/", requiresDB(h, koschTierAccess("enterprise", method("POST", h.RevokeAPIKey))))','Enterprise credential revoke route');

requireText(handler,'func (h *Handler) APIKeysCollection','credential collection handler');
requireText(handler,'case http.MethodGet:','credential GET collection');
requireText(handler,'h.ListAPIKeys(w, r)','credential list dispatch');
requireText(handler,'case http.MethodPost:','credential POST collection');
requireText(handler,'h.CreateAPIKey(w, r)','credential create dispatch');
requireText(handler,'raw, err := newRawAPIKey()','raw credential generation');
requireText(handler,'hash := hashAPIKey(raw)','raw credential hashing');
requireText(handler,'INSERT INTO api_keys (auth_subject,email,name,key_prefix,key_hash','hashed credential storage');
requireText(handler,'"key":                   raw','one-time raw credential response');
requireText(handler,'SELECT id::text,name,key_prefix,status,monthly_limit,rate_limit_per_minute,created_at,last_used_at,revoked_at FROM api_keys','prefix-only list query');
requireText(handler,'"api_keys": items','credential list envelope');
requireText(handler,"UPDATE api_keys SET status='revoked', revoked_at=now() WHERE id=$1 AND auth_subject=$2 AND status='active'",'active-only revoke');
requireText(handler,'"ok": true, "message": "API anahtarı iptal edildi."','authoritative revoke ok response');
requireText(handler,'effectiveMonthly, effectiveRPM := clampAPIKeyLimits(requestedMonthly, requestedRPM, caps)','create-time requested-limit clamp invocation');

requireText(caps,'apiKeyCapsByTier','server-owned credential cap map');
requireText(caps,'func clampAPIKeyLimits(requestedMonthly, requestedRPM int, caps apiKeyTierCaps) (int, int)','server-side clamp definition');
requireText(caps,'if monthly > caps.MaxMonthly','monthly cap enforcement');
requireText(caps,'if rpm > caps.MaxRPM','RPM cap enforcement');

requireText(js,'KoscheiAuth.apiCall(path','shared customer-session client');
requireText(js,"api('/api/account/api-keys')",'credential list source');
requireText(js,"api('/api/account/api-keys',{method:'POST'",'credential create source');
requireText(js,'/api/account/api-keys/${encodeURIComponent(id)}/revoke','credential revoke source');
requireText(js,'const SECRET_VISIBLE_MS=120000','bounded one-time raw-key visibility');
requireText(js,"secretValue.textContent=''",'raw key DOM removal');
requireText(js,"if(!Array.isArray(items)){count.textContent='UNAVAILABLE'",'missing credential collection boundary');
requireText(js,"data?.ok!==true||!Array.isArray(data?.api_keys)",'list envelope completeness boundary');
requireText(js,"if(!key||!id||!tier||monthly===null||monthly<=0||rpm===null||rpm<=0)",'create response completeness boundary');
requireText(js,'Server effective tier: ${tier.toUpperCase()}','server-returned effective tier display');
requireText(js,"if(id&&status==='active')",'active-only revoke UI');
requireText(js,"status==='active'||status==='revoked'?status.toUpperCase():'UNAVAILABLE'",'unknown status boundary');
requireText(js,"optionalPositiveInteger('apiKeyMonthly'",'optional requested monthly limit');
requireText(js,"optionalPositiveInteger('apiKeyRPM'",'optional requested RPM');
requireText(js,"data?.ok!==true)throw new Error('The revoke response was incomplete.')",'revoke response completeness');
requireText(js,"KoscheiAuth.requireAuth('/login.html')",'canonical login continuation');

forbid(js,/\bfetch\s*\(/,'raw fetch bypassing KoscheiAuth');
forbid(js,/Authorization/i,'manual bearer header');
forbid(js,/X-API-Key/i,'management controller must not authenticate itself with a developer credential');
forbid(js,/\blocalStorage\b|\bsessionStorage\b/,'raw credential browser persistence');
forbid(js,/\.innerHTML\s*=/,'API-derived innerHTML');
forbid(js,/Math\.random\s*\(/,'synthetic credential evidence');
forbid(js,/\b(?:signMessage|signTransaction|signAllTransactions|signAndSendTransaction|sendTransaction)\b/,'wallet authority in credential controller');

for(const cap of ['1000','20000','200000','30','120','600']){
  const pattern=new RegExp(`\\b${cap}\\b`);
  if(pattern.test(html)||pattern.test(js))throw new Error(`credential UI must not hardcode server cap: ${cap}`);
}

requireText(css,'.api-key-secret','one-time raw-key styles');
requireText(css,'.api-key-status.bad','revoked/failed credential styles');
requireText(css,'@media(max-width:520px)','mobile credential layout');
console.log('Enterprise credential lifecycle contract: ok');
