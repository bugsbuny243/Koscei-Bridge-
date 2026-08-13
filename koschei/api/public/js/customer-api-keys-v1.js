'use strict';
(()=>{
  if(window.__koscheiCustomerAPIKeysV1)return;
  window.__koscheiCustomerAPIKeysV1=true;
  const $=id=>document.getElementById(id);
  const form=$('apiKeyForm');
  if(!form||!window.KoscheiAuth)return;

  const list=$('apiKeyList');
  const count=$('apiKeyCount');
  const message=$('apiKeyMessage');
  const secretPanel=$('apiKeySecretPanel');
  const secretValue=$('apiKeySecretValue');
  const secretMeta=$('apiKeySecretMeta');
  const copyButton=$('apiKeyCopy');
  const createButton=$('apiKeyCreate');
  const reloadButton=$('apiKeyReload');
  const SECRET_VISIBLE_MS=120000;
  let secretTimer=0;

  const hasValue=value=>value!==null&&value!==undefined&&String(value).trim()!=='';
  const text=(value,fallback='UNAVAILABLE')=>hasValue(value)?String(value).trim():fallback;
  const integerOrNull=value=>{if(value===null||value===undefined||value==='')return null;const parsed=Number(value);return Number.isInteger(parsed)&&parsed>=0?parsed:null;};
  const node=(tag,className,value)=>{const el=document.createElement(tag);if(className)el.className=className;if(value!==undefined)el.textContent=String(value);return el;};
  const clear=host=>{while(host?.firstChild)host.removeChild(host.firstChild);};
  const when=value=>{if(!hasValue(value))return'UNAVAILABLE';const date=new Date(value);return Number.isNaN(date.getTime())?'UNAVAILABLE':date.toLocaleString();};

  function showMessage(value,tone=''){message.textContent=value;message.className=`api-key-message show${tone?` ${tone}`:''}`;}
  function clearSecret(){window.clearTimeout(secretTimer);secretTimer=0;secretValue.textContent='';secretMeta.textContent='';secretPanel.hidden=true;}
  function revealSecret(data){
    clearSecret();
    const key=text(data?.key,''),id=text(data?.id,''),plan=text(data?.plan,''),monthly=integerOrNull(data?.monthly_limit),rpm=integerOrNull(data?.rate_limit_per_minute);
    if(!key||!id||!plan||monthly===null||monthly<=0||rpm===null||rpm<=0){showMessage('The create request returned incomplete credential evidence. A key may have been created, but no raw key is treated as usable unless the one-time response is complete. Reload the list and revoke any unexpected row.','bad');return false;}
    secretValue.textContent=key;
    secretMeta.textContent=`Server effective plan: ${plan.toUpperCase()} · monthly limit: ${monthly} · rate limit: ${rpm}/min`;
    secretPanel.hidden=false;
    secretTimer=window.setTimeout(clearSecret,SECRET_VISIBLE_MS);
    return true;
  }

  async function api(path,options={}){
    const headers={...(options.headers||{})};
    if(options.body!==undefined&&!headers['Content-Type'])headers['Content-Type']='application/json';
    const response=await KoscheiAuth.apiCall(path,{...options,headers});
    const raw=await response.text();let data={};
    if(raw){try{data=JSON.parse(raw);}catch{throw new Error('The credential service returned invalid JSON.');}}
    if(!response.ok){const enterprise=[401,402,403].includes(response.status)?'An active Enterprise SaaS entitlement and verified customer session are required for API-key management. ':'';throw new Error(enterprise+text(data?.message||data?.error,`Credential request failed with HTTP ${response.status}`));}
    return data;
  }

  function statusClass(status){if(status==='active')return'good';if(status==='revoked')return'bad';return'';}
  function metric(label,value){const wrap=node('div','api-key-metric');wrap.append(node('span','',label),node('strong','',value));return wrap;}
  function button(label,action,id,extra=''){const el=node('button',`ops-btn ${extra}`.trim(),label);el.type='button';el.dataset.apiKeyAction=action;el.dataset.apiKeyId=id;return el;}

  function renderKeys(items){
    clear(list);
    if(!Array.isArray(items)){count.textContent='UNAVAILABLE';list.append(node('div','api-key-empty','API-key collection is unavailable. Missing collection evidence is not treated as an empty keyring.'));return;}
    count.textContent=`${items.length} key${items.length===1?'':'s'} returned`;
    if(items.length===0){list.append(node('div','api-key-empty','No API keys are registered for this account.'));return;}
    for(const item of items){
      const id=text(item?.id,''),name=text(item?.name),prefix=text(item?.key_prefix),status=text(item?.status,'unknown').toLowerCase();
      const monthly=integerOrNull(item?.monthly_limit),rpm=integerOrNull(item?.rate_limit_per_minute);
      const card=node('article','api-key-card');const head=node('div','api-key-head');const identity=node('div');
      identity.append(node('span','api-key-kicker','DEVELOPER CREDENTIAL'),node('h3','',name),node('code','',prefix));
      head.append(identity,node('span',`api-key-status ${statusClass(status)}`.trim(),status==='active'||status==='revoked'?status.toUpperCase():'UNAVAILABLE'));
      const metrics=node('div','api-key-metrics');
      metrics.append(metric('Monthly limit',monthly===null?'UNAVAILABLE':monthly),metric('Rate / minute',rpm===null?'UNAVAILABLE':rpm),metric('Created',when(item?.created_at)),metric('Last used',when(item?.last_used_at)));
      card.append(head,metrics);
      if(id&&status==='active'){const actions=node('div','api-key-actions');actions.append(button('Revoke key','revoke',id,'danger'));card.append(actions);}
      list.append(card);
    }
  }

  async function loadKeys(){
    list.setAttribute('aria-busy','true');
    try{
      const data=await api('/api/account/api-keys');
      if(data?.ok!==true||!Array.isArray(data?.api_keys)){renderKeys(null);showMessage('Credential response is incomplete. No key count or empty state was inferred.','bad');return;}
      renderKeys(data.api_keys);
    }catch(error){renderKeys(null);showMessage(error.message,'bad');}
    finally{list.removeAttribute('aria-busy');}
  }

  function optionalPositiveInteger(id,label){const raw=$(id).value.trim();if(raw==='')return undefined;const value=Number(raw);if(!Number.isInteger(value)||value<=0)throw new Error(`${label} must be a positive integer or left blank for the current server default.`);return value;}

  form.addEventListener('submit',async event=>{
    event.preventDefault();
    if(createButton.disabled)return;
    const name=$('apiKeyName').value.trim();if(!name){showMessage('Provide a name so the server does not fall back to a legacy default label.','bad');return;}
    createButton.disabled=true;
    try{
      const monthly=optionalPositiveInteger('apiKeyMonthly','Monthly limit');
      const rpm=optionalPositiveInteger('apiKeyRPM','Rate limit');
      const body={name};if(monthly!==undefined)body.monthly_limit=monthly;if(rpm!==undefined)body.rate_limit_per_minute=rpm;
      const data=await api('/api/account/api-keys',{method:'POST',body:JSON.stringify(body)});
      form.reset();
      if(revealSecret(data))showMessage('API key created. Store the one-time raw key before it disappears; effective limits shown below came from the server.','good');
      await loadKeys();
    }catch(error){showMessage(error.message,'bad');}
    finally{createButton.disabled=false;}
  });

  document.addEventListener('click',async event=>{
    const target=event.target.closest('[data-api-key-action="revoke"][data-api-key-id]');if(!target)return;
    const id=target.dataset.apiKeyId;if(!id||!window.confirm('Revoke this API key? Requests using it will stop authenticating.'))return;
    target.disabled=true;
    try{const data=await api(`/api/account/api-keys/${encodeURIComponent(id)}/revoke`,{method:'POST',body:'{}'});if(data?.ok!==true)throw new Error('The revoke response was incomplete.');showMessage('API key revoked.','good');await loadKeys();}catch(error){showMessage(error.message,'bad');}finally{target.disabled=false;}
  });

  copyButton.addEventListener('click',async()=>{const value=secretValue.textContent;if(!value)return;try{await navigator.clipboard.writeText(value);showMessage('Raw API key copied. It is still removed from this page after two minutes.','good');}catch{showMessage('Clipboard access was unavailable. Copy the raw key manually before it disappears.','bad');}});
  reloadButton.addEventListener('click',loadKeys);

  (async()=>{try{await KoscheiAuth.init();}catch{}if(!KoscheiAuth.requireAuth('/login.html'))return;await loadKeys();})();
})();
