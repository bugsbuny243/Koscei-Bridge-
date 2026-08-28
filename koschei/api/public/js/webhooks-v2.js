'use strict';
(()=>{
  const $=id=>document.getElementById(id);
  const form=$('webhookForm');
  if(!form||!window.KoscheiAuth)return;

  const endpointList=$('webhookEndpoints');
  const deliveryList=$('webhookDeliveries');
  const count=$('webhookCount');
  const notice=$('webhookNotice');
  const secretPanel=$('webhookSecretPanel');
  const secretValue=$('webhookSecretValue');
  const secretTitle=$('webhookSecretTitle');
  const copySecret=$('webhookCopySecret');
  const deliveryStatus=$('deliveryStatus');
  const reload=$('webhookReload');
  const submit=$('webhookCreate');
  const SECRET_VISIBLE_MS=120000;
  let secretTimer=0;

  function hasValue(value){return value!==null&&value!==undefined&&String(value).trim()!=='';}
  function numberOrNull(value){if(value===null||value===undefined||value==='')return null;const n=Number(value);return Number.isFinite(n)?n:null;}
  function text(value,fallback='UNAVAILABLE'){return hasValue(value)?String(value):fallback;}
  function when(value){if(!hasValue(value))return 'UNAVAILABLE';const date=new Date(value);return Number.isNaN(date.getTime())?'UNAVAILABLE':date.toLocaleString();}
  function node(tag,className,value){const el=document.createElement(tag);if(className)el.className=className;if(value!==undefined)el.textContent=String(value);return el;}
  function clear(element){while(element.firstChild)element.removeChild(element.firstChild);}
  function showNotice(message,bad=false){notice.textContent=message;notice.hidden=false;notice.className=`webhook-notice${bad?' bad':''}`;}
  function clearSecret(){window.clearTimeout(secretTimer);secretTimer=0;secretValue.textContent='';secretPanel.hidden=true;}
  function revealSecret(value,title){clearSecret();if(!hasValue(value)){showNotice('The server did not return a plaintext signing secret. Nothing was exposed.',true);return false;}secretTitle.textContent=title;secretValue.textContent=String(value);secretPanel.hidden=false;secretTimer=window.setTimeout(clearSecret,SECRET_VISIBLE_MS);return true;}

  async function api(path,options={}){
    const headers={...(options.headers||{})};
    if(options.body!==undefined&&!headers['Content-Type'])headers['Content-Type']='application/json';
    const response=await KoscheiAuth.apiCall(path,{...options,headers});
    let data={};
    const raw=await response.text();
    if(raw){try{data=JSON.parse(raw);}catch{data={error:'invalid_json_response'};}}
    if(!response.ok){
      const access=[401,402,403].includes(response.status)?'An active Enterprise SaaS subscription and a verified customer session are required. ':'';
      throw new Error(access+text(data?.message||data?.error,`Request failed with HTTP ${response.status}`));
    }
    return data;
  }

  function statusClass(status){const value=String(status||'').toLowerCase();if(value==='active'||value==='delivered')return 'good';if(value==='dead_letter')return 'bad';return 'warn';}
  function actionButton(label,action,id,extraClass=''){const button=node('button',`webhook-btn ${extraClass}`.trim(),label);button.type='button';button.dataset.action=action;button.dataset.id=id;return button;}
  function metric(label,value){const wrap=node('div','webhook-metric');wrap.append(node('span','',label),node('strong','',value));return wrap;}

  function renderEndpoints(items,max){
    clear(endpointList);
    if(!Array.isArray(items)){count.textContent='UNAVAILABLE';endpointList.append(node('div','webhook-error-box','Endpoint list unavailable. No endpoint count or capacity state is inferred.'));return;}
    const endpointItems=items;
    const maxValue=numberOrNull(max);
    count.textContent=`${endpointItems.length} / ${maxValue===null?'UNAVAILABLE':maxValue}`;
    if(endpointItems.length===0){endpointList.append(node('div','webhook-empty','No webhook endpoints are registered for this account.'));return;}
    for(const item of endpointItems){
      const id=text(item?.id,'');
      const status=text(item?.status,'unknown').toLowerCase();
      const failureCount=numberOrNull(item?.failure_count);
      const card=node('article','webhook-card');
      const head=node('div','webhook-card-head');
      const identity=node('div');
      identity.append(node('span','webhook-kicker','ENDPOINT'),node('h3','',text(item?.name)),node('p','webhook-url',text(item?.url)));
      head.append(identity,node('span',`webhook-status ${statusClass(status)}`,status.toUpperCase()));
      const metrics=node('div','webhook-metrics');
      metrics.append(metric('Failures',failureCount===null?'UNAVAILABLE':failureCount),metric('Last success',when(item?.last_success_at)),metric('Secret suffix',hasValue(item?.secret_last4)?`••••${item.secret_last4}`:'UNAVAILABLE'));
      const events=node('div','webhook-events');
      const eventTypes=Array.isArray(item?.event_types)?item.event_types:[];
      if(eventTypes.length){for(const eventType of eventTypes)events.append(node('span','webhook-event',text(eventType)));}
      else events.append(node('span','webhook-event neutral','EVENT TYPES UNAVAILABLE'));
      const actions=node('div','webhook-actions');
      if(id){
        actions.append(actionButton('Queue test','test',id,'primary'));
        if(status==='active'||status==='paused'){
          const toggle=actionButton(status==='active'?'Pause':'Activate','toggle',id);
          toggle.dataset.nextStatus=status==='active'?'paused':'active';
          actions.append(toggle);
        }
        actions.append(actionButton('Rotate secret','rotate',id));
        actions.append(actionButton('Delete','delete',id,'danger'));
      }
      card.append(head,metrics,events,actions);endpointList.append(card);
    }
  }

  function renderDeliveries(items){
    clear(deliveryList);
    if(!Array.isArray(items)){deliveryList.append(node('div','webhook-error-box','Delivery list unavailable. Missing collection evidence is not treated as an empty or delivered queue.'));return;}
    const deliveries=items;
    if(deliveries.length===0){deliveryList.append(node('div','webhook-empty','No deliveries match this filter.'));return;}
    for(const item of deliveries){
      const id=text(item?.id,'');
      const status=text(item?.status,'unknown').toLowerCase();
      const attempts=numberOrNull(item?.attempt_count);
      const maxAttempts=numberOrNull(item?.max_attempts);
      const httpStatus=numberOrNull(item?.last_http_status);
      const card=node('article','webhook-delivery');
      const head=node('div','webhook-delivery-head');
      const identity=node('div');
      identity.append(node('span','webhook-kicker','DELIVERY'),node('code','',text(item?.event_type)),node('p','webhook-url',`${text(item?.endpoint_name)} · ${id||'ID UNAVAILABLE'}`));
      head.append(identity,node('span',`webhook-status ${statusClass(status)}`,status.toUpperCase()));
      const metrics=node('div','webhook-metrics');
      metrics.append(metric('Attempts',attempts===null||maxAttempts===null?'UNAVAILABLE':`${attempts}/${maxAttempts}`),metric('HTTP',httpStatus===null?'UNAVAILABLE':httpStatus),metric('Created',when(item?.created_at)));
      card.append(head,metrics);
      if(hasValue(item?.last_error))card.append(node('p','webhook-error',item.last_error));
      if(status==='dead_letter'&&id){const actions=node('div','webhook-actions');actions.append(actionButton('Requeue dead letter','retry',id,'primary'));card.append(actions);}
      deliveryList.append(card);
    }
  }

  async function load(){
    endpointList.setAttribute('aria-busy','true');deliveryList.setAttribute('aria-busy','true');
    try{
      const filter=deliveryStatus.value;
      const [endpointData,deliveryData]=await Promise.all([
        api('/api/webhooks'),
        api('/api/webhooks/deliveries'+(filter?`?status=${encodeURIComponent(filter)}`:''))
      ]);
      renderEndpoints(endpointData?.endpoints,endpointData?.max_endpoints);
      renderDeliveries(deliveryData?.deliveries);
    }catch(error){
      clear(endpointList);clear(deliveryList);
      endpointList.append(node('div','webhook-error-box','Endpoint state unavailable. No capacity or health value is inferred.'));
      deliveryList.append(node('div','webhook-error-box','Delivery state unavailable. A missing delivery response is not treated as delivered.'));
      count.textContent='UNAVAILABLE';showNotice(error.message,true);
    }finally{endpointList.removeAttribute('aria-busy');deliveryList.removeAttribute('aria-busy');}
  }

  async function perform(action,id,nextStatus){
    if(!id)return;
    if(action==='delete'&&!window.confirm('Delete this webhook endpoint? Existing delivery history may remain as evidence.'))return;
    try{
      if(action==='test'){const data=await api(`/api/webhooks/${id}/test`,{method:'POST',body:'{}'});showNotice(`Test queued${hasValue(data?.delivery_id)?` · delivery ${data.delivery_id}`:''}.`);}
      if(action==='toggle'){if(nextStatus!=='active'&&nextStatus!=='paused')throw new Error('Endpoint status is unavailable; no state change was sent.');await api(`/api/webhooks/${id}`,{method:'PATCH',body:JSON.stringify({status:nextStatus})});showNotice(`Endpoint ${nextStatus}.`);}
      if(action==='rotate'){const data=await api(`/api/webhooks/${id}/rotate-secret`,{method:'POST',body:'{}'});revealSecret(data?.secret,'Signing secret rotated');}
      if(action==='delete'){await api(`/api/webhooks/${id}`,{method:'DELETE'});showNotice('Endpoint deleted.');clearSecret();}
      if(action==='retry'){await api(`/api/webhooks/deliveries/${id}/retry`,{method:'POST',body:'{}'});showNotice('Dead-letter delivery requeued.');}
      await load();
    }catch(error){showNotice(error.message,true);}
  }

  document.addEventListener('click',event=>{const button=event.target.closest('[data-action][data-id]');if(!button)return;perform(button.dataset.action,button.dataset.id,button.dataset.nextStatus);});
  form.addEventListener('submit',async event=>{event.preventDefault();const name=$('webhookName').value.trim();const url=$('webhookUrl').value.trim();if(!name||!url)return;submit.disabled=true;try{const data=await api('/api/webhooks',{method:'POST',body:JSON.stringify({name,url})});form.reset();if(revealSecret(data?.secret,'Webhook created'))showNotice('Endpoint created. Store the one-time signing secret before it disappears.');await load();}catch(error){showNotice(error.message,true);}finally{submit.disabled=false;}});
  copySecret.addEventListener('click',async()=>{const value=secretValue.textContent;if(!value)return;try{await navigator.clipboard.writeText(value);showNotice('Signing secret copied. It is still removed from this page after two minutes.');}catch{showNotice('Clipboard access was unavailable. Copy the secret manually before it disappears.',true);}});
  deliveryStatus.addEventListener('change',load);reload.addEventListener('click',load);

  (async()=>{await KoscheiAuth.init();if(!KoscheiAuth.requireAuth('/login.html'))return;await load();})();
})();
