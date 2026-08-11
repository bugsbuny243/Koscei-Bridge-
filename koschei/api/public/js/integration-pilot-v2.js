(()=>{
'use strict';
if(window.__koscheiIntegrationPilotV2)return;
window.__koscheiIntegrationPilotV2=true;

const REQUEST_TIMEOUT_MS=15000;
const $=id=>document.getElementById(id);
const form=$('pilotForm'),notice=$('pilotNotice'),submit=$('pilotSubmit');
let inFlight=false;

function value(id){return String($(id)?.value||'').trim();}
function show(message,bad=false){if(!notice)return;notice.textContent=message;notice.className=`pilot-notice show${bad?' bad':''}`;}
function clear(){if(!notice)return;notice.textContent='';notice.className='pilot-notice';}
function errorMessage(data,status){const code=String(data?.error||'').trim();switch(code){case'rate_limited':return'Too many pilot applications were submitted from this network. Try again later.';case'database_unavailable':return'Pilot intake is temporarily unavailable.';case'invalid_email':return'Enter a valid work email address.';case'invalid_message':return'The integration description is outside the accepted length.';case'invalid_subject':return'The pilot application title could not be accepted.';case'feedback_store_failed':return'Pilot intake could not store the application.';default:return`Pilot application could not be accepted${status?` (HTTP ${status})`:''}.`;}}
function messageOf(fields){return[
  `Project: ${fields.project}`,
  `Role: ${fields.role}`,
  `Integration surface: ${fields.surface}`,
  `Stage: ${fields.stage}`,
  `Expected monthly checks: ${fields.volume}`,
  `Decision point: ${fields.decision}`,
  `Success criteria: ${fields.success}`
].join('\n');}
async function send(payload){const controller=new AbortController(),timer=setTimeout(()=>controller.abort('pilot_timeout'),REQUEST_TIMEOUT_MS);try{const response=await fetch('/api/analytics/event',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload),signal:controller.signal});const data=await response.json().catch(()=>({}));if(!response.ok||data?.ok!==true)throw Object.assign(new Error(errorMessage(data,response.status)),{data,status:response.status});return data;}catch(error){if(error?.name==='AbortError')throw new Error(`Pilot intake did not respond within ${REQUEST_TIMEOUT_MS/1000} seconds.`);throw error;}finally{clearTimeout(timer);}}
form?.addEventListener('submit',async event=>{
  event.preventDefault();if(inFlight)return;clear();
  const fields={project:value('project'),email:value('email'),role:value('role'),surface:value('surface'),stage:value('stage'),volume:value('volume'),decision:value('decision'),success:value('success'),website:value('website')};
  if(!fields.project||!fields.email||!fields.role||!fields.surface||!fields.stage||!fields.volume||fields.decision.length<10||fields.success.length<10){show('Complete every required field so the integration can be evaluated.',true);return;}
  if(fields.email.length>254||!fields.email.includes('@')||/\s/.test(fields.email)){show('Enter a valid work email address.',true);return;}
  const message=messageOf(fields);if(message.length>5000){show('The pilot description is too long for the current intake contract.',true);return;}
  inFlight=true;submit.disabled=true;submit.textContent='Submitting application…';
  try{
    const data=await send({event_name:'customer_feedback',email:fields.email,path:location.pathname,metadata:{category:'suggestion',subject:`Integration pilot — ${fields.project}`.slice(0,160),message,contact_email:fields.email,page_url:location.href,website:fields.website}});
    show(`Pilot application received.${data.feedback_id?` Reference: ${data.feedback_id}`:''}`);form.reset();
  }catch(error){show(error?.message||'Pilot application could not be submitted.',true);}
  finally{inFlight=false;submit.disabled=false;submit.textContent='Submit pilot application';}
});
})();
