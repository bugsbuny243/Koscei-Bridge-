(()=>{
'use strict';
if(window.__koscheiEarlyAccessV1)return;
window.__koscheiEarlyAccessV1=true;

const form=document.getElementById('earlyAccessForm');
if(!form)return;
const email=document.getElementById('earlyAccessEmail');
const useCase=document.getElementById('earlyAccessUseCase');
const website=document.getElementById('earlyAccessWebsite');
const submit=document.getElementById('earlyAccessSubmit');
const status=document.getElementById('earlyAccessStatus');

function show(message,bad=false){
  if(!status)return;
  status.hidden=false;
  status.textContent=message;
  status.dataset.tone=bad?'bad':'good';
}

form.addEventListener('submit',async event=>{
  event.preventDefault();
  const contact=String(email?.value||'').trim();
  const context=String(useCase?.value||'').trim();
  if(!contact||context.length<10){show('Add a valid email and a short description of how you plan to use Koschei.',true);return;}
  submit.disabled=true;
  show('Submitting your early access request…');
  try{
    const response=await fetch('/api/analytics/event',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({
        event_name:'customer_feedback',
        email:contact,
        path:location.href,
        metadata:{
          category:'other',
          subject:'Koschei Web3 early access request',
          message:context,
          website:String(website?.value||'')
        }
      })
    });
    const data=await response.json().catch(()=>({}));
    if(!response.ok||data?.ok!==true)throw new Error('Early access request could not be recorded.');
    form.reset();
    show('Request received. No payment was taken.');
  }catch(error){
    show(error?.message||'Early access request is unavailable right now.',true);
  }finally{
    submit.disabled=false;
  }
});
})();
