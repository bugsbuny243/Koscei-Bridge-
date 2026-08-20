(function(){
  'use strict';

  var state=document.getElementById('state');
  function setState(message,kind){
    if(!state)return;
    state.textContent=message;
    state.className='checkout-state'+(kind?' '+kind:'');
  }

  async function readJSON(response){
    var text=await response.text().catch(function(){return '';});
    if(!text)return {};
    try{return JSON.parse(text);}catch(_){return {};}
  }

  async function boot(){
    try{
      var response=await fetch('/paddle/public-config',{credentials:'same-origin',cache:'no-store'});
      var config=await readJSON(response);
      if(!response.ok||!config.ok){
        var missing=config&&config.paddle&&Array.isArray(config.paddle.missing_fields)?config.paddle.missing_fields:[];
        throw new Error(missing.length?'Billing setup is incomplete: '+missing.join(', '):'Secure checkout is not ready yet.');
      }
      if(!config.client_token)throw new Error('Paddle client token is unavailable.');
      if(!window.Paddle||typeof window.Paddle.Initialize!=='function')throw new Error('Paddle.js could not be loaded.');

      if(config.environment==='sandbox'&&window.Paddle.Environment&&typeof window.Paddle.Environment.set==='function'){
        window.Paddle.Environment.set('sandbox');
      }

      window.Paddle.Initialize({
        token:config.client_token,
        checkout:{settings:{
          displayMode:'overlay',
          theme:'dark',
          locale:'en',
          allowLogout:false,
          successUrl:config.success_url||'/account?payment=paddle_success'
        }},
        eventCallback:function(event){
          if(event&&event.name==='checkout.completed'){
            setState('Payment completed. Your Koschei entitlement is being activated after signed webhook verification.','good');
          }else if(event&&event.name==='checkout.closed'){
            setState('Checkout closed. You can return to Pricing when you are ready.','warn');
          }
        }
      });

      var params=new URLSearchParams(window.location.search);
      var transactionID=params.get('_ptxn')||params.get('transaction_id');
      if(params.get('_ptxn')){
        setState('Secure Paddle checkout is opening…');
        return;
      }
      if(transactionID&&window.Paddle.Checkout&&typeof window.Paddle.Checkout.open==='function'){
        setState('Secure Paddle checkout is opening…');
        window.Paddle.Checkout.open({transactionId:transactionID});
        return;
      }
      setState('Checkout is ready. Choose a plan on the Pricing page to begin.');
    }catch(error){
      setState(error&&error.message?error.message:'Paddle checkout could not be initialized.','bad');
    }
  }

  boot();
})();
