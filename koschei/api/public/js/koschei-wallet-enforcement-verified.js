(function(root,factory){
  let enforcement=root.KoscheiWalletEnforcement;
  let verifier=root.KoscheiEnforcementPermitVerifier;
  let trustAnchor=root.KoscheiEnforcementTrustAnchor;
  if(typeof module==='object'&&module.exports){
    enforcement=require('./koschei-wallet-enforcement.js');
    verifier=require('./koschei-enforcement-permit-verifier.js');
    trustAnchor=require('./koschei-enforcement-trust-anchor.js');
  }
  const api=factory(root,enforcement,verifier,trustAnchor);
  if(typeof module==='object'&&module.exports)module.exports=api;
  root.KoscheiVerifiedWalletEnforcement=api;
})(typeof globalThis!=='undefined'?globalThis:this,function(root,enforcement,verifier,trustAnchor){
  'use strict';

  const VERSION='koschei-verified-wallet-enforcement-v2';

  function asString(value){return String(value??'').trim()}
  function normalizeAction(value){return asString(value).toLowerCase()}
  function normalizeOrigin(value){return asString(value).replace(/\/+$/,'').toLowerCase()}

  function assertDependencies(){
    if(!enforcement||typeof enforcement.createGuardedWallet!=='function'){
      throw new Error('KoscheiWalletEnforcement must be loaded before verified enforcement.');
    }
    if(!verifier||typeof verifier.verifyPermit!=='function'){
      throw new Error('KoscheiEnforcementPermitVerifier must be loaded before verified enforcement.');
    }
  }

  function withTrustedDefaults(options){
    const config=Object.assign({},options||{});
    const customTrust=Boolean(config.pinnedKeys||config.pinnedKey||config.keyResolver);
    if(!customTrust&&trustAnchor?.PINNED_KEYS&&trustAnchor?.CURRENT_KEY_ID){
      config.pinnedKeys=trustAnchor.PINNED_KEYS;
      config.expectedKeyID=asString(config.expectedKeyID||trustAnchor.CURRENT_KEY_ID);
    }
    if(!config.pinnedKeys&&!config.pinnedKey&&!config.keyResolver){
      const ErrorType=verifier?.PermitVerificationError||Error;
      throw new ErrorType(
        'permit_trust_anchor_missing',
        'No out-of-band Koschei enforcement trust anchor is configured.'
      );
    }
    return config;
  }

  function cloneResponse(body,response){
    return{
      ok:Boolean(response?.ok),
      status:Number(response?.status||0),
      statusText:asString(response?.statusText),
      headers:response?.headers,
      url:response?.url,
      redirected:Boolean(response?.redirected),
      type:response?.type,
      async json(){return body},
      async text(){return JSON.stringify(body)}
    };
  }

  function expectedPermitContext(request,assessment,origin){
    const signedIntent=assessment?.signed_ui_intent||{};
    return{
      transactionFingerprint:asString(assessment?.transaction_fingerprint||request?.transaction_fingerprint),
      wallet:asString(assessment?.wallet||request?.wallet),
      network:asString(assessment?.network||request?.network),
      origin:normalizeOrigin(signedIntent?.complete?signedIntent?.ui_origin:origin),
      action:normalizeAction(assessment?.action),
      riskLevel:asString(assessment?.risk_level),
      riskIndex:Number(assessment?.risk_index||0),
      requestID:asString(assessment?.request_id),
      guardVersion:asString(assessment?.guard_version),
      analysisVersion:asString(assessment?.analysis_version),
      signedUIIntentID:signedIntent?.complete?asString(signedIntent?.intent_id):'',
      uiSummaryHash:signedIntent?.complete?asString(signedIntent?.ui_summary_hash):'',
      assessment
    };
  }

  function createPermitVerifiedFetch(options){
    assertDependencies();
    const config=withTrustedDefaults(options);
    const underlying=config.fetch||root.fetch;
    if(typeof underlying!=='function')throw new Error('A fetch implementation is required.');
    return async function permitVerifiedFetch(url,fetchOptions){
      const response=await underlying(url,fetchOptions);
      let body;
      try{
        body=await response.json();
      }catch(error){
        throw new verifier.PermitVerificationError('guard_response_unreadable','Guard response could not be parsed before permit verification.',{cause:error});
      }
      const action=normalizeAction(body?.action);
      if(action==='allow'||action==='warn'){
        let request={};
        try{request=JSON.parse(asString(fetchOptions?.body)||'{}')}catch(_error){request={}}
        const origin=normalizeOrigin(
          config.origin||
          request?.signed_intent?.ui_origin||
          fetchOptions?.headers?.Origin||
          fetchOptions?.headers?.origin||
          root.location?.origin
        );
        if(body?.guard_complete!==true){
          throw new verifier.PermitVerificationError('guard_incomplete','Guard returned an issuable action without complete evidence.');
        }
        if(body?.enforcement_permit_issued!==true||body?.enforcement_permit_complete!==true){
          throw new verifier.PermitVerificationError('permit_missing','Guard returned ALLOW/WARN without a complete enforcement permit.');
        }
        const verification=await verifier.verifyPermit(
          body.enforcement_permit,
          expectedPermitContext(request,body,origin),
          {
            pinnedKeys:config.pinnedKeys,
            pinnedKey:config.pinnedKey,
            expectedKeyID:config.expectedKeyID,
            keyResolver:config.keyResolver,
            clockSkewMs:config.clockSkewMs,
            nowMs:typeof config.nowProvider==='function'?config.nowProvider():config.nowMs
          }
        );
        Object.defineProperty(body,'_koscheiPermitVerification',{
          value:verification,
          enumerable:false,
          configurable:false,
          writable:false
        });
        if(typeof config.onPermitVerified==='function')await config.onPermitVerified({verification,assessment:body,request});
      }
      return cloneResponse(body,response);
    };
  }

  function createPermitVerifiedWallet(wallet,options){
    assertDependencies();
    const config=withTrustedDefaults(options);
    config.fetch=createPermitVerifiedFetch(config);
    return enforcement.createGuardedWallet(wallet,config);
  }

  return{
    VERSION,
    TRUST_ANCHOR_VERSION:trustAnchor?.VERSION||'',
    CURRENT_KEY_ID:trustAnchor?.CURRENT_KEY_ID||'',
    createPermitVerifiedFetch,
    createPermitVerifiedWallet,
    PermitVerificationError:verifier?.PermitVerificationError,
    verifyPermit:verifier?.verifyPermit
  };
});
