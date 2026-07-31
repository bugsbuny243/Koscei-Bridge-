(function(root,factory){
  const api=factory(root);
  if(typeof module==='object'&&module.exports)module.exports=api;
  root.KoscheiWalletEnforcement=api;
})(typeof globalThis!=='undefined'?globalThis:this,function(root){
  'use strict';

  const VERSION='koschei-wallet-enforcement-v1';
  const DEFAULT_ENDPOINT='/api/v1/shield/transaction';
  const DEFAULT_NETWORK='solana-mainnet';
  const DEFAULT_TIMEOUT_MS=25000;
  const DEFAULT_DECISION_AGE_MS=30000;
  const DEFAULT_INTENT_TTL_MS=5*60*1000;

  class KoscheiEnforcementError extends Error{
    constructor(code,message,details){
      super(message||code);
      this.name='KoscheiEnforcementError';
      this.code=code;
      this.action=details?.action||'withhold';
      this.assessment=details?.assessment||null;
      this.transactionFingerprint=details?.transactionFingerprint||'';
      this.cause=details?.cause;
    }
  }

  class KoscheiBlockedError extends KoscheiEnforcementError{
    constructor(message,details){super('koschei_transaction_blocked',message||'Koschei blocked this transaction.',details);this.name='KoscheiBlockedError'}
  }

  class KoscheiWithheldError extends KoscheiEnforcementError{
    constructor(message,details){super('koschei_decision_withheld',message||'Koschei withheld a safe signing decision.',details);this.name='KoscheiWithheldError'}
  }

  const asString=value=>String(value??'').trim();
  const normalizeOrigin=value=>asString(value).replace(/\/+$/,'').toLowerCase();
  const normalizeAction=value=>asString(value).toLowerCase();
  const encoder=()=>{
    if(typeof root.TextEncoder==='function')return new root.TextEncoder();
    if(typeof TextEncoder==='function')return new TextEncoder();
    throw new KoscheiEnforcementError('text_encoder_unavailable','TextEncoder is required for Koschei enforcement.');
  };

  function cryptoProvider(){
    const provider=root.crypto||globalThis.crypto;
    if(!provider?.subtle)throw new KoscheiEnforcementError('web_crypto_unavailable','Web Crypto SHA-256 support is required.');
    return provider;
  }

  function randomID(prefix){
    const crypto=cryptoProvider();
    if(typeof crypto.randomUUID==='function')return `${prefix}-${crypto.randomUUID()}`;
    const bytes=new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return `${prefix}-${Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('')}`;
  }

  function toUint8Array(value){
    if(value instanceof Uint8Array)return new Uint8Array(value);
    if(value instanceof ArrayBuffer)return new Uint8Array(value.slice(0));
    if(ArrayBuffer.isView(value))return new Uint8Array(value.buffer.slice(value.byteOffset,value.byteOffset+value.byteLength));
    if(Array.isArray(value))return Uint8Array.from(value);
    throw new KoscheiEnforcementError('transaction_serialization_invalid','Transaction serialization did not return bytes.');
  }

  function bytesEqual(left,right){
    const a=toUint8Array(left),b=toUint8Array(right);
    if(a.length!==b.length)return false;
    let diff=0;
    for(let index=0;index<a.length;index++)diff|=a[index]^b[index];
    return diff===0;
  }

  function bytesToBase64(bytes){
    const value=toUint8Array(bytes);
    if(typeof Buffer!=='undefined')return Buffer.from(value).toString('base64');
    let binary='';
    const chunk=0x8000;
    for(let index=0;index<value.length;index+=chunk){
      binary+=String.fromCharCode.apply(null,value.subarray(index,index+chunk));
    }
    if(typeof root.btoa!=='function')throw new KoscheiEnforcementError('base64_encoder_unavailable','A base64 encoder is required.');
    return root.btoa(binary);
  }

  async function sha256Hex(value){
    const bytes=typeof value==='string'?encoder().encode(value):toUint8Array(value);
    const digest=await cryptoProvider().subtle.digest('SHA-256',bytes);
    return Array.from(new Uint8Array(digest),item=>item.toString(16).padStart(2,'0')).join('');
  }

  async function transactionFingerprintFromBase64(base64){
    const hash=await sha256Hex(asString(base64));
    return `txf_${hash.slice(0,32)}`;
  }

  function serializeTransaction(transaction){
    if(!transaction||typeof transaction.serialize!=='function'){
      throw new KoscheiEnforcementError('transaction_serializer_missing','Transaction must expose serialize().');
    }
    let serialized;
    try{
      serialized=transaction.serialize({requireAllSignatures:false,verifySignatures:false});
    }catch(firstError){
      try{serialized=transaction.serialize()}catch(secondError){
        throw new KoscheiEnforcementError('transaction_serialization_failed','Transaction could not be serialized.',{cause:secondError||firstError});
      }
    }
    return toUint8Array(serialized);
  }

  function serializeMessage(transaction){
    if(transaction&&typeof transaction.serializeMessage==='function')return toUint8Array(transaction.serializeMessage());
    if(transaction?.message&&typeof transaction.message.serialize==='function')return toUint8Array(transaction.message.serialize());
    return null;
  }

  function walletAddress(wallet,configured){
    const explicit=asString(configured);
    if(explicit)return explicit;
    const key=wallet?.publicKey;
    if(!key)return '';
    if(typeof key.toBase58==='function')return asString(key.toBase58());
    if(typeof key.toString==='function')return asString(key.toString());
    return asString(key);
  }

  function normalizeAccount(account){
    const source=account||{};
    const normalized={address:asString(source.address),role:asString(source.role).toLowerCase()};
    const mint=asString(source.mint);
    if(mint)normalized.mint=mint;
    if(source.decimals!==undefined&&source.decimals!==null)normalized.decimals=Number(source.decimals);
    const maximum=asString(source.maximum_spend_raw);
    const minimum=asString(source.minimum_receive_raw);
    const quoted=asString(source.quoted_receive_raw);
    if(maximum)normalized.maximum_spend_raw=maximum;
    if(minimum)normalized.minimum_receive_raw=minimum;
    if(quoted)normalized.quoted_receive_raw=quoted;
    const slippage=Number(source.max_slippage_bps||0);
    if(slippage)normalized.max_slippage_bps=slippage;
    return normalized;
  }

  function normalizePolicy(policy){
    const source=policy||{};
    const stringList=value=>Array.from(new Set((Array.isArray(value)?value:[]).map(asString).filter(Boolean))).sort();
    const accounts=(Array.isArray(source.accounts)?source.accounts:[]).map(normalizeAccount).sort((left,right)=>{
      const a=`${left.address}|${left.role}|${left.mint||''}`;
      const b=`${right.address}|${right.role}|${right.mint||''}`;
      return a.localeCompare(b);
    });
    return{
      expected_programs:stringList(source.expected_programs),
      required_programs:stringList(source.required_programs),
      blocked_programs:stringList(source.blocked_programs),
      accounts
    };
  }

  function canonicalJSONString(value){
    if(value===null||typeof value!=='object')return JSON.stringify(value);
    if(Array.isArray(value))return `[${value.map(canonicalJSONString).join(',')}]`;
    return `{${Object.keys(value).sort().map(key=>`${JSON.stringify(key)}:${canonicalJSONString(value[key])}`).join(',')}}`;
  }

  function signatureBytes(value){
    if(value?.signature!==undefined)return toUint8Array(value.signature);
    return toUint8Array(value);
  }

  async function createSignedIntent(wallet,details,config){
    if(typeof wallet?.signMessage!=='function'){
      throw new KoscheiWithheldError('The connected wallet cannot sign the required UI intent.',{transactionFingerprint:details.transactionFingerprint});
    }
    const issued=new Date();
    const ttl=Math.min(Math.max(Number(config.intentTTLms||DEFAULT_INTENT_TTL_MS),1000),30*60*1000);
    const expires=new Date(issued.getTime()+ttl);
    const uiOrigin=normalizeOrigin(config.uiOrigin||root.location?.origin);
    if(!uiOrigin)throw new KoscheiWithheldError('A UI origin is required for signed intent binding.',{transactionFingerprint:details.transactionFingerprint});
    const uiSummary=details.uiSummary;
    if(uiSummary===undefined||uiSummary===null||uiSummary===''){
      throw new KoscheiWithheldError('A human-visible UI summary is required for signed intent binding.',{transactionFingerprint:details.transactionFingerprint});
    }
    const uiSummaryHash=await sha256Hex(typeof uiSummary==='string'?uiSummary:canonicalJSONString(uiSummary));
    const policy=details.policy;
    const payload={
      version:'koschei-ui-intent-v1',
      intent_id:randomID('intent'),
      nonce:randomID('nonce'),
      issued_at:issued.toISOString().replace('.000Z','Z'),
      expires_at:expires.toISOString().replace('.000Z','Z'),
      network:details.network,
      wallet:details.walletAddress,
      transaction_fingerprint:details.transactionFingerprint,
      ui_origin:uiOrigin,
      ui_summary_hash:uiSummaryHash,
      expected_programs:policy.expected_programs,
      required_programs:policy.required_programs,
      blocked_programs:policy.blocked_programs,
      accounts:policy.accounts,
      signer:details.walletAddress
    };
    const canonical=JSON.stringify(payload);
    const signed=await wallet.signMessage(encoder().encode(canonical));
    return Object.assign({},payload,{signature:bytesToBase64(signatureBytes(signed))});
  }

  async function resolveHeaders(config,context){
    const headers={'Content-Type':'application/json','Accept':'application/json'};
    if(config.apiKey)headers['X-API-Key']=asString(config.apiKey);
    if(typeof config.headersProvider==='function'){
      const provided=await config.headersProvider(context);
      Object.entries(provided||{}).forEach(([key,value])=>{if(value!==undefined&&value!==null)headers[key]=String(value)});
    }
    return headers;
  }

  function linkedAbortController(externalSignal,timeoutMs){
    const controller=new AbortController();
    const abort=()=>controller.abort(externalSignal?.reason);
    if(externalSignal){
      if(externalSignal.aborted)abort();
      else externalSignal.addEventListener('abort',abort,{once:true});
    }
    const timeout=setTimeout(()=>controller.abort(new Error('koschei_guard_timeout')),timeoutMs);
    return{signal:controller.signal,cleanup:()=>{
      clearTimeout(timeout);
      if(externalSignal)externalSignal.removeEventListener('abort',abort);
    }};
  }

  function effectiveAction(assessment){
    const action=normalizeAction(assessment?.action);
    if(action==='block')return'block';
    if(action==='withhold')return'withhold';
    if(action!=='allow'&&action!=='warn')return'withhold';
    if(assessment?.guard_complete!==true)return'withhold';
    return action;
  }

  function decisionMessage(assessment,fallback){
    return asString(assessment?.pre_signing_explanation?.plain_language_summary)||asString(assessment?.summary)||fallback;
  }

  async function fetchAssessment(wallet,transaction,operation,index,config,initialBytes){
    const base64=bytesToBase64(initialBytes);
    const transactionFingerprint=await transactionFingerprintFromBase64(base64);
    const address=walletAddress(wallet,config.walletAddress);
    if(!address)throw new KoscheiWithheldError('The connected wallet address is unavailable.',{transactionFingerprint});
    const policyRaw=typeof config.policyProvider==='function'
      ?await config.policyProvider({transaction,operation,index,transactionFingerprint,walletAddress:address})
      :(config.policy||{});
    const afterPolicyBytes=serializeTransaction(transaction);
    if(!bytesEqual(initialBytes,afterPolicyBytes)){
      throw new KoscheiBlockedError('The transaction changed while Koschei policy was being prepared.',{transactionFingerprint});
    }
    const policy=normalizePolicy(policyRaw);
    const network=asString(policyRaw?.network||config.network||DEFAULT_NETWORK);
    const intentMode=asString(config.intentMode||'required').toLowerCase();
    let signedIntent=policyRaw?.signed_intent||null;
    const intentContext={transaction,operation,index,transactionFingerprint,walletAddress:address,network,policy,uiSummary:policyRaw?.ui_summary};
    if(!signedIntent&&typeof config.signedIntentProvider==='function')signedIntent=await config.signedIntentProvider(intentContext);
    if(!signedIntent&&intentMode==='required')signedIntent=await createSignedIntent(wallet,intentContext,config);
    if(intentMode==='required'&&!signedIntent){
      throw new KoscheiWithheldError('A signed UI intent is required before transaction signing.',{transactionFingerprint});
    }
    const request={
      transaction:base64,
      encoding:'base64',
      network,
      wallet:address,
      expected_programs:policy.expected_programs,
      required_programs:policy.required_programs,
      blocked_programs:policy.blocked_programs,
      accounts:policy.accounts
    };
    if(signedIntent)request.signed_intent=signedIntent;
    const headers=await resolveHeaders(config,{operation,index,transactionFingerprint,walletAddress:address});
    const linked=linkedAbortController(config.signal,Number(config.timeoutMs||DEFAULT_TIMEOUT_MS));
    let response;
    try{
      response=await (config.fetch||root.fetch)(asString(config.endpoint||DEFAULT_ENDPOINT),{
        method:'POST',headers,body:JSON.stringify(request),signal:linked.signal,
        credentials:config.credentials||'same-origin',cache:'no-store',redirect:'error'
      });
    }catch(error){
      throw new KoscheiWithheldError('Koschei Guard could not be reached; signing was withheld.',{transactionFingerprint,cause:error});
    }finally{linked.cleanup()}
    let assessment;
    try{assessment=await response.json()}catch(error){
      throw new KoscheiWithheldError('Koschei Guard returned an unreadable response.',{transactionFingerprint,cause:error});
    }
    if(!response.ok&&normalizeAction(assessment?.action)!=='block'){
      throw new KoscheiWithheldError(decisionMessage(assessment,'Koschei Guard did not complete.'),{transactionFingerprint,assessment});
    }
    if(asString(assessment?.transaction_fingerprint)!==transactionFingerprint){
      throw new KoscheiBlockedError('Koschei response fingerprint does not match the transaction.',{transactionFingerprint,assessment});
    }
    if(asString(assessment?.network)!==network){
      throw new KoscheiBlockedError('Koschei response network does not match the requested network.',{transactionFingerprint,assessment});
    }
    if(asString(assessment?.wallet)!==address){
      throw new KoscheiBlockedError('Koschei response wallet does not match the connected wallet.',{transactionFingerprint,assessment});
    }
    return{assessment,action:effectiveAction(assessment),transactionFingerprint,base64,receivedAt:Date.now(),initialBytes,policy};
  }

  async function authorizeDecision(decision,transaction,config){
    if(typeof config.onDecision==='function')await config.onDecision(decision);
    const details={action:decision.action,assessment:decision.assessment,transactionFingerprint:decision.transactionFingerprint};
    if(decision.action==='block')throw new KoscheiBlockedError(decisionMessage(decision.assessment,'Koschei blocked this transaction.'),details);
    if(decision.action==='withhold')throw new KoscheiWithheldError(decisionMessage(decision.assessment,'Koschei withheld a safe decision.'),details);
    if(decision.action==='warn'){
      if(typeof config.onWarn!=='function'){
        throw new KoscheiWithheldError('Koschei returned WARN but no fingerprint-bound approval handler is configured.',details);
      }
      const approval=await config.onWarn({
        assessment:decision.assessment,
        transactionFingerprint:decision.transactionFingerprint,
        explanation:decision.assessment?.pre_signing_explanation||null
      });
      if(approval?.approved!==true||asString(approval?.fingerprint)!==decision.transactionFingerprint){
        throw new KoscheiWithheldError('The WARN approval was denied or was not bound to this transaction fingerprint.',details);
      }
    }
    if(Date.now()-decision.receivedAt>Number(config.maxDecisionAgeMs||DEFAULT_DECISION_AGE_MS)){
      throw new KoscheiWithheldError('The Koschei decision expired before signing.',details);
    }
    const currentBytes=serializeTransaction(transaction);
    const currentBase64=bytesToBase64(currentBytes);
    const currentFingerprint=await transactionFingerprintFromBase64(currentBase64);
    if(currentFingerprint!==decision.transactionFingerprint||!bytesEqual(currentBytes,decision.initialBytes)){
      throw new KoscheiBlockedError('The transaction changed after Koschei analysis and before wallet signing.',details);
    }
    return decision;
  }

  function verifySignedMessage(originalMessage,signedTransaction,config,details){
    if(config.requireMessageIntegrity===false)return;
    if(!originalMessage){
      throw new KoscheiWithheldError('Transaction message serialization is unavailable; post-sign integrity cannot be verified.',details);
    }
    const signedMessage=serializeMessage(signedTransaction);
    if(!signedMessage||!bytesEqual(originalMessage,signedMessage)){
      throw new KoscheiBlockedError('The wallet changed the transaction message while signing.',details);
    }
  }

  function createGuardedWallet(wallet,options){
    if(!wallet||typeof wallet!=='object')throw new KoscheiEnforcementError('wallet_missing','A wallet adapter/provider object is required.');
    const config=Object.assign({
      endpoint:DEFAULT_ENDPOINT,network:DEFAULT_NETWORK,intentMode:'required',
      timeoutMs:DEFAULT_TIMEOUT_MS,maxDecisionAgeMs:DEFAULT_DECISION_AGE_MS,
      requireMessageIntegrity:true,allowCombinedSignAndSend:false
    },options||{});
    if(typeof (config.fetch||root.fetch)!=='function')throw new KoscheiEnforcementError('fetch_unavailable','fetch() is required for Koschei enforcement.');
    let lastDecision=null;

    const signOne=async(transaction,args,operation)=>{
      const initialBytes=serializeTransaction(transaction);
      const originalMessage=serializeMessage(transaction);
      const decision=await fetchAssessment(wallet,transaction,operation,0,config,initialBytes);
      await authorizeDecision(decision,transaction,config);
      lastDecision=decision;
      const method=wallet[operation];
      if(typeof method!=='function')throw new KoscheiEnforcementError('wallet_sign_method_missing',`Wallet does not implement ${operation}().`);
      const signed=await method.call(wallet,transaction,...args);
      verifySignedMessage(originalMessage,signed,config,{action:decision.action,assessment:decision.assessment,transactionFingerprint:decision.transactionFingerprint});
      return signed;
    };

    const signAll=async(transactions,args)=>{
      if(!Array.isArray(transactions)||transactions.length===0)throw new KoscheiEnforcementError('transaction_batch_invalid','signAllTransactions requires a non-empty transaction array.');
      const prepared=[];
      for(let index=0;index<transactions.length;index++){
        const transaction=transactions[index];
        const initialBytes=serializeTransaction(transaction);
        const message=serializeMessage(transaction);
        const decision=await fetchAssessment(wallet,transaction,'signAllTransactions',index,config,initialBytes);
        await authorizeDecision(decision,transaction,config);
        prepared.push({transaction,message,decision});
      }
      for(const item of prepared){
        const current=serializeTransaction(item.transaction);
        if(!bytesEqual(current,item.decision.initialBytes)){
          throw new KoscheiBlockedError('A batched transaction changed before wallet signing.',{
            action:item.decision.action,assessment:item.decision.assessment,transactionFingerprint:item.decision.transactionFingerprint
          });
        }
      }
      if(typeof wallet.signAllTransactions!=='function')throw new KoscheiEnforcementError('wallet_sign_method_missing','Wallet does not implement signAllTransactions().');
      const signed=await wallet.signAllTransactions.call(wallet,transactions,...args);
      if(!Array.isArray(signed)||signed.length!==prepared.length)throw new KoscheiBlockedError('Wallet returned an invalid signed transaction batch.');
      signed.forEach((transaction,index)=>verifySignedMessage(prepared[index].message,transaction,config,{
        action:prepared[index].decision.action,assessment:prepared[index].decision.assessment,
        transactionFingerprint:prepared[index].decision.transactionFingerprint
      }));
      lastDecision=prepared[prepared.length-1].decision;
      return signed;
    };

    return new Proxy(wallet,{
      get(target,property,receiver){
        if(property==='koscheiEnforcementVersion')return VERSION;
        if(property==='getKoscheiLastDecision')return()=>lastDecision;
        if(property==='signTransaction')return(transaction,...args)=>signOne(transaction,args,'signTransaction');
        if(property==='signAllTransactions')return(transactions,...args)=>signAll(transactions,args);
        if(property==='sendTransaction'||property==='signAndSendTransaction'){
          if(!config.allowCombinedSignAndSend){
            return()=>{throw new KoscheiWithheldError(`${String(property)} is disabled in strict mode because post-sign message integrity cannot be checked before broadcast.`)};
          }
          return async(transaction,...args)=>{
            const initialBytes=serializeTransaction(transaction);
            const decision=await fetchAssessment(wallet,transaction,String(property),0,config,initialBytes);
            await authorizeDecision(decision,transaction,config);
            lastDecision=decision;
            const method=target[property];
            if(typeof method!=='function')throw new KoscheiEnforcementError('wallet_sign_method_missing',`Wallet does not implement ${String(property)}().`);
            return method.call(target,transaction,...args);
          };
        }
        const value=Reflect.get(target,property,receiver);
        return typeof value==='function'?value.bind(target):value;
      }
    });
  }

  return{
    VERSION,
    KoscheiEnforcementError,KoscheiBlockedError,KoscheiWithheldError,
    createGuardedWallet,createSignedIntent,normalizePolicy,
    serializeTransaction,serializeMessage,transactionFingerprintFromBase64,sha256Hex
  };
});
