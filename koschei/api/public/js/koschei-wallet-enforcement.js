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
  const MAX_INTENT_TTL_MS=30*60*1000;

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
    constructor(message,details){
      super('koschei_transaction_blocked',message||'Koschei blocked this transaction.',details);
      this.name='KoscheiBlockedError';
    }
  }

  class KoscheiWithheldError extends KoscheiEnforcementError{
    constructor(message,details){
      super('koschei_decision_withheld',message||'Koschei withheld a safe signing decision.',details);
      this.name='KoscheiWithheldError';
    }
  }

  const asString=value=>String(value??'').trim();
  const normalizeOrigin=value=>asString(value).replace(/\/+$/,'').toLowerCase();
  const normalizeAction=value=>asString(value).toLowerCase();

  function textEncoder(){
    if(typeof root.TextEncoder==='function')return new root.TextEncoder();
    if(typeof TextEncoder==='function')return new TextEncoder();
    throw new KoscheiEnforcementError('text_encoder_unavailable','TextEncoder is required for Koschei enforcement.');
  }

  function cryptoProvider(){
    const provider=root.crypto||globalThis.crypto;
    if(!provider?.subtle)throw new KoscheiEnforcementError('web_crypto_unavailable','Web Crypto SHA-256 support is required.');
    return provider;
  }

  function randomID(prefix){
    const provider=cryptoProvider();
    if(typeof provider.randomUUID==='function')return `${prefix}-${provider.randomUUID()}`;
    const bytes=new Uint8Array(16);
    provider.getRandomValues(bytes);
    return `${prefix}-${Array.from(bytes,value=>value.toString(16).padStart(2,'0')).join('')}`;
  }

  function toUint8Array(value){
    if(value instanceof Uint8Array)return new Uint8Array(value);
    if(value instanceof ArrayBuffer)return new Uint8Array(value.slice(0));
    if(ArrayBuffer.isView(value))return new Uint8Array(value.buffer.slice(value.byteOffset,value.byteOffset+value.byteLength));
    if(Array.isArray(value))return Uint8Array.from(value);
    throw new KoscheiEnforcementError('transaction_serialization_invalid','Transaction serialization did not return bytes.');
  }

  function bytesEqual(left,right){
    const a=toUint8Array(left);
    const b=toUint8Array(right);
    if(a.length!==b.length)return false;
    let difference=0;
    for(let index=0;index<a.length;index++)difference|=a[index]^b[index];
    return difference===0;
  }

  function bytesToBase64(bytes){
    const value=toUint8Array(bytes);
    if(typeof Buffer!=='undefined')return Buffer.from(value).toString('base64');
    let binary='';
    const chunkSize=0x8000;
    for(let index=0;index<value.length;index+=chunkSize){
      binary+=String.fromCharCode.apply(null,value.subarray(index,index+chunkSize));
    }
    if(typeof root.btoa!=='function')throw new KoscheiEnforcementError('base64_encoder_unavailable','A base64 encoder is required.');
    return root.btoa(binary);
  }

  async function sha256Hex(value){
    const bytes=typeof value==='string'?textEncoder().encode(value):toUint8Array(value);
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
    try{
      return toUint8Array(transaction.serialize({requireAllSignatures:false,verifySignatures:false}));
    }catch(firstError){
      try{
        return toUint8Array(transaction.serialize());
      }catch(secondError){
        throw new KoscheiEnforcementError('transaction_serialization_failed','Transaction could not be serialized.',{cause:secondError||firstError});
      }
    }
  }

  function serializeMessage(transaction){
    if(transaction&&typeof transaction.serializeMessage==='function')return toUint8Array(transaction.serializeMessage());
    if(transaction?.message&&typeof transaction.message.serialize==='function')return toUint8Array(transaction.message.serialize());
    return null;
  }

  function walletAddress(wallet,configured){
    const explicit=asString(configured);
    if(explicit)return explicit;
    const publicKey=wallet?.publicKey;
    if(!publicKey)return '';
    if(typeof publicKey.toBase58==='function')return asString(publicKey.toBase58());
    if(typeof publicKey.toString==='function')return asString(publicKey.toString());
    return asString(publicKey);
  }

  function normalizeAccount(account){
    const source=account||{};
    const normalized={address:asString(source.address)};
    const mint=asString(source.mint);
    if(mint)normalized.mint=mint;
    normalized.role=asString(source.role).toLowerCase();
    if(source.decimals!==undefined&&source.decimals!==null)normalized.decimals=Number(source.decimals);
    const maximumSpend=asString(source.maximum_spend_raw);
    const minimumReceive=asString(source.minimum_receive_raw);
    const quotedReceive=asString(source.quoted_receive_raw);
    if(maximumSpend)normalized.maximum_spend_raw=maximumSpend;
    if(minimumReceive)normalized.minimum_receive_raw=minimumReceive;
    if(quotedReceive)normalized.quoted_receive_raw=quotedReceive;
    const maxSlippage=Number(source.max_slippage_bps||0);
    if(maxSlippage)normalized.max_slippage_bps=maxSlippage;
    return normalized;
  }

  function normalizePolicy(policy){
    const source=policy||{};
    const normalizeList=value=>Array.from(new Set((Array.isArray(value)?value:[]).map(asString).filter(Boolean))).sort();
    const accounts=(Array.isArray(source.accounts)?source.accounts:[]).map(normalizeAccount).sort((left,right)=>{
      const a=`${left.address}|${left.role}|${left.mint||''}`;
      const b=`${right.address}|${right.role}|${right.mint||''}`;
      return a.localeCompare(b);
    });
    return{
      expected_programs:normalizeList(source.expected_programs),
      required_programs:normalizeList(source.required_programs),
      blocked_programs:normalizeList(source.blocked_programs),
      accounts
    };
  }

  function canonicalJSONString(value){
    if(value===null||typeof value!=='object')return JSON.stringify(value);
    if(Array.isArray(value))return `[${value.map(canonicalJSONString).join(',')}]`;
    return `{${Object.keys(value).sort().map(key=>`${JSON.stringify(key)}:${canonicalJSONString(value[key])}`).join(',')}}`;
  }

  function rfc3339Seconds(milliseconds){
    return new Date(Math.floor(milliseconds/1000)*1000).toISOString().replace('.000Z','Z');
  }

  function signatureBytes(value){
    if(value?.signature!==undefined)return toUint8Array(value.signature);
    return toUint8Array(value);
  }

  async function createSignedIntent(wallet,details,config){
    if(typeof wallet?.signMessage!=='function'){
      throw new KoscheiWithheldError('The connected wallet cannot sign the required UI intent.',{transactionFingerprint:details.transactionFingerprint});
    }
    const now=Date.now();
    const configuredTTL=Number(config.intentTTLms||DEFAULT_INTENT_TTL_MS);
    const ttlSeconds=Math.max(1,Math.min(Math.floor(configuredTTL/1000),MAX_INTENT_TTL_MS/1000));
    const issuedAt=rfc3339Seconds(now);
    const issuedMilliseconds=Date.parse(issuedAt);
    const expiresAt=rfc3339Seconds(issuedMilliseconds+ttlSeconds*1000);
    const uiOrigin=normalizeOrigin(config.uiOrigin||root.location?.origin);
    if(!uiOrigin)throw new KoscheiWithheldError('A UI origin is required for signed intent binding.',{transactionFingerprint:details.transactionFingerprint});
    const uiSummary=details.uiSummary;
    if(uiSummary===undefined||uiSummary===null||uiSummary===''){
      throw new KoscheiWithheldError('A human-visible UI summary is required for signed intent binding.',{transactionFingerprint:details.transactionFingerprint});
    }
    const summaryCanonical=typeof uiSummary==='string'?uiSummary:canonicalJSONString(uiSummary);
    const uiSummaryHash=await sha256Hex(summaryCanonical);
    const policy=normalizePolicy(details.policy);
    const payload={
      version:'koschei-ui-intent-v1',
      intent_id:randomID('intent'),
      nonce:randomID('nonce'),
      issued_at:issuedAt,
      expires_at:expiresAt,
      network:asString(details.network||DEFAULT_NETWORK),
      wallet:asString(details.walletAddress),
      transaction_fingerprint:asString(details.transactionFingerprint),
      ui_origin:uiOrigin,
      ui_summary_hash:uiSummaryHash,
      expected_programs:policy.expected_programs,
      required_programs:policy.required_programs,
      blocked_programs:policy.blocked_programs,
      accounts:policy.accounts,
      signer:asString(details.walletAddress)
    };
    const canonical=JSON.stringify(payload);
    const signed=await wallet.signMessage(textEncoder().encode(canonical));
    return Object.assign({},payload,{signature:bytesToBase64(signatureBytes(signed))});
  }

  async function resolveHeaders(config,context){
    const headers={'Content-Type':'application/json','Accept':'application/json'};
    if(config.apiKey)headers['X-API-Key']=asString(config.apiKey);
    if(typeof config.headersProvider==='function'){
      const provided=await config.headersProvider(context);
      Object.entries(provided||{}).forEach(([key,value])=>{
        if(value!==undefined&&value!==null)headers[key]=String(value);
      });
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
    return{
      signal:controller.signal,
      cleanup:()=>{
        clearTimeout(timeout);
        if(externalSignal)externalSignal.removeEventListener('abort',abort);
      }
    };
  }

  function effectiveAction(assessment){
    const action=normalizeAction(assessment?.action);
    if(action==='block')return'block';
    if(action==='withhold')return'withhold';
    if(assessment?.ok!==true)return'withhold';
    if(action!=='allow'&&action!=='warn')return'withhold';
    if(assessment?.guard_complete!==true)return'withhold';
    return action;
  }

  function decisionMessage(assessment,fallback){
    return asString(assessment?.pre_signing_explanation?.plain_language_summary)||asString(assessment?.summary)||fallback;
  }

  function assertTransactionUnchanged(transaction,initialBytes,transactionFingerprint,message){
    const currentBytes=serializeTransaction(transaction);
    if(!bytesEqual(currentBytes,initialBytes)){
      throw new KoscheiBlockedError(message||'The transaction changed after Koschei analysis.',{transactionFingerprint});
    }
    return currentBytes;
  }

  async function fetchAssessment(wallet,transaction,operation,index,config,initialBytes){
    const base64=bytesToBase64(initialBytes);
    const transactionFingerprint=await transactionFingerprintFromBase64(base64);
    const address=walletAddress(wallet,config.walletAddress);
    if(!address)throw new KoscheiWithheldError('The connected wallet address is unavailable.',{transactionFingerprint});

    const providerContext={transaction,operation,index,transactionFingerprint,walletAddress:address};
    const policyRaw=typeof config.policyProvider==='function'
      ?await config.policyProvider(providerContext)
      :(config.policy||{});
    assertTransactionUnchanged(transaction,initialBytes,transactionFingerprint,'The transaction changed while Koschei policy was being prepared.');

    const policy=normalizePolicy(policyRaw);
    const network=asString(policyRaw?.network||config.network||DEFAULT_NETWORK);
    const intentMode=asString(config.intentMode||'required').toLowerCase();
    let signedIntent=policyRaw?.signed_intent||null;
    const intentContext={
      transaction,operation,index,transactionFingerprint,walletAddress:address,
      network,policy,uiSummary:policyRaw?.ui_summary
    };
    if(!signedIntent&&typeof config.signedIntentProvider==='function')signedIntent=await config.signedIntentProvider(intentContext);
    if(!signedIntent&&intentMode==='required')signedIntent=await createSignedIntent(wallet,intentContext,config);
    if(intentMode==='required'&&!signedIntent){
      throw new KoscheiWithheldError('A signed UI intent is required before transaction signing.',{transactionFingerprint});
    }
    assertTransactionUnchanged(transaction,initialBytes,transactionFingerprint,'The transaction changed while signed UI intent was being prepared.');

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
    assertTransactionUnchanged(transaction,initialBytes,transactionFingerprint,'The transaction changed before the Guard request was sent.');
    const fetchImplementation=config.fetch||root.fetch;
    if(typeof fetchImplementation!=='function')throw new KoscheiWithheldError('fetch() is unavailable; signing was withheld.',{transactionFingerprint});
    const linked=linkedAbortController(config.signal,Number(config.timeoutMs||DEFAULT_TIMEOUT_MS));
    let response;
    try{
      response=await fetchImplementation(asString(config.endpoint||DEFAULT_ENDPOINT),{
        method:'POST',headers,body:JSON.stringify(request),signal:linked.signal,
        credentials:config.credentials||'same-origin',cache:'no-store',redirect:'error'
      });
    }catch(error){
      throw new KoscheiWithheldError('Koschei Guard could not be reached; signing was withheld.',{transactionFingerprint,cause:error});
    }finally{
      linked.cleanup();
    }

    let assessment;
    try{
      assessment=await response.json();
    }catch(error){
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
    return{
      assessment,
      action:effectiveAction(assessment),
      transactionFingerprint,
      receivedAt:Date.now(),
      initialBytes:new Uint8Array(initialBytes),
      policy
    };
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
    const currentBytes=assertTransactionUnchanged(
      transaction,decision.initialBytes,decision.transactionFingerprint,
      'The transaction changed after Koschei analysis and before wallet signing.'
    );
    const currentFingerprint=await transactionFingerprintFromBase64(bytesToBase64(currentBytes));
    if(currentFingerprint!==decision.transactionFingerprint){
      throw new KoscheiBlockedError('The transaction fingerprint changed before wallet signing.',details);
    }
    return decision;
  }

  function verifySignedMessage(originalMessage,signedTransaction,config,details){
    if(config.requireMessageIntegrity===false)return;
    const signedMessage=serializeMessage(signedTransaction);
    if(!originalMessage||!signedMessage||!bytesEqual(originalMessage,signedMessage)){
      throw new KoscheiBlockedError('The wallet changed the transaction message while signing.',details);
    }
  }

  function createGuardedWallet(wallet,options){
    if(!wallet||typeof wallet!=='object')throw new KoscheiEnforcementError('wallet_missing','A wallet adapter/provider object is required.');
    const config=Object.assign({
      endpoint:DEFAULT_ENDPOINT,
      network:DEFAULT_NETWORK,
      intentMode:'required',
      timeoutMs:DEFAULT_TIMEOUT_MS,
      maxDecisionAgeMs:DEFAULT_DECISION_AGE_MS,
      requireMessageIntegrity:true,
      allowCombinedSignAndSend:false
    },options||{});
    let lastDecision=null;

    async function signOne(transaction,args,operation){
      const initialBytes=serializeTransaction(transaction);
      const originalMessage=serializeMessage(transaction);
      if(config.requireMessageIntegrity!==false&&!originalMessage){
        throw new KoscheiWithheldError('Transaction message serialization is unavailable; strict signing was withheld.');
      }
      const decision=await fetchAssessment(wallet,transaction,operation,0,config,initialBytes);
      await authorizeDecision(decision,transaction,config);
      lastDecision=decision;
      const method=wallet[operation];
      if(typeof method!=='function')throw new KoscheiEnforcementError('wallet_sign_method_missing',`Wallet does not implement ${operation}().`);
      const signed=await method.call(wallet,transaction,...args);
      verifySignedMessage(originalMessage,signed,config,{
        action:decision.action,
        assessment:decision.assessment,
        transactionFingerprint:decision.transactionFingerprint
      });
      return signed;
    }

    async function signAll(transactions,args){
      if(!Array.isArray(transactions)||transactions.length===0){
        throw new KoscheiEnforcementError('transaction_batch_invalid','signAllTransactions requires a non-empty transaction array.');
      }
      const prepared=[];
      for(let index=0;index<transactions.length;index++){
        const transaction=transactions[index];
        const initialBytes=serializeTransaction(transaction);
        const originalMessage=serializeMessage(transaction);
        if(config.requireMessageIntegrity!==false&&!originalMessage){
          throw new KoscheiWithheldError('A batched transaction cannot expose its message bytes; strict signing was withheld.');
        }
        const decision=await fetchAssessment(wallet,transaction,'signAllTransactions',index,config,initialBytes);
        await authorizeDecision(decision,transaction,config);
        prepared.push({transaction,originalMessage,decision});
      }
      for(const item of prepared){
        assertTransactionUnchanged(
          item.transaction,item.decision.initialBytes,item.decision.transactionFingerprint,
          'A batched transaction changed before wallet signing.'
        );
      }
      if(typeof wallet.signAllTransactions!=='function'){
        throw new KoscheiEnforcementError('wallet_sign_method_missing','Wallet does not implement signAllTransactions().');
      }
      const signed=await wallet.signAllTransactions.call(wallet,transactions,...args);
      if(!Array.isArray(signed)||signed.length!==prepared.length){
        throw new KoscheiBlockedError('Wallet returned an invalid signed transaction batch.');
      }
      signed.forEach((transaction,index)=>verifySignedMessage(prepared[index].originalMessage,transaction,config,{
        action:prepared[index].decision.action,
        assessment:prepared[index].decision.assessment,
        transactionFingerprint:prepared[index].decision.transactionFingerprint
      }));
      lastDecision=prepared[prepared.length-1].decision;
      return signed;
    }

    return new Proxy(wallet,{
      get(target,property){
        if(property==='koscheiEnforcementVersion')return VERSION;
        if(property==='getKoscheiLastDecision')return()=>lastDecision;
        if(property==='signTransaction')return(transaction,...args)=>signOne(transaction,args,'signTransaction');
        if(property==='signAllTransactions')return(transactions,...args)=>signAll(transactions,args);
        if(property==='sendTransaction'||property==='signAndSendTransaction'){
          if(!config.allowCombinedSignAndSend){
            return()=>{
              throw new KoscheiWithheldError(`${String(property)} is disabled in strict mode because post-sign message integrity cannot be checked before broadcast.`);
            };
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
        const value=Reflect.get(target,property,target);
        return typeof value==='function'?value.bind(target):value;
      }
    });
  }

  return{
    VERSION,
    KoscheiEnforcementError,
    KoscheiBlockedError,
    KoscheiWithheldError,
    createGuardedWallet,
    createSignedIntent,
    normalizePolicy,
    serializeTransaction,
    serializeMessage,
    transactionFingerprintFromBase64,
    sha256Hex
  };
});
