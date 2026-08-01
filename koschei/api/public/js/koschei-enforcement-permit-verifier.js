(function(root,factory){
  const api=factory(root);
  if(typeof module==='object'&&module.exports)module.exports=api;
  root.KoscheiEnforcementPermitVerifier=api;
})(typeof globalThis!=='undefined'?globalThis:this,function(root){
  'use strict';

  const VERSION='koschei-enforcement-permit-verifier-v1';
  const PERMIT_VERSION='koschei-enforcement-permit-v1';
  const ALGORITHM='Ed25519';
  const DEFAULT_CLOCK_SKEW_MS=2000;
  const MAX_PERMIT_LIFETIME_MS=120000;

  class PermitVerificationError extends Error{
    constructor(code,message,details){
      super(message||code);
      this.name='PermitVerificationError';
      this.code=code;
      this.details=details||null;
    }
  }

  const asString=value=>String(value??'').trim();
  const normalizeOrigin=value=>asString(value).replace(/\/+$/,'').toLowerCase();
  const normalizeAction=value=>asString(value).toLowerCase();

  function textEncoder(){
    if(typeof root.TextEncoder==='function')return new root.TextEncoder();
    if(typeof TextEncoder==='function')return new TextEncoder();
    throw new PermitVerificationError('text_encoder_unavailable','TextEncoder is required for permit verification.');
  }

  function cryptoProvider(){
    const provider=root.crypto||globalThis.crypto;
    if(!provider?.subtle)throw new PermitVerificationError('web_crypto_unavailable','Web Crypto is required for permit verification.');
    return provider;
  }

  function toUint8Array(value){
    if(value instanceof Uint8Array)return new Uint8Array(value);
    if(value instanceof ArrayBuffer)return new Uint8Array(value.slice(0));
    if(ArrayBuffer.isView(value))return new Uint8Array(value.buffer.slice(value.byteOffset,value.byteOffset+value.byteLength));
    if(Array.isArray(value))return Uint8Array.from(value);
    throw new PermitVerificationError('byte_value_invalid','Expected a byte sequence.');
  }

  function base64ToBytes(value){
    const encoded=asString(value);
    if(!encoded)throw new PermitVerificationError('base64_value_missing','A base64 value is required.');
    try{
      if(typeof Buffer!=='undefined')return new Uint8Array(Buffer.from(encoded,'base64'));
      if(typeof root.atob!=='function')throw new Error('atob unavailable');
      const binary=root.atob(encoded);
      const bytes=new Uint8Array(binary.length);
      for(let index=0;index<binary.length;index++)bytes[index]=binary.charCodeAt(index);
      return bytes;
    }catch(error){
      throw new PermitVerificationError('base64_value_invalid','Permit cryptographic material is not valid base64.',{cause:error});
    }
  }

  function bytesEqual(left,right){
    const a=toUint8Array(left);
    const b=toUint8Array(right);
    if(a.length!==b.length)return false;
    let difference=0;
    for(let index=0;index<a.length;index++)difference|=a[index]^b[index];
    return difference===0;
  }

  function hex(bytes){
    return Array.from(toUint8Array(bytes),value=>value.toString(16).padStart(2,'0')).join('');
  }

  async function sha256Hex(value){
    const bytes=typeof value==='string'?textEncoder().encode(value):toUint8Array(value);
    const digest=await cryptoProvider().subtle.digest('SHA-256',bytes);
    return hex(new Uint8Array(digest));
  }

  function requireString(payload,key){
    const value=asString(payload?.[key]);
    if(!value)throw new PermitVerificationError('permit_payload_invalid',`Permit payload field ${key} is required.`);
    return value;
  }

  function requireInteger(payload,key){
    const value=payload?.[key];
    if(!Number.isInteger(value))throw new PermitVerificationError('permit_payload_invalid',`Permit payload field ${key} must be an integer.`);
    return value;
  }

  function canonicalPermitPayload(payload){
    if(!payload||typeof payload!=='object'||Array.isArray(payload)){
      throw new PermitVerificationError('permit_payload_invalid','Permit payload must be an object.');
    }
    const canonical={
      version:requireString(payload,'version'),
      permit_id:requireString(payload,'permit_id'),
      nonce:requireString(payload,'nonce'),
      key_id:requireString(payload,'key_id'),
      algorithm:requireString(payload,'algorithm'),
      issued_at:requireString(payload,'issued_at'),
      expires_at:requireString(payload,'expires_at'),
      network:requireString(payload,'network'),
      wallet:requireString(payload,'wallet'),
      origin:requireString(payload,'origin'),
      transaction_fingerprint:requireString(payload,'transaction_fingerprint'),
      action:requireString(payload,'action'),
      risk_level:requireString(payload,'risk_level'),
      risk_index:requireInteger(payload,'risk_index'),
      guard_complete:payload.guard_complete,
      warn_approval_required:payload.warn_approval_required,
      guard_version:requireString(payload,'guard_version'),
      analysis_version:requireString(payload,'analysis_version'),
      request_id:requireString(payload,'request_id'),
      decision_hash:requireString(payload,'decision_hash')
    };
    if(typeof canonical.guard_complete!=='boolean'||typeof canonical.warn_approval_required!=='boolean'){
      throw new PermitVerificationError('permit_payload_invalid','Permit boolean fields are malformed.');
    }
    const signedIntentID=asString(payload.signed_ui_intent_id);
    const uiSummaryHash=asString(payload.ui_summary_hash);
    if(signedIntentID)canonical.signed_ui_intent_id=signedIntentID;
    if(uiSummaryHash)canonical.ui_summary_hash=uiSummaryHash;
    return JSON.stringify(canonical);
  }

  function decisionCommitmentFromAssessment(assessment){
    const source=assessment||{};
    const threat=source.threat_history||{};
    const cpi=source.cpi_asset_flow||{};
    const authority=source.authority_surface||{};
    const commitment={
      action:asString(source.action),
      risk_level:asString(source.risk_level),
      risk_index:Number.isInteger(source.risk_index)?source.risk_index:Number(source.risk_index||0),
      summary:asString(source.summary),
      findings:Array.isArray(source.findings)?source.findings:[],
      program_policy:source.program_policy||{},
      intent_policy:source.intent_policy||{},
      threat_status:asString(threat.status)
    };
    const threatRiskLevel=asString(threat.highest_risk_level);
    if(threatRiskLevel)commitment.threat_risk_level=threatRiskLevel;
    commitment.threat_risk_index=Number.isInteger(threat.highest_risk_index)?threat.highest_risk_index:Number(threat.highest_risk_index||0);
    commitment.cpi_status=asString(cpi.status);
    commitment.authority_status=asString(authority.status);
    return commitment;
  }

  async function decisionHashFromAssessment(assessment){
    return `sha256:${await sha256Hex(JSON.stringify(decisionCommitmentFromAssessment(assessment)))}`;
  }

  async function resolvePinnedKey(keyID,options){
    let value=null;
    if(typeof options?.keyResolver==='function')value=await options.keyResolver(keyID);
    if(value==null&&options?.pinnedKeys instanceof Map)value=options.pinnedKeys.get(keyID);
    if(value==null&&options?.pinnedKeys&&typeof options.pinnedKeys==='object')value=options.pinnedKeys[keyID];
    if(value==null&&options?.pinnedKey&&(!options.expectedKeyID||asString(options.expectedKeyID)===keyID))value=options.pinnedKey;
    if(value==null){
      throw new PermitVerificationError('permit_key_not_pinned',`No trusted enforcement key is pinned for ${keyID}.`,{keyID});
    }
    const bytes=typeof value==='string'?base64ToBytes(value):toUint8Array(value);
    if(bytes.length!==32)throw new PermitVerificationError('permit_key_invalid','Pinned Ed25519 public key must be exactly 32 bytes.',{keyID});
    return bytes;
  }

  async function verifyEd25519(publicKey,message,signature){
    const keyBytes=toUint8Array(publicKey);
    const messageBytes=toUint8Array(message);
    const signatureBytes=toUint8Array(signature);
    if(signatureBytes.length!==64)throw new PermitVerificationError('permit_signature_invalid','Ed25519 signature must be exactly 64 bytes.');
    try{
      const subtle=cryptoProvider().subtle;
      const imported=await subtle.importKey('raw',keyBytes,{name:'Ed25519'},false,['verify']);
      return await subtle.verify({name:'Ed25519'},imported,signatureBytes,messageBytes);
    }catch(webError){
      if(typeof module==='object'&&module.exports&&typeof require==='function'){
        try{
          const nodeCrypto=require('node:crypto');
          const prefix=Buffer.from('302a300506032b6570032100','hex');
          const key=nodeCrypto.createPublicKey({key:Buffer.concat([prefix,Buffer.from(keyBytes)]),format:'der',type:'spki'});
          return nodeCrypto.verify(null,Buffer.from(messageBytes),key,Buffer.from(signatureBytes));
        }catch(nodeError){
          throw new PermitVerificationError('ed25519_verifier_unavailable','No supported Ed25519 verifier is available.',{webError,nodeError});
        }
      }
      throw new PermitVerificationError('ed25519_verifier_unavailable','This runtime cannot verify Ed25519 enforcement permits.',{cause:webError});
    }
  }

  function expectedValue(expected,key,fallback){
    const value=expected?.[key];
    return value===undefined||value===null?fallback:value;
  }

  function assertExpected(payload,expected){
    if(!expected)return;
    const checks=[
      ['transaction_fingerprint','transactionFingerprint'],
      ['wallet','wallet'],
      ['network','network'],
      ['request_id','requestID'],
      ['guard_version','guardVersion'],
      ['analysis_version','analysisVersion']
    ];
    for(const [payloadKey,expectedKey] of checks){
      const wanted=asString(expectedValue(expected,expectedKey,''));
      if(wanted&&asString(payload[payloadKey])!==wanted){
        throw new PermitVerificationError('permit_binding_mismatch',`Permit ${payloadKey} does not match the protected signing context.`,{expected:wanted,actual:payload[payloadKey]});
      }
    }
    const expectedOrigin=normalizeOrigin(expectedValue(expected,'origin',''));
    if(expectedOrigin&&normalizeOrigin(payload.origin)!==expectedOrigin){
      throw new PermitVerificationError('permit_origin_mismatch','Permit origin does not match the protected signing context.',{expected:expectedOrigin,actual:payload.origin});
    }
    const expectedAction=normalizeAction(expectedValue(expected,'action',''));
    if(expectedAction&&normalizeAction(payload.action)!==expectedAction){
      throw new PermitVerificationError('permit_action_mismatch','Permit action does not match the Guard response.',{expected:expectedAction,actual:payload.action});
    }
    const expectedRiskLevel=asString(expectedValue(expected,'riskLevel','')).toLowerCase();
    if(expectedRiskLevel&&asString(payload.risk_level).toLowerCase()!==expectedRiskLevel){
      throw new PermitVerificationError('permit_risk_mismatch','Permit risk level does not match the Guard response.');
    }
    const expectedRiskIndex=expectedValue(expected,'riskIndex',null);
    if(expectedRiskIndex!==null&&Number(payload.risk_index)!==Number(expectedRiskIndex)){
      throw new PermitVerificationError('permit_risk_mismatch','Permit risk index does not match the Guard response.');
    }
    const expectedIntentID=asString(expectedValue(expected,'signedUIIntentID',''));
    if(expectedIntentID&&asString(payload.signed_ui_intent_id)!==expectedIntentID){
      throw new PermitVerificationError('permit_intent_mismatch','Permit signed UI intent ID does not match.');
    }
    const expectedSummaryHash=asString(expectedValue(expected,'uiSummaryHash',''));
    if(expectedSummaryHash&&asString(payload.ui_summary_hash)!==expectedSummaryHash){
      throw new PermitVerificationError('permit_intent_mismatch','Permit UI summary hash does not match.');
    }
  }

  async function verifyPermit(permit,expected,options){
    const config=options||{};
    if(!permit||typeof permit!=='object')throw new PermitVerificationError('permit_missing','A Koschei enforcement permit is required.');
    if(permit.available!==true||permit.complete!==true||asString(permit.status)!=='issued'){
      throw new PermitVerificationError('permit_not_issued','Koschei did not issue a complete enforcement permit.',{status:permit.status});
    }
    if(asString(permit.algorithm)!==ALGORITHM)throw new PermitVerificationError('permit_algorithm_invalid','Unsupported enforcement permit algorithm.');
    const payload=permit.payload;
    const canonical=canonicalPermitPayload(payload);
    if(payload.version!==PERMIT_VERSION||payload.algorithm!==ALGORITHM){
      throw new PermitVerificationError('permit_version_invalid','Unsupported enforcement permit version or algorithm.');
    }
    if(payload.guard_complete!==true)throw new PermitVerificationError('permit_guard_incomplete','Permit does not attest a complete Guard decision.');
    const action=normalizeAction(payload.action);
    if(action!=='allow'&&action!=='warn')throw new PermitVerificationError('permit_action_invalid','Only ALLOW or WARN can authorize signing.');
    if(payload.warn_approval_required!==(action==='warn')){
      throw new PermitVerificationError('permit_warn_contract_invalid','WARN approval requirement does not match the permit action.');
    }
    if(asString(permit.key_id)!==asString(payload.key_id))throw new PermitVerificationError('permit_key_id_mismatch','Permit key identifiers do not match.');
    if(asString(permit.canonical_payload)!==canonical){
      throw new PermitVerificationError('permit_canonical_mismatch','Permit canonical payload does not match the structured payload.');
    }
    const canonicalHash=`sha256:${await sha256Hex(canonical)}`;
    if(asString(permit.canonical_sha256)!==canonicalHash){
      throw new PermitVerificationError('permit_hash_mismatch','Permit canonical SHA-256 does not match.');
    }

    const issuedAt=Date.parse(payload.issued_at);
    const expiresAt=Date.parse(payload.expires_at);
    if(!Number.isFinite(issuedAt)||!Number.isFinite(expiresAt)||expiresAt<=issuedAt){
      throw new PermitVerificationError('permit_time_invalid','Permit timestamps are invalid.');
    }
    if(expiresAt-issuedAt>MAX_PERMIT_LIFETIME_MS){
      throw new PermitVerificationError('permit_lifetime_invalid','Permit lifetime exceeds the verifier maximum.');
    }
    const now=Number(config.nowMs??Date.now());
    const clockSkew=Math.max(0,Number(config.clockSkewMs??DEFAULT_CLOCK_SKEW_MS));
    if(now<issuedAt-clockSkew)throw new PermitVerificationError('permit_not_yet_valid','Permit is not yet valid.');
    if(now>expiresAt+clockSkew)throw new PermitVerificationError('permit_expired','Permit has expired.');

    assertExpected(payload,expected);
    if(expected?.assessment){
      const decisionHash=await decisionHashFromAssessment(expected.assessment);
      if(asString(payload.decision_hash)!==decisionHash){
        throw new PermitVerificationError('permit_decision_hash_mismatch','Permit decision commitment does not match the Guard response.',{expected:decisionHash,actual:payload.decision_hash});
      }
    }

    const pinnedKey=await resolvePinnedKey(payload.key_id,config);
    if(asString(permit.verification_key)){
      const advertised=base64ToBytes(permit.verification_key);
      if(!bytesEqual(advertised,pinnedKey)){
        throw new PermitVerificationError('permit_advertised_key_mismatch','Response verification key differs from the pinned trusted key.');
      }
    }
    const signature=base64ToBytes(permit.signature);
    const verified=await verifyEd25519(pinnedKey,textEncoder().encode(canonical),signature);
    if(!verified)throw new PermitVerificationError('permit_signature_invalid','Enforcement permit signature verification failed.');

    return{
      verified:true,
      version:VERSION,
      keyID:payload.key_id,
      action,
      transactionFingerprint:payload.transaction_fingerprint,
      issuedAt:payload.issued_at,
      expiresAt:payload.expires_at,
      canonicalSHA256:canonicalHash,
      decisionHash:payload.decision_hash,
      payload
    };
  }

  return{
    VERSION,
    PERMIT_VERSION,
    ALGORITHM,
    PermitVerificationError,
    canonicalPermitPayload,
    decisionCommitmentFromAssessment,
    decisionHashFromAssessment,
    verifyPermit,
    sha256Hex
  };
});