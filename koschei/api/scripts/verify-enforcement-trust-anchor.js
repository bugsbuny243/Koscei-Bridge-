'use strict';

const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const trustAnchor=require('../public/js/koschei-enforcement-trust-anchor.js');
const verifier=require('../public/js/koschei-enforcement-permit-verifier.js');
const verified=require('../public/js/koschei-wallet-enforcement-verified.js');

const EXPECTED_KEY_ID='tgk_c7a9c6f81e4acb98';
const EXPECTED_PUBLIC_KEY='lCXYBwWBUlws5nZj7cb2uBs1+AnXvSXVK6v9iwKs8k4=';

function base64(bytes){return Buffer.from(bytes).toString('base64')}

async function productionAnchorContract(){
  assert.equal(trustAnchor.CURRENT_KEY_ID,EXPECTED_KEY_ID);
  assert.equal(trustAnchor.PINNED_KEYS[EXPECTED_KEY_ID],EXPECTED_PUBLIC_KEY);
  assert.equal(Buffer.from(EXPECTED_PUBLIC_KEY,'base64').length,32);
  assert.equal(verified.CURRENT_KEY_ID,EXPECTED_KEY_ID);
  assert.equal(verified.TRUST_ANCHOR_VERSION,'koschei-enforcement-trust-anchor-v1');

  const fingerprint='txf_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const assessment={
    ok:true,
    action:'allow',
    guard_complete:true,
    transaction_fingerprint:fingerprint,
    network:'solana-mainnet',
    wallet:'Wallet111111111111111111111111111111111',
    risk_level:'low',
    risk_index:0,
    request_id:'req_anchor_contract',
    guard_version:'v2',
    analysis_version:'v3-foundation-7',
    summary:'allow',
    findings:[],
    program_policy:{},
    intent_policy:{},
    threat_history:{status:'complete',highest_risk_index:0},
    cpi_asset_flow:{status:'complete'},
    authority_surface:{status:'complete'}
  };

  const attacker=crypto.generateKeyPairSync('ed25519');
  const spki=attacker.publicKey.export({format:'der',type:'spki'});
  const attackerRaw=spki.subarray(spki.length-32);
  const now=new Date(Date.now()-1000);
  const payload={
    version:'koschei-enforcement-permit-v1',
    permit_id:'tgp_attacker',
    nonce:'nonce_attacker',
    key_id:EXPECTED_KEY_ID,
    algorithm:'Ed25519',
    issued_at:now.toISOString().replace('.000Z','Z'),
    expires_at:new Date(now.getTime()+45000).toISOString().replace('.000Z','Z'),
    network:assessment.network,
    wallet:assessment.wallet,
    origin:'https://app.example.com',
    transaction_fingerprint:fingerprint,
    action:'allow',
    risk_level:assessment.risk_level,
    risk_index:assessment.risk_index,
    guard_complete:true,
    warn_approval_required:false,
    guard_version:assessment.guard_version,
    analysis_version:assessment.analysis_version,
    request_id:assessment.request_id,
    decision_hash:await verifier.decisionHashFromAssessment(assessment)
  };
  const canonical=verifier.canonicalPermitPayload(payload);
  const signature=crypto.sign(null,Buffer.from(canonical),attacker.privateKey);
  const permit={
    requested:true,
    required:true,
    available:true,
    complete:true,
    status:'issued',
    algorithm:'Ed25519',
    key_id:EXPECTED_KEY_ID,
    verification_key:base64(attackerRaw),
    payload,
    canonical_payload:canonical,
    canonical_sha256:`sha256:${await verifier.sha256Hex(canonical)}`,
    signature:signature.toString('base64'),
    limitations:[]
  };

  let rejected=false;
  try{
    await verifier.verifyPermit(permit,{
      transactionFingerprint:fingerprint,
      wallet:assessment.wallet,
      network:assessment.network,
      origin:'https://app.example.com',
      action:'allow',
      riskLevel:assessment.risk_level,
      riskIndex:assessment.risk_index,
      requestID:assessment.request_id,
      guardVersion:assessment.guard_version,
      analysisVersion:assessment.analysis_version,
      assessment
    },{pinnedKeys:trustAnchor.PINNED_KEYS});
  }catch(error){
    rejected=error instanceof verifier.PermitVerificationError;
  }
  assert.equal(rejected,true,'an attacker key reusing the production key ID must be rejected');
  console.log('production enforcement trust anchor: ok');
}

productionAnchorContract().catch(error=>{
  console.error(error);
  process.exit(1);
});
