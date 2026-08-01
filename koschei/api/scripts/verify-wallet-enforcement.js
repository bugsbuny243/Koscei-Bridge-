'use strict';

const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {
  createGuardedWallet,
  createSignedIntent,
  normalizePolicy,
  transactionFingerprintFromBase64,
  KoscheiBlockedError,
  KoscheiWithheldError
}=require('../public/js/koschei-wallet-enforcement.js');
const {
  verifyPermit,
  canonicalPermitPayload,
  decisionHashFromAssessment,
  PermitVerificationError,
  sha256Hex
}=require('../public/js/koschei-enforcement-permit-verifier.js');
const {
  createPermitVerifiedWallet
}=require('../public/js/koschei-wallet-enforcement-verified.js');

class FakeTransaction{
  constructor(marker,messageMarker){
    this.bytes=Uint8Array.from([marker,marker+1,marker+2]);
    this.message=Uint8Array.from([messageMarker??marker,77]);
  }
  serialize(){return new Uint8Array(this.bytes)}
  serializeMessage(){return new Uint8Array(this.message)}
}

function base64(bytes){return Buffer.from(bytes).toString('base64')}

function response(body,status){
  return{
    ok:(status??200)>=200&&(status??200)<300,
    status:status??200,
    async json(){return body}
  };
}

function assessment(action,fingerprint,overrides){
  const riskLevel={allow:'low',warn:'medium',block:'critical',withhold:'unknown'}[action]||'unknown';
  const riskIndex={allow:0,warn:25,block:100,withhold:0}[action]??0;
  return Object.assign({
    ok:true,
    action,
    guard_complete:action!=='withhold',
    transaction_fingerprint:fingerprint,
    network:'solana-mainnet',
    wallet:'Wallet111111111111111111111111111111111',
    risk_level:riskLevel,
    risk_index:riskIndex,
    request_id:`request-${action}`,
    guard_version:'v2',
    analysis_version:'v3-foundation-7',
    summary:`decision:${action}`,
    findings:[],
    program_policy:{complete:true,invoked_programs:[],unexpected_programs:[],missing_required_programs:[],blocked_programs:[]},
    intent_policy:{requested:false,complete:true,accounts:[]},
    threat_history:{status:'complete',highest_risk_index:0,matches:[],limitations:[]},
    cpi_asset_flow:{status:'complete',flows:[],program_ids:[],limitations:[]},
    authority_surface:{status:'complete',events:[],limitations:[]},
    signed_ui_intent:{complete:false},
    pre_signing_explanation:{plain_language_summary:`decision:${action}`}
  },overrides||{});
}

function fetchForActions(actions){
  let index=0;
  return async(_url,options)=>{
    const request=JSON.parse(options.body);
    const fingerprint=await transactionFingerprintFromBase64(request.transaction);
    const action=actions[Math.min(index++,actions.length-1)];
    return response(assessment(action,fingerprint,action==='withhold'?{guard_complete:false}:null),action==='withhold'?503:200);
  };
}

function walletFixture(){
  const state={single:0,batch:0,combined:0};
  const wallet={
    publicKey:{toString:()=> 'Wallet111111111111111111111111111111111'},
    async signTransaction(transaction){state.single++;return transaction},
    async signAllTransactions(transactions){state.batch++;return transactions},
    async sendTransaction(){state.combined++;return'SIGNATURE'},
    async signAndSendTransaction(){state.combined++;return{signature:'SIGNATURE'}}
  };
  return{wallet,state};
}

const baseOptions=fetchImpl=>({
  fetch:fetchImpl,
  intentMode:'disabled',
  walletAddress:'Wallet111111111111111111111111111111111',
  policy:{expected_programs:[],required_programs:[],blocked_programs:[],accounts:[]}
});

async function expectError(type,fn){
  let caught=null;
  try{await fn()}catch(error){caught=error}
  assert.ok(caught instanceof type,`expected ${type.name}, got ${caught?.constructor?.name}: ${caught?.message}`);
  return caught;
}

async function testBlockNeverCallsWallet(){
  const {wallet,state}=walletFixture();
  const guarded=createGuardedWallet(wallet,baseOptions(fetchForActions(['block'])));
  await expectError(KoscheiBlockedError,()=>guarded.signTransaction(new FakeTransaction(1)));
  assert.equal(state.single,0);
}

async function testWithholdNeverCallsWallet(){
  const {wallet,state}=walletFixture();
  const guarded=createGuardedWallet(wallet,baseOptions(fetchForActions(['withhold'])));
  await expectError(KoscheiWithheldError,()=>guarded.signTransaction(new FakeTransaction(2)));
  assert.equal(state.single,0);
}

async function testAllowSignsAndPreservesMessage(){
  const {wallet,state}=walletFixture();
  const guarded=createGuardedWallet(wallet,baseOptions(fetchForActions(['allow'])));
  const transaction=new FakeTransaction(3);
  const signed=await guarded.signTransaction(transaction);
  assert.equal(signed,transaction);
  assert.equal(state.single,1);
  assert.equal(guarded.getKoscheiLastDecision().action,'allow');
}

async function testWarnRequiresFingerprintBoundApproval(){
  const deniedFixture=walletFixture();
  const denied=createGuardedWallet(deniedFixture.wallet,Object.assign(baseOptions(fetchForActions(['warn'])),{
    onWarn:async()=>({approved:true,fingerprint:'txf_wrong'})
  }));
  await expectError(KoscheiWithheldError,()=>denied.signTransaction(new FakeTransaction(4)));
  assert.equal(deniedFixture.state.single,0);

  const allowedFixture=walletFixture();
  const allowed=createGuardedWallet(allowedFixture.wallet,Object.assign(baseOptions(fetchForActions(['warn'])),{
    onWarn:async context=>({approved:true,fingerprint:context.transactionFingerprint})
  }));
  await allowed.signTransaction(new FakeTransaction(5));
  assert.equal(allowedFixture.state.single,1);
}

async function testMutationAfterDecisionIsBlocked(){
  const {wallet,state}=walletFixture();
  const transaction=new FakeTransaction(6);
  const guarded=createGuardedWallet(wallet,Object.assign(baseOptions(fetchForActions(['allow'])),{
    onDecision:async()=>{transaction.bytes[0]=99}
  }));
  await expectError(KoscheiBlockedError,()=>guarded.signTransaction(transaction));
  assert.equal(state.single,0);
}

async function testWalletMessageMutationIsRejected(){
  const state={single:0};
  const wallet={
    publicKey:{toString:()=> 'Wallet111111111111111111111111111111111'},
    async signTransaction(transaction){
      state.single++;
      const changed=new FakeTransaction(transaction.bytes[0],99);
      changed.bytes=new Uint8Array(transaction.bytes);
      return changed;
    }
  };
  const guarded=createGuardedWallet(wallet,baseOptions(fetchForActions(['allow'])));
  await expectError(KoscheiBlockedError,()=>guarded.signTransaction(new FakeTransaction(7)));
  assert.equal(state.single,1);
}

async function testBatchIsAllOrNothing(){
  const {wallet,state}=walletFixture();
  const guarded=createGuardedWallet(wallet,baseOptions(fetchForActions(['allow','block'])));
  await expectError(KoscheiBlockedError,()=>guarded.signAllTransactions([new FakeTransaction(8),new FakeTransaction(9)]));
  assert.equal(state.batch,0);
}

async function testCombinedSignAndSendDisabledByDefault(){
  const {wallet,state}=walletFixture();
  const guarded=createGuardedWallet(wallet,baseOptions(fetchForActions(['allow'])));
  await expectError(KoscheiWithheldError,()=>guarded.sendTransaction(new FakeTransaction(10)));
  await expectError(KoscheiWithheldError,()=>guarded.signAndSendTransaction(new FakeTransaction(11)));
  assert.equal(state.combined,0);
}

async function testResponseFingerprintMismatchBlocks(){
  const {wallet,state}=walletFixture();
  const guarded=createGuardedWallet(wallet,baseOptions(async(_url,options)=>{
    const request=JSON.parse(options.body);
    assert.ok(request.transaction);
    return response(assessment('allow','txf_wrong'));
  }));
  await expectError(KoscheiBlockedError,()=>guarded.signTransaction(new FakeTransaction(12)));
  assert.equal(state.single,0);
}

async function testSignedIntentCanonicalOrderAndTime(){
  let signedMessage='';
  const wallet={
    async signMessage(bytes){
      signedMessage=new TextDecoder().decode(bytes);
      return new Uint8Array(64);
    }
  };
  const policy=normalizePolicy({
    expected_programs:['ProgramB','ProgramA'],
    accounts:[{
      address:'AccountA',mint:'MintA',role:'input',decimals:6,
      maximum_spend_raw:'100',max_slippage_bps:50
    }]
  });
  const intent=await createSignedIntent(wallet,{
    transactionFingerprint:'txf_12345678901234567890123456789012',
    walletAddress:'Wallet111111111111111111111111111111111',
    network:'solana-mainnet',
    policy,
    uiSummary:{action:'Swap',spend:'100'}
  },{uiOrigin:'https://app.example.com/',intentTTLms:60000});
  assert.equal(intent.ui_origin,'https://app.example.com');
  assert.deepEqual(intent.expected_programs,['ProgramA','ProgramB']);
  assert.ok(!/\.\d{3}Z/.test(signedMessage),'canonical RFC3339 timestamps must not contain milliseconds');
  const accountJSON='{"address":"AccountA","mint":"MintA","role":"input","decimals":6,"maximum_spend_raw":"100","max_slippage_bps":50}';
  assert.ok(signedMessage.includes(accountJSON),`unexpected canonical account order: ${signedMessage}`);
  assert.equal(Buffer.from(intent.signature,'base64').length,64);
}

function permitKeyFixture(){
  const pair=crypto.generateKeyPairSync('ed25519');
  const spki=pair.publicKey.export({format:'der',type:'spki'});
  return{
    privateKey:pair.privateKey,
    publicKeyRaw:new Uint8Array(spki.subarray(spki.length-32)),
    keyID:'tgk_contract_test'
  };
}

async function issuePermit(value,keyFixture,overrides){
  const now=new Date(Date.now()-1000);
  const expires=new Date(now.getTime()+45000);
  const payload=Object.assign({
    version:'koschei-enforcement-permit-v1',
    permit_id:'tgp_contract_test',
    nonce:'nonce_contract_test',
    key_id:keyFixture.keyID,
    algorithm:'Ed25519',
    issued_at:now.toISOString().replace('.000Z','Z'),
    expires_at:expires.toISOString().replace('.000Z','Z'),
    network:value.network,
    wallet:value.wallet,
    origin:'https://app.example.com',
    transaction_fingerprint:value.transaction_fingerprint,
    action:value.action,
    risk_level:value.risk_level,
    risk_index:value.risk_index,
    guard_complete:true,
    warn_approval_required:value.action==='warn',
    guard_version:value.guard_version,
    analysis_version:value.analysis_version,
    request_id:value.request_id,
    decision_hash:await decisionHashFromAssessment(value)
  },overrides?.payload||{});
  const canonical=canonicalPermitPayload(payload);
  const signature=crypto.sign(null,Buffer.from(canonical),keyFixture.privateKey);
  const permit={
    requested:true,
    required:true,
    available:true,
    complete:true,
    status:'issued',
    algorithm:'Ed25519',
    key_id:keyFixture.keyID,
    verification_key:base64(keyFixture.publicKeyRaw),
    payload,
    canonical_payload:canonical,
    canonical_sha256:`sha256:${await sha256Hex(canonical)}`,
    signature:signature.toString('base64'),
    limitations:[]
  };
  return Object.assign(permit,overrides?.permit||{});
}

function expectedPermit(value){
  return{
    transactionFingerprint:value.transaction_fingerprint,
    wallet:value.wallet,
    network:value.network,
    origin:'https://app.example.com',
    action:value.action,
    riskLevel:value.risk_level,
    riskIndex:value.risk_index,
    requestID:value.request_id,
    guardVersion:value.guard_version,
    analysisVersion:value.analysis_version,
    assessment:value
  };
}

async function testPinnedPermitVerifierAcceptsValidPermit(){
  const keys=permitKeyFixture();
  const value=assessment('allow','txf_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  const permit=await issuePermit(value,keys);
  const verified=await verifyPermit(permit,expectedPermit(value),{pinnedKeys:{[keys.keyID]:base64(keys.publicKeyRaw)}});
  assert.equal(verified.verified,true);
  assert.equal(verified.action,'allow');
  assert.equal(verified.keyID,keys.keyID);
}

async function testPinnedPermitVerifierRejectsKeySubstitution(){
  const trusted=permitKeyFixture();
  const attacker=permitKeyFixture();
  attacker.keyID=trusted.keyID;
  const value=assessment('allow','txf_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
  const permit=await issuePermit(value,attacker);
  await expectError(PermitVerificationError,()=>verifyPermit(permit,expectedPermit(value),{
    pinnedKeys:{[trusted.keyID]:base64(trusted.publicKeyRaw)}
  }));
}

async function testPinnedPermitVerifierRejectsExpiredPermit(){
  const keys=permitKeyFixture();
  const value=assessment('allow','txf_cccccccccccccccccccccccccccccccc');
  const permit=await issuePermit(value,keys,{
    payload:{issued_at:'2026-01-01T00:00:00Z',expires_at:'2026-01-01T00:00:30Z'}
  });
  await expectError(PermitVerificationError,()=>verifyPermit(permit,expectedPermit(value),{
    pinnedKey:keys.publicKeyRaw,expectedKeyID:keys.keyID,nowMs:Date.parse('2026-01-01T00:01:00Z')
  }));
}

async function testPinnedPermitVerifierRejectsDecisionTamper(){
  const keys=permitKeyFixture();
  const value=assessment('allow','txf_dddddddddddddddddddddddddddddddd');
  const permit=await issuePermit(value,keys);
  const tampered=Object.assign({},value,{summary:'tampered after permit issuance'});
  await expectError(PermitVerificationError,()=>verifyPermit(permit,expectedPermit(tampered),{
    pinnedKey:keys.publicKeyRaw,expectedKeyID:keys.keyID
  }));
}

async function permitFetch(keys,action,mutator){
  return async(_url,options)=>{
    const request=JSON.parse(options.body);
    const fingerprint=await transactionFingerprintFromBase64(request.transaction);
    const value=assessment(action,fingerprint);
    value.enforcement_permit=await issuePermit(value,keys);
    value.enforcement_permit_issued=true;
    value.enforcement_permit_complete=true;
    if(mutator)await mutator(value);
    return response(value);
  };
}

async function testVerifiedWalletRequiresPermit(){
  const keys=permitKeyFixture();
  const {wallet,state}=walletFixture();
  const guarded=createPermitVerifiedWallet(wallet,Object.assign(baseOptions(fetchForActions(['allow'])),{
    origin:'https://app.example.com',
    pinnedKeys:{[keys.keyID]:base64(keys.publicKeyRaw)}
  }));
  await expectError(KoscheiWithheldError,()=>guarded.signTransaction(new FakeTransaction(13)));
  assert.equal(state.single,0);
}

async function testVerifiedWalletSignsOnlyAfterPermitVerification(){
  const keys=permitKeyFixture();
  const {wallet,state}=walletFixture();
  let verificationSeen=false;
  const guarded=createPermitVerifiedWallet(wallet,Object.assign(baseOptions(await permitFetch(keys,'allow')),{
    origin:'https://app.example.com',
    pinnedKeys:{[keys.keyID]:base64(keys.publicKeyRaw)},
    onPermitVerified:async context=>{verificationSeen=context.verification.verified===true}
  }));
  await guarded.signTransaction(new FakeTransaction(14));
  assert.equal(state.single,1);
  assert.equal(verificationSeen,true);
}

async function testVerifiedWalletRejectsTamperedDecision(){
  const keys=permitKeyFixture();
  const {wallet,state}=walletFixture();
  const fetchImpl=await permitFetch(keys,'allow',async value=>{value.summary='tampered response summary'});
  const guarded=createPermitVerifiedWallet(wallet,Object.assign(baseOptions(fetchImpl),{
    origin:'https://app.example.com',
    pinnedKeys:{[keys.keyID]:base64(keys.publicKeyRaw)}
  }));
  await expectError(KoscheiWithheldError,()=>guarded.signTransaction(new FakeTransaction(15)));
  assert.equal(state.single,0);
}

async function testVerifiedWarnStillRequiresFingerprintApproval(){
  const keys=permitKeyFixture();
  const {wallet,state}=walletFixture();
  const guarded=createPermitVerifiedWallet(wallet,Object.assign(baseOptions(await permitFetch(keys,'warn')),{
    origin:'https://app.example.com',
    pinnedKeys:{[keys.keyID]:base64(keys.publicKeyRaw)},
    onWarn:async context=>({approved:true,fingerprint:context.transactionFingerprint})
  }));
  await guarded.signTransaction(new FakeTransaction(16));
  assert.equal(state.single,1);
}

async function main(){
  await testBlockNeverCallsWallet();
  await testWithholdNeverCallsWallet();
  await testAllowSignsAndPreservesMessage();
  await testWarnRequiresFingerprintBoundApproval();
  await testMutationAfterDecisionIsBlocked();
  await testWalletMessageMutationIsRejected();
  await testBatchIsAllOrNothing();
  await testCombinedSignAndSendDisabledByDefault();
  await testResponseFingerprintMismatchBlocks();
  await testSignedIntentCanonicalOrderAndTime();
  await testPinnedPermitVerifierAcceptsValidPermit();
  await testPinnedPermitVerifierRejectsKeySubstitution();
  await testPinnedPermitVerifierRejectsExpiredPermit();
  await testPinnedPermitVerifierRejectsDecisionTamper();
  await testVerifiedWalletRequiresPermit();
  await testVerifiedWalletSignsOnlyAfterPermitVerification();
  await testVerifiedWalletRejectsTamperedDecision();
  await testVerifiedWarnStillRequiresFingerprintApproval();
  console.log('wallet enforcement and pinned permit contract: ok');
}

main().catch(error=>{
  console.error(error);
  process.exit(1);
});