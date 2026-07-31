'use strict';

const assert=require('node:assert/strict');
const {
  createGuardedWallet,
  createSignedIntent,
  normalizePolicy,
  transactionFingerprintFromBase64,
  KoscheiBlockedError,
  KoscheiWithheldError
}=require('../public/js/koschei-wallet-enforcement.js');

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
  return Object.assign({
    ok:true,
    action,
    guard_complete:action!=='withhold',
    transaction_fingerprint:fingerprint,
    network:'solana-mainnet',
    wallet:'Wallet111111111111111111111111111111111',
    summary:`decision:${action}`,
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
  assert.ok(caught instanceof type,`expected ${type.name}, got ${caught?.constructor?.name}`);
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
  console.log('wallet enforcement contract: ok');
}

main().catch(error=>{
  console.error(error);
  process.exit(1);
});
