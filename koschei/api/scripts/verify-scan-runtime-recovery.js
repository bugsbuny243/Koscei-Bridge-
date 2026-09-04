'use strict';

const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

const rootDir=path.resolve(__dirname,'..');
const ownerSource=fs.readFileSync(path.join(rootDir,'public','js','owner-court-ui.js'),'utf8');
const publicSource=fs.readFileSync(path.join(rootDir,'public','js','public-solana-scan.js'),'utf8');
const ownerHTML=fs.readFileSync(path.join(rootDir,'public','owner-production.html'),'utf8');
const scanHTML=fs.readFileSync(path.join(rootDir,'public','scan.html'),'utf8');

function assert(condition,message){if(!condition)throw new Error(message)}

async function ownerScenario(status,payload){
  const resultRoot={innerHTML:'',querySelector:()=>null,insertAdjacentHTML:()=>{}};
  let directCalls=0;
  let jobCalls=0;
  const directResult={ok:true,source:'live_direct_scan'};
  const window={OwnerRadarKit:{
    scan:async(target,root)=>{
      directCalls++;
      assert(target==='test-mint','direct fallback target changed');
      assert(root===resultRoot,'direct fallback result root changed');
      return directResult;
    },
    renderUnified:()=>{}
  }};
  const context={
    window,
    document:{getElementById:id=>id==='result'?resultRoot:null},
    fetch:async()=>{
      jobCalls++;
      return{ok:status>=200&&status<300,status,json:async()=>payload};
    },
    setTimeout,
    clearTimeout,
    Promise
  };
  vm.runInNewContext(ownerSource,context,{filename:'owner-court-ui.js'});
  let result;
  let error;
  try{result=await window.OwnerRadarKit.scan('test-mint','result')}catch(caught){error=caught}
  return{result,error,directCalls,jobCalls};
}

(async()=>{
  const unavailable=await ownerScenario(503,{error:'database unavailable'});
  assert(!unavailable.error,`stateless owner fallback failed: ${unavailable.error?.message}`);
  assert(unavailable.jobCalls===1,'canonical owner job was not attempted exactly once');
  assert(unavailable.directCalls===1,'live owner scan fallback did not run exactly once');
  assert(unavailable.result?.source==='live_direct_scan','live owner scan result was not returned');

  const invalid=await ownerScenario(422,{ok:false,error:'unsupported_canonical_job_target'});
  assert(Boolean(invalid.error),'invalid owner target error was swallowed');
  assert(invalid.directCalls===0,'invalid owner target incorrectly fell back to a second scan');

  const timeout=publicSource.match(/const TOKEN_SCAN_TIMEOUT_MS=(\d+);/);
  assert(timeout,'public token scan timeout constant is missing');
  assert(Number(timeout[1])>=180000,'public token scan aborts before the server investigation budget');
  assert(publicSource.includes("url.includes('/api/token/scan')?TOKEN_SCAN_TIMEOUT_MS"),'public token request does not use the extended timeout');
  assert(ownerHTML.includes('/js/owner-court-ui.js?v=4'),'owner scan recovery cache key is stale');
  assert(scanHTML.includes('/js/public-solana-scan.js?v=12'),'public scan recovery cache key is stale');

  console.log('stateless owner fallback and public scan timeout contracts: ok');
})().catch(error=>{
  console.error(error);
  process.exitCode=1;
});
