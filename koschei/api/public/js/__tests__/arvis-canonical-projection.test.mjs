import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {project,moduleState,evidenceLabel}=require('../arvis-canonical-projection-v1.js');

const creator='D9gQ6RhKEpnobPBUdWY5bPQt2p3zGk3iVz6ChpUi2ArA';
const target='Ai66LHZG9MCzg1WKdawwqduVAXpNDUuV8M3uyq5ppump';

function productionShape(){
 const modules=Array.from({length:11},(_,index)=>({module_id:`verified_module_${index}`,signals:{execution_status:'completed',evidence_status:'verified_rpc_observation',applicable:true}}));
 modules.push({module_id:'walletless_claim_shield',signals:{evidence_status:'insufficient_evidence',applicable:true}});
 modules.push({module_id:'claim_surface_risk',signals:{evidence_status:'insufficient_evidence',applicable:true}});
 modules.push({module_id:'repeat_actor_scan',signals:{execution_status:'completed',evidence_status:'verified_actor_lifecycle',creator_wallet:creator,creator_active_tokens:2,creator_inactive_or_dead_tokens:15,creator_total_tokens:17,creator_token_recurrence:true,actor_lifecycle_status:'verified_recurrence'}});
 return{
  target,modules,
  source_context:{creator_wallet:creator,creator_relation_verified:true,slot:435366376,observed_at:'2026-07-26T16:24:38Z',canonical_creator_verification:{verified:true,slot:435366376,status:'verified_canonical_create_transaction'}},
  holder_cluster:{launch_estimate_slot:441064258,launch_estimate_at:'2026-08-23T02:59:43Z'},
  actor_investigation:{
   wallet:creator,
   dossier:{wallet:creator,evidence:[{evidence_key:'created_mint:sig-1',relation:'created_token',actor_wallet:creator,counterpart_id:'MintOld',signature:'sig-1'}]},
   evidence_graph:{available:true,edge_count:2,edges:[{source:creator,target:'MintOld',relation:'created_token',verification_status:'verified',signature:'sig-1',slot:400},{source:creator,target:'HolderOld',relation:'direct_token_transfer',verification_status:'verified',signature:'sig-2',slot:401}]}
  },
  evidence:[{summary:'Canonical creator relation verified',status:'verified'}],
  final_verdict:{grade:'D',signed:true,signature:'final-signature',ruleset_version:'koschei-unified-radar-rules-v1.4.0'}
 };
}

test('canonical projection reads nested module state and actor truth from production-shaped payload',()=>{
 const vm=project(productionShape());
 assert.equal(vm.coverage.total,14);
 assert.equal(vm.coverage.complete,12);
 assert.equal(vm.coverage.partial,2);
 assert.equal(vm.coverage.unavailable,0);
 assert.equal(vm.creator_wallet,creator);
 assert.deepEqual(vm.creator_lifecycle,{active:2,inactive:15,total:17,recurrence:true,status:'verified_recurrence'});
 assert.equal(vm.graph.length,2);
 assert.equal(vm.evidence.length,2);
 assert.equal(vm.evidence.map(evidenceLabel).some(label=>label.includes('[object Object]')),false);
 assert.equal(vm.launch.canonical_verified,true);
 assert.equal(vm.launch.canonical_slot,435366376);
 assert.equal(vm.launch.cluster_estimate_slot,441064258);
 assert.equal(vm.launch.launch_slot,435366376);
});

test('not-applicable is not misreported as unavailable',()=>{
 assert.equal(moduleState({module_id:'optional',signals:{execution_status:'not_applicable',applicable:false}}),'not_applicable');
 const vm=project({modules:[{module_id:'optional',signals:{execution_status:'not_applicable',applicable:false}}]});
 assert.equal(vm.coverage.not_applicable,1);
 assert.equal(vm.coverage.unavailable,0);
});

test('object evidence always receives human-readable canonical label',()=>{
 assert.equal(evidenceLabel({summary:'Verified fact'}),'Verified fact');
 assert.match(evidenceLabel({source_wallet:'Creator',destination_wallet:'Holder',relation:'direct_transfer'}),/Creator → Holder/);
 assert.match(evidenceLabel({signature:'abc'}),/Transaction evidence/);
 assert.equal(evidenceLabel({foo:'bar'}),'');
});
