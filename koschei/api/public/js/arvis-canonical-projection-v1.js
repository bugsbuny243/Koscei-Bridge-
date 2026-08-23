(function(root,factory){const api=factory();if(typeof module==='object'&&module.exports)module.exports=api;root.KoscheiARVISCanonicalProjection=api;})(typeof globalThis!=='undefined'?globalThis:this,function(){
'use strict';
const arr=value=>Array.isArray(value)?value:[];
const obj=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
const text=value=>typeof value==='string'?value.trim():value===undefined||value===null?'':String(value).trim();
const num=value=>Number.isFinite(Number(value))?Number(value):0;
const bool=value=>value===true||String(value||'').toLowerCase()==='true';
const first=(...values)=>{for(const value of values){if(value===undefined||value===null)continue;if(typeof value==='string'&&value.trim()==='')continue;return value;}return undefined;};
const uniqueBy=(items,keyOf)=>{const seen=new Set(),out=[];for(const item of items){const key=text(keyOf(item));if(!key||seen.has(key))continue;seen.add(key);out.push(item);}return out;};

function reportOf(payload){const envelope=obj(payload);return obj(envelope.investigation_report||envelope.report||envelope);}
function moduleID(module){return text(first(module?.module_id,module?.module,module?.id,module?.name));}
function moduleSignals(module){return obj(module?.signals||module?.metrics);}
function rawModuleStatus(module){const signals=moduleSignals(module);return text(first(module?.execution_status,module?.evidence_status,module?.verification_status,module?.status,module?.state,signals.execution_status,signals.evidence_status,signals.verification_status,signals.status,signals.state,signals.data_quality));}
function moduleState(module){
 const raw=rawModuleStatus(module).toLowerCase();
 if(raw.includes('not_applicable')||raw==='n/a')return'not_applicable';
 if(['unavailable','failed','error','missing','not_collected','not_configured','unresolved'].some(value=>raw.includes(value)))return'unavailable';
 if(['partial','observed','inferred','bounded','watch','pending','degraded','insufficient'].some(value=>raw.includes(value)))return'partial';
 if(['completed','complete','verified','available','persisted','resolved','passed','pass','ok'].some(value=>raw.includes(value)))return'complete';
 const signals=moduleSignals(module);
 if(signals.applicable===false)return'not_applicable';
 if(bool(module?.verified)||bool(signals.verified_evidence)||bool(signals.real_onchain_evidence))return'complete';
 return'unknown';
}
function modulesFrom(report,envelope){
 const candidates=[...arr(report.modules),...arr(report.evidence_arms),...arr(obj(report.legacy_14_arm_radar).modules),...arr(envelope.modules)];
 return uniqueBy(candidates,(item,index)=>moduleID(item)||`module-${index}`);
}
function moduleCoverage(modules){
 const out={complete:0,partial:0,unavailable:0,not_applicable:0,unknown:0,total:modules.length};
 for(const module of modules)out[moduleState(module)]++;
 return out;
}
function repeatActorSignals(modules){
 const module=modules.find(item=>moduleID(item).toLowerCase()==='repeat_actor_scan');
 return moduleSignals(module||{});
}
function creatorLifecycle(report,envelope,modules){
 const actor=obj(report.actor_investigation||envelope.actor_investigation),dossier=obj(actor.dossier||report.creator_intelligence||envelope.creator_intelligence),track=obj(dossier.track),repeat=repeatActorSignals(modules);
 const active=num(first(repeat.creator_active_tokens,track.active_token_count,dossier.active_token_count,dossier.liquid_candidates));
 const inactive=num(first(repeat.creator_inactive_or_dead_tokens,track.inactive_or_dead_count,dossier.inactive_or_dead_candidates,dossier.dead_token_count));
 const total=num(first(repeat.creator_total_tokens,track.created_token_count,dossier.created_token_count,dossier.dossier_token_count,active+inactive));
 return{active,inactive,total,recurrence:bool(first(repeat.creator_token_recurrence,false)),status:text(first(repeat.actor_lifecycle_status,dossier.actor_lifecycle_status,track.state,'unknown'))};
}
function creatorWallet(report,envelope){
 const actor=obj(report.actor_investigation||envelope.actor_investigation),relation=obj(actor.current_creator_relation),target=obj(relation.target),relationEvidence=obj(relation.evidence),dossier=obj(actor.dossier||report.creator_intelligence||envelope.creator_intelligence),source=obj(report.source_context||envelope.source_context);
 return text(first(target.creator_wallet,relationEvidence.actor_wallet,relationEvidence.source_wallet,source.creator_wallet,actor.creator_wallet,actor.wallet,dossier.creator_wallet,dossier.wallet,report.creator_wallet,envelope.creator_wallet));
}
function evidenceLabel(item){
 if(typeof item==='string')return item.trim();
 const value=obj(item),metadata=obj(value.metadata);
 const direct=text(first(value.summary,value.claim,value.message,value.title,value.reason,value.description,value.evidence_key,value.relation));
 if(direct)return direct;
 const source=text(first(value.source_wallet,metadata.source_wallet,value.actor_wallet));
 const destination=text(first(value.destination_wallet,metadata.destination_wallet,value.counterpart_id));
 const relation=text(first(value.relation,metadata.relation,value.kind));
 if(source&&destination)return`${source} → ${destination}${relation?` · ${relation}`:''}`;
 const signature=text(first(value.signature,metadata.signature));
 if(signature)return`Transaction evidence · ${signature}`;
 return'';
}
function evidenceFrom(report,envelope){
 const actor=obj(report.actor_investigation||envelope.actor_investigation),dossier=obj(actor.dossier),behavior=obj(report.behavior_signals||envelope.behavior_signals);
 const candidates=[...arr(report.verified_evidence),...arr(report.evidence),...arr(report.evidence_log),...arr(envelope.verified_evidence),...arr(envelope.evidence),...arr(actor.evidence),...arr(dossier.evidence),...arr(behavior.evidence)];
 return uniqueBy(candidates,item=>{const value=obj(item);return text(first(value.evidence_key,value.id,value.signature,evidenceLabel(item)));}).filter(item=>evidenceLabel(item));
}
function normalizeEdge(edge){
 const value=obj(edge),metadata=obj(value.metadata);
 return{
  source:text(first(value.source,value.from,value.source_wallet,value.source_id,metadata.source_wallet,metadata.source_id)),
  target:text(first(value.target,value.to,value.destination,value.destination_wallet,value.target_id,metadata.destination_wallet,metadata.target_id)),
  relation:text(first(value.relation,value.type,value.kind,metadata.relation,'observed_relation')),
  verification_status:text(first(value.verification_status,value.evidence_status,value.status,value.state,metadata.verification_status,'observed')),
  signature:text(first(value.signature,metadata.signature)),slot:num(first(value.slot,metadata.slot)),raw:value
 };
}
function graphEdges(report,envelope){
 const actor=obj(report.actor_investigation||envelope.actor_investigation),actorGraph=obj(actor.evidence_graph),cluster=obj(report.holder_cluster||envelope.holder_cluster),relationship=obj(report.relationship_graph||report.graph||cluster.graph||envelope.relationship_graph);
 const candidates=[...arr(actorGraph.edges),...arr(relationship.edges),...arr(cluster.graph_edges),...arr(report.relationship_edges)];
 return uniqueBy(candidates,edge=>{const item=normalizeEdge(edge);return[item.source,item.target,item.relation,item.signature,item.slot].join('|');}).map(normalizeEdge).filter(edge=>edge.source||edge.target);
}
function canonicalLaunch(report,envelope){
 const source=obj(report.source_context||envelope.source_context),verified=obj(source.canonical_creator_verification),cluster=obj(report.holder_cluster||envelope.holder_cluster),launch=obj(report.launch_forensics||envelope.launch_forensics);
 const verifiedFlag=bool(verified.verified)||bool(source.creator_relation_verified);
 const canonicalSlot=num(first(verified.slot,source.slot));
 const canonicalTime=text(first(source.observed_at,source.created_at,obj(source.creator_resolution).created_at,obj(source.creator_resolution).first_mint_at));
 return{
  canonical_verified:verifiedFlag,canonical_slot:canonicalSlot,canonical_time:canonicalTime,
  launch_slot:num(first(launch.launch_slot,canonicalSlot,cluster.launch_estimate_slot)),
  launch_time:text(first(launch.launch_time,canonicalTime,cluster.launch_estimate_at)),
  launch_time_source:text(first(launch.launch_time_source,verifiedFlag?'verified_canonical_create_transaction':'cluster_launch_estimate')),
  cluster_estimate_slot:num(cluster.launch_estimate_slot),cluster_estimate_at:text(cluster.launch_estimate_at)
 };
}
function project(payload){
 const envelope=obj(payload),report=reportOf(envelope),modules=modulesFrom(report,envelope),coverage=moduleCoverage(modules),actor=obj(report.actor_investigation||envelope.actor_investigation),dossier=obj(actor.dossier||report.creator_intelligence||envelope.creator_intelligence),holder=obj(report.holder_intelligence||envelope.holder_intelligence),distribution=obj(report.holder_distribution||envelope.holder_distribution),graph=graphEdges(report,envelope),evidence=evidenceFrom(report,envelope),lifecycle=creatorLifecycle(report,envelope,modules),final=obj(report.final_verdict||envelope.final_verdict);
 return{
  raw:envelope,report,modules,coverage,actor,dossier,evidence,graph,
  creator_wallet:creatorWallet(report,envelope),creator_lifecycle:lifecycle,launch:canonicalLaunch(report,envelope),
  top1:num(first(holder.top_owner_percentage,holder.top_1_percentage,distribution.top_1_percentage,envelope.largest_holder_percent)),
  top3:num(first(holder.top_3_percentage,distribution.top_3_percentage)),top10:num(first(holder.top_10_percentage,distribution.top_10_percentage,envelope.top_ten_percent)),top20:num(first(holder.top_20_percentage,distribution.top_20_percentage)),
  grade:text(first(final.grade,envelope.grade,'—')).toUpperCase(),signed:final.signed===true||Boolean(first(final.signature,envelope.signature,report.signature)),signature:text(first(final.signature,envelope.signature,report.signature)),ruleset:text(first(final.ruleset_version,report.ruleset_version,envelope.ruleset_version)),target:text(first(report.target,envelope.target,envelope.mint,envelope.address))
 };
}
return{project,moduleState,moduleCoverage,evidenceLabel,normalizeEdge};
});
