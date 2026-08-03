'use strict';

const card=require('../public/js/verdict-card-evidence-refs.js');

const rowIDs=[
  'launch','mint','freeze','wash','address','liquidity','funding','concentration','sniper','first-buyer',
  'track','creator-sell','dominant-exit','liq-move','program','metadata','claim','mev','distribution','signed'
];

function references(){
  return Object.fromEntries(rowIDs.map(id=>[id,{
    wallets:id==='concentration'?['Owner111']:[],
    accounts:['Mint111'],
    signatures:id==='signed'?['VerdictSignature111']:[],
    slots:id==='launch'?[100]:[],
    evidence_keys:[`row:${id}`]
  }]));
}

function analysisSummary(){
  return{
    schema_version:'koschei-customer-analysis-summary-v3',
    executive_summary:'A signed deterministic F verdict was produced by one grade-determining rule.',
    decision:{
      grade:'F',verdict:'hard_trigger',signed:true,confidence:'medium',readiness:'actionable_with_gaps',
      ruleset_version:'koschei-unified-radar-rules-v1.1.1',signature:'VerdictSignature111',
      grade_determining_rule_count:1,triggered_evidence_group_count:5,supporting_evidence_group_count:4,
      distinct_compounding_rule_count:1,grading_semantics:'distinct_rule_ids_not_evidence_group_count'
    },
    evidence_coverage:{architecture_arm_count:14,verified:0,observed:9,inferred:0,pending:3,not_applicable:2,coverage_percent:75,coverage_is_risk_score:false},
    grade_changing_findings:[{rule_id:'URD-C005',title:'Owner-resolved dominant concentration',severity:'critical',evidence_status:'verified',summary:'Owner concentration met the F cap.',evidence_keys:['state:owner'],signatures:['OwnerTx111']}],
    supporting_findings:[
      {rule_id:'ARD-C004',title:'Repeated direct transfer relation',evidence_status:'verified',grade_effect:'supporting_context',summary:'Supporting evidence group one.',evidence_keys:['row:one'],signatures:['Tx111']},
      {rule_id:'ARD-C004',title:'Repeated direct transfer relation',evidence_status:'verified',grade_effect:'supporting_context',summary:'Supporting evidence group two.',evidence_keys:['row:two'],signatures:['Tx222']},
      {rule_id:'ARD-C004',title:'Repeated direct transfer relation',evidence_status:'verified',grade_effect:'supporting_context',summary:'Supporting evidence group three.',evidence_keys:['row:three'],signatures:['Tx333']},
      {rule_id:'ARD-C004',title:'Repeated direct transfer relation',evidence_status:'verified',grade_effect:'supporting_context',summary:'Supporting evidence group four.',evidence_keys:['row:four'],signatures:['Tx444']}
    ],
    triggered_evidence_groups:[],watch_items:[],non_triggered_observations:[],
    unresolved_questions:[{module:'Holder Concentration',reason:'Role evidence remains pending.'}],
    recommended_actions:[{priority:1,action:'Review the grade-determining rule.',reason:'Distinct rules control grading.'}]
  };
}

function fixture(){
  return{
    target:'Mint111',
    generated_at:'2026-07-17T07:00:00Z',
    final_verdict:{grade:'D',verdict:'hard_trigger',signed:true,signature:'VerdictSignature111',ruleset_version:'koschei-unified-radar-rules-v1.1.1',generated_at:'2026-07-17T07:00:00Z'},
    holder_intelligence:{available:true,owner_aggregation_applied:true,circulating_supply:1000000,top_owner_percentage:55,rows:[{owner_wallet:'Owner111',owner_resolved:true,risk_bearing:true,excluded_from_holder_risk:false,token_accounts:['OwnerATA111']}]},
    holder_distribution:{top_1_percentage:55},
    holder_concentration_context:{available:true,status:'observed_corpus_percentile',top_share_pct:55,top_percentile:7.25,sample_count:50000,bucket_width:1,method:'distinct_mint_latest_owner_resolved_top_share_histogram'},
    market:{available:true,liquidity_usd:100000,best_pair_address:'Pool111'},
    lp_control:{available:true,status:'burned',pool_address:'Pool111',lp_mint:'LP111',token_vault:'Vault111',quote_vault:'Quote111',read_slot:200,burned_share_pct:99,evidence_keys:['pool:Pool111@200']},
    launch_forensics:{available:true,launch_time:'2026-07-17T06:00:00Z',launch_slot:100,owners_requested:1,owners_with_trade_history:1,ledger_trade_count:1,sniper_count:0,creator_linked_count:0,profiles:[]},
    trade_ledger_aggregates:{available:true,trade_count:1,round_trip_wallet_count:0},
    actor_investigation:{dossier:{tokens:[],related_actors:[],evidence:[]}},
    behavior_signals:{signals:[{rule_id:'URD-C005',evidence_status:'verified',triggered:true,summary:'Owner concentration observed.',evidence_keys:['owner:Owner111']}]},
    modules:[
      {module_id:'token_authority_scanner',signals:{execution_status:'completed',mint_authority_present:false,freeze_authority_present:false},verified:true},
      {module_id:'holder_concentration',signals:{execution_status:'completed',top_owner_percentage:55},verified:true},
      {module_id:'liquidity_movement',signals:{execution_status:'completed',liquidity_usd:100000},verified:true},
      {module_id:'launch_distribution',signals:{execution_status:'completed'},verified:true}
    ],
    evidence_references:references(),
    analysis_summary:analysisSummary()
  };
}

const vm=card.mapVerdictCard(fixture(),{lang:'tr'});
if(!vm||!Array.isArray(vm.checklist)||vm.checklist.length!==20)throw new Error(`expected 20 rows, got ${vm?.checklist?.length}`);
for(const row of vm.checklist){
  if(!card.refsPresent(row.refs))throw new Error(`row ${row.id} has no evidence reference`);
}
const concentration=vm.checklist.find(row=>row.id==='concentration');
if(!concentration.refs.wallets.includes('Owner111'))throw new Error('owner wallet reference missing');
if(!String(concentration.value).includes('50.000'))throw new Error(`corpus sample count missing: ${concentration.value}`);
if(!String(concentration.value).includes('7,25'))throw new Error(`corpus percentile missing: ${concentration.value}`);
if(concentration.corpus_context?.method!=='distinct_mint_latest_owner_resolved_top_share_histogram')throw new Error('corpus method missing');
const signed=vm.checklist.find(row=>row.id==='signed');
if(!signed.refs.signatures.includes('VerdictSignature111'))throw new Error('verdict signature reference missing');

if(vm.analysis_summary.schema_version!=='koschei-customer-analysis-summary-v3')throw new Error('v3 analysis summary missing');
if(vm.analysis_summary.grade_changing_findings.length!==1)throw new Error('grade-determining findings were not preserved');
if(vm.analysis_summary.supporting_findings.length!==4)throw new Error('supporting findings were dropped');
if(vm.analysis_summary.decision.distinct_compounding_rule_count!==1)throw new Error('distinct compounding count was dropped');
const analysisHTML=card.advancedAnalysisHTML(vm.analysis_summary);
if(!analysisHTML.includes('Supporting evidence groups (4)'))throw new Error('supporting evidence heading was not rendered');
if(!analysisHTML.includes('Supporting evidence group four.'))throw new Error('supporting evidence rows were not rendered');
if(!analysisHTML.includes('do not count as separate grading rules'))throw new Error('supporting evidence grading policy missing');
if(!analysisHTML.includes('Grade-determining findings (1)'))throw new Error('grade-determining heading missing');

const missing=fixture();
missing.evidence_references.concentration={wallets:[],accounts:[],signatures:[],slots:[],evidence_keys:[]};
const degraded=card.mapVerdictCard(missing,{lang:'tr'}).checklist.find(row=>row.id==='concentration');
if(degraded.state!=='arm_pending')throw new Error(`missing evidence reference did not degrade row: ${degraded.state}`);
if(!String(degraded.value).includes('Kanıt referansı'))throw new Error('degraded row did not explain reference gap');

const smallCorpus=fixture();
smallCorpus.holder_concentration_context={available:false,status:'corpus_sample_too_small',sample_count:12,top_share_pct:55};
const withheld=card.mapVerdictCard(smallCorpus,{lang:'tr'}).checklist.find(row=>row.id==='concentration');
if(String(withheld.value).includes('farklı mint corpus'))throw new Error('small corpus rendered a percentile');

console.log('verdict-card evidence reference, supporting findings and corpus contract: ok');
