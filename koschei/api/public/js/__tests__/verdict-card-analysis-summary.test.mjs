import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require=createRequire(import.meta.url);
const {normalizeAnalysisSummary,analysisSummaryPresent,advancedAnalysisHTML,mapVerdictCard}=require('../verdict-card-evidence-refs.js');

const analysisSummary={
  schema_version:'koschei-customer-analysis-summary-v2',
  executive_summary:'A signed deterministic C verdict was produced from two grade-changing findings.',
  decision:{grade:'C',verdict:'severe_compounding_rule',signed:true,confidence:'medium',readiness:'actionable_with_gaps',ruleset_version:'rules-v1',signature:'sig-final'},
  evidence_coverage:{architecture_arm_count:14,verified:4,observed:3,inferred:1,pending:5,not_applicable:1,coverage_percent:62,coverage_is_risk_score:false},
  grade_changing_findings:[{rule_id:'URD-C002',severity:'high',evidence_status:'observed',summary:'Dominant-holder position exceeds observed liquidity.',evidence_keys:['holder-liquidity:Mint111'],signatures:['tx111']}],
  watch_items:[{rule_id:'ARD-W001',severity:'watch',evidence_status:'inferred',summary:'Relationship requires verification.'}],
  unresolved_questions:[{module:'Creator Link Analysis',reason:'Creator evidence did not complete.'}],
  recommended_actions:[{priority:1,action:'Review every grade-changing rule.',reason:'The grade is deterministic.'}]
};

test('normalizes the advanced investigation summary without turning coverage into risk',()=>{
  const normalized=normalizeAnalysisSummary(analysisSummary);
  assert.equal(normalized.decision.grade,'C');
  assert.equal(normalized.decision.confidence,'medium');
  assert.equal(normalized.evidence_coverage.coverage_percent,62);
  assert.equal(normalized.evidence_coverage.coverage_is_risk_score,false);
  assert.equal(normalized.grade_changing_findings.length,1);
  assert.equal(normalized.watch_items.length,1);
  assert.equal(analysisSummaryPresent(normalized),true);
});

test('renders decision analysis with findings, gaps and explicit coverage policy',()=>{
  const html=advancedAnalysisHTML(analysisSummary);
  assert.match(html,/DECISION ANALYSIS/);
  assert.match(html,/Why this result was produced/);
  assert.match(html,/62%/);
  assert.match(html,/coverage, not a risk score/);
  assert.match(html,/URD-C002/);
  assert.match(html,/holder-liquidity:Mint111/);
  assert.match(html,/Creator Link Analysis/);
  assert.match(html,/Missing evidence is not safety/);
});

test('maps server analysis summary into the verdict-card view model',()=>{
  const payload={
    target:'Mint111',
    generated_at:'2026-08-03T12:00:00Z',
    final_verdict:{signed:true,signature:'sig-final',grade:'C',verdict:'severe_compounding_rule'},
    holder_intelligence:{available:false},
    modules:[],
    analysis_summary:analysisSummary
  };
  const vm=mapVerdictCard(payload,{lang:'en'});
  assert.equal(vm.analysis_summary.schema_version,'koschei-customer-analysis-summary-v2');
  assert.equal(vm.analysis_summary.decision.grade,'C');
  assert.equal(vm.analysis_summary.unresolved_questions.length,1);
});
