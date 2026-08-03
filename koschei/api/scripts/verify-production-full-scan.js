'use strict';

const fs = require('fs');
const path = require('path');

const baseURL = String(process.env.BASE_URL || 'https://tradepigloball.co').replace(/\/$/, '');
const mint = String(process.env.KOSCHEI_FULL_SCAN_MINT || 'HHPpU9u56Bwxov12nf7DXUCuv6h1q5j1xgGS3yukpump').trim();
const outputDir = path.resolve(process.env.OUTPUT_DIR || 'diagnostics');
const timeoutMs = Number(process.env.FULL_SCAN_TIMEOUT_MS || 300000);

function requireObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label}_missing`);
  return value;
}

function requireArray(value, label) {
  if (!Array.isArray(value)) throw new Error(`${label}_missing`);
  return value;
}

function number(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function statusOf(value) {
  if (!value || typeof value !== 'object') return 'missing';
  return String(value.status || value.execution_status || value.verification_status || 'present');
}

function pick(value, keys) {
  const out = {};
  for (const key of keys) {
    if (value && Object.prototype.hasOwnProperty.call(value, key)) out[key] = value[key];
  }
  return out;
}

async function main() {
  if (!mint) throw new Error('full_scan_mint_missing');
  fs.mkdirSync(outputDir, { recursive: true });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error('production_full_scan_timeout')), timeoutMs);
  const startedAt = Date.now();
  let response;
  try {
    response = await fetch(`${baseURL}/api/token/scan`, {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
        'user-agent': 'koschei-production-full-scan-acceptance/1.1.1',
      },
      body: JSON.stringify({ mint, network: 'solana-mainnet' }),
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }

  const raw = await response.text();
  fs.writeFileSync(path.join(outputDir, 'full-scan-http-status.txt'), `${response.status}\n`);
  if (!response.ok) {
    fs.writeFileSync(path.join(outputDir, 'full-scan-error.body'), raw);
    throw new Error(`production_full_scan_http_${response.status}`);
  }

  let payload;
  try {
    payload = JSON.parse(raw);
  } catch (error) {
    fs.writeFileSync(path.join(outputDir, 'full-scan-invalid-json.body'), raw);
    throw new Error(`production_full_scan_invalid_json:${error.message}`);
  }

  const report = requireObject(payload.investigation_report, 'investigation_report');
  const summary = requireObject(payload.analysis_summary || report.analysis_summary, 'analysis_summary');
  const nestedSummary = requireObject(report.analysis_summary, 'investigation_report_analysis_summary');
  const decision = requireObject(summary.decision, 'analysis_summary_decision');
  const coverage = requireObject(summary.evidence_coverage, 'analysis_summary_evidence_coverage');
  const finalVerdict = requireObject(report.final_verdict, 'final_verdict');
  const topFinalVerdict = requireObject(payload.final_verdict || finalVerdict, 'top_level_final_verdict');
  const modules = requireArray(coverage.modules, 'evidence_coverage_modules');
  const actions = requireArray(summary.recommended_actions, 'recommended_actions');
  const unresolved = requireArray(summary.unresolved_questions, 'unresolved_questions');
  const gradeDetermining = requireArray(summary.grade_changing_findings, 'grade_changing_findings');
  const supporting = requireArray(summary.supporting_findings, 'supporting_findings');
  const triggeredGroups = requireArray(summary.triggered_evidence_groups, 'triggered_evidence_groups');
  const watchItems = requireArray(summary.watch_items, 'watch_items');

  if (String(payload.mint || '') !== mint) throw new Error('token_scan_mint_mismatch');
  if (String(report.target || '') !== mint) throw new Error('investigation_report_target_mismatch');
  if (String(payload.response_schema_version || '') !== 'koschei-customer-investigation-response-v3') throw new Error('response_schema_mismatch');
  if (String(summary.schema_version || '') !== 'koschei-customer-analysis-summary-v3') throw new Error('analysis_summary_schema_mismatch');
  if (String(nestedSummary.schema_version || '') !== 'koschei-customer-analysis-summary-v3') throw new Error('nested_analysis_summary_schema_mismatch');
  if (number(coverage.architecture_arm_count) !== 14) throw new Error('architecture_arm_count_not_14');
  if (coverage.coverage_is_risk_score !== false) throw new Error('coverage_misrepresented_as_risk_score');
  if (!modules.length) throw new Error('evidence_coverage_modules_empty');
  if (!actions.length) throw new Error('recommended_actions_empty');

  const verdictFields = ['grade', 'verdict', 'signed', 'signature', 'ruleset_version'];
  for (const field of verdictFields) {
    if (String(finalVerdict[field] ?? '') !== String(decision[field] ?? '')) throw new Error(`nested_final_verdict_${field}_mismatch`);
    if (String(topFinalVerdict[field] ?? '') !== String(decision[field] ?? '')) throw new Error(`top_final_verdict_${field}_mismatch`);
  }
  if (String(decision.ruleset_version || '') !== 'koschei-unified-radar-rules-v1.1.1') throw new Error('unified_ruleset_not_v111');
  if (number(decision.grade_determining_rule_count) !== gradeDetermining.length) throw new Error('grade_determining_count_mismatch');
  if (number(decision.triggered_evidence_group_count) !== triggeredGroups.length) throw new Error('triggered_group_count_mismatch');
  if (number(decision.supporting_evidence_group_count) !== supporting.length) throw new Error('supporting_group_count_mismatch');
  if (String(decision.grading_semantics || '') !== 'distinct_rule_ids_not_evidence_group_count') throw new Error('grading_semantics_missing');
  const decisionPath = Array.isArray(decision.decision_path) ? decision.decision_path.join('\n') : '';
  if (/\b5 distinct\b/i.test(decisionPath)) throw new Error('evidence_groups_still_counted_as_distinct_rules');

  const requiredReportSections = [
    'holder_distribution', 'holder_intelligence', 'holder_cluster', 'launch_forensics', 'market',
    'lp_control', 'jupiter_market_context', 'exit_liquidity', 'program_security', 'actor_investigation',
    'full_scan_live_evidence', 'evidence_references', 'threat_anticipation',
  ];
  for (const section of requiredReportSections) requireObject(report[section], `report_${section}`);

  const completed = number(coverage.verified) + number(coverage.observed) + number(coverage.inferred);
  if (completed < 1) throw new Error('no_completed_evidence_arm');

  const liveEvidence = requireObject(report.full_scan_live_evidence, 'full_scan_live_evidence');
  const actorInvestigation = requireObject(report.actor_investigation, 'actor_investigation');
  const actorRun = requireObject(actorInvestigation.integration_run, 'actor_investigation_integration_run');
  const lpControl = requireObject(report.lp_control, 'lp_control');
  const jupiter = requireObject(report.jupiter_market_context, 'jupiter_market_context');
  const exitLiquidity = requireObject(report.exit_liquidity, 'exit_liquidity');
  const programSecurity = requireObject(report.program_security, 'program_security');
  const holder = requireObject(report.holder_intelligence, 'holder_intelligence');
  const launch = requireObject(report.launch_forensics, 'launch_forensics');
  const market = requireObject(report.market, 'market');

  const artifact = {
    schema_version: 'koschei-production-full-scan-result-v2',
    generated_at: new Date().toISOString(),
    elapsed_ms: Date.now() - startedAt,
    endpoint: `${baseURL}/api/token/scan`,
    target: mint,
    network: String(payload.network || report.network || 'solana-mainnet'),
    response_contract: {
      response_schema: payload.response_schema_version,
      top_level_analysis_summary: Boolean(payload.analysis_summary),
      nested_analysis_summary: Boolean(report.analysis_summary),
      analysis_summary_schema: summary.schema_version,
      report_schema: report.schema_version,
      final_verdict_consistent: true,
    },
    legacy_token_surface: pick(payload, [
      'score', 'risk_level', 'final_policy', 'verdict_withheld', 'supply', 'decimals',
      'mint_authority', 'freeze_authority', 'largest_holder_percent', 'top_ten_percent',
      'token_program', 'token_2022', 'extension_resolution_status', 'extension_evidence_complete',
    ]),
    decision,
    executive_summary: summary.executive_summary,
    evidence_coverage: {
      architecture_arm_count: coverage.architecture_arm_count,
      applicable_arm_count: coverage.applicable_arm_count,
      verified: coverage.verified,
      observed: coverage.observed,
      inferred: coverage.inferred,
      pending: coverage.pending,
      not_applicable: coverage.not_applicable,
      completed: coverage.completed,
      coverage_percent: coverage.coverage_percent,
      coverage_is_risk_score: coverage.coverage_is_risk_score,
      modules,
    },
    grade_determining_findings: gradeDetermining,
    supporting_findings: supporting,
    triggered_evidence_groups: triggeredGroups,
    watch_items: watchItems,
    non_triggered_observations: Array.isArray(summary.non_triggered_observations) ? summary.non_triggered_observations : [],
    unresolved_questions: unresolved,
    recommended_actions: actions,
    final_verdict: finalVerdict,
    evidence_surfaces: {
      holder: pick(holder, ['available', 'status', 'top_1_percentage', 'top_10_percentage', 'circulating_supply', 'final_verdict_blocked', 'limitations']),
      launch: pick(launch, ['available', 'status', 'launch_time', 'age_seconds', 'creator_wallet', 'findings', 'limitations']),
      market: pick(market, ['available', 'status', 'price_usd', 'market_cap_usd', 'liquidity_usd', 'volume_24h_usd', 'best_pair_address']),
      lp_control: { status: statusOf(lpControl), ...pick(lpControl, ['available', 'pool_address', 'lp_mint', 'burned_share_pct', 'creator_lp_share_pct', 'locked_until', 'limitations']) },
      jupiter_market_context: { status: statusOf(jupiter), ...pick(jupiter, ['available', 'price_available', 'price_usd', 'sell_impact_available', 'estimated_price_impact_pct', 'quote_context_slot', 'limitations']) },
      exit_liquidity: { status: statusOf(exitLiquidity), ...pick(exitLiquidity, ['available', 'quote_only', 'provider', 'tiers', 'limitations']) },
      program_security: { status: statusOf(programSecurity), ...pick(programSecurity, ['available', 'authority_coverage_complete', 'age_coverage_complete', 'programs', 'limitations']) },
      actor_investigation: {
        wallet: actorInvestigation.wallet,
        store_status: actorInvestigation.store_status,
        run_status: actorRun.status,
        live_requested: actorRun.live_requested,
        funding_origin_persistence: actorRun.funding_origin_persistence,
        rule_verdict_persistence: actorRun.rule_verdict_persistence,
        limitations: actorRun.limitations,
      },
      full_scan_live_evidence: pick(liveEvidence, [
        'status', 'rpc_configured', 'wallets_requested', 'wallets_completed', 'signatures_seen',
        'transactions_parsed', 'relevant_transactions', 'rpc_failures', 'launch_signer', 'wallet_coverage', 'limitations',
      ]),
    },
    evidence_references: report.evidence_references,
    threat_anticipation: report.threat_anticipation,
    interpretation_policy: summary.interpretation_policy,
  };

  fs.writeFileSync(path.join(outputDir, 'full-scan-result.json'), `${JSON.stringify(artifact, null, 2)}\n`);
  fs.writeFileSync(path.join(outputDir, 'full-scan-response.json'), `${JSON.stringify(payload, null, 2)}\n`);

  console.log(`FULL_SCAN_HTTP_STATUS=${response.status}`);
  console.log(`FULL_SCAN_ELAPSED_MS=${artifact.elapsed_ms}`);
  console.log(`FULL_SCAN_TARGET=${mint}`);
  console.log(`FULL_SCAN_GRADE=${String(decision.grade || '-')}`);
  console.log(`FULL_SCAN_SIGNED=${String(Boolean(decision.signed))}`);
  console.log(`FULL_SCAN_RULESET=${String(decision.ruleset_version || 'unknown')}`);
  console.log(`FULL_SCAN_GRADE_DETERMINING_RULES=${gradeDetermining.length}`);
  console.log(`FULL_SCAN_SUPPORTING_GROUPS=${supporting.length}`);
  console.log(`FULL_SCAN_DISTINCT_COMPOUNDING_RULES=${number(decision.distinct_compounding_rule_count)}`);
  console.log(`FULL_SCAN_CONFIDENCE=${String(decision.confidence || 'unknown')}`);
  console.log(`FULL_SCAN_READINESS=${String(decision.readiness || 'unknown')}`);
  console.log(`FULL_SCAN_COVERAGE=${number(coverage.coverage_percent)}%`);
  console.log(`FULL_SCAN_ARMS=verified:${number(coverage.verified)},observed:${number(coverage.observed)},inferred:${number(coverage.inferred)},pending:${number(coverage.pending)},not_applicable:${number(coverage.not_applicable)}`);
  console.log(`FULL_SCAN_LIVE_STATUS=${String(liveEvidence.status || 'unknown')}`);
  console.log(`FULL_SCAN_ACTOR_STATUS=${String(actorRun.status || 'unknown')}`);
  console.log('PRODUCTION_FULL_SCAN_ACCEPTED=true');
}

main().catch((error) => {
  fs.mkdirSync(outputDir, { recursive: true });
  fs.writeFileSync(path.join(outputDir, 'full-scan-probe-error.txt'), `${error.stack || error.message || String(error)}\n`);
  console.error(`PRODUCTION_FULL_SCAN_FAILURE: ${error.stack || error.message || String(error)}`);
  process.exit(1);
});
