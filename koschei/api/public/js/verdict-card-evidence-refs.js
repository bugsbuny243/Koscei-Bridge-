(function(root,factory){
  const api=factory(root.KoscheiVerdictCard,typeof module==='object'&&module.exports?require('./verdict-card-market-context.js'):null);
  if(typeof module==='object'&&module.exports)module.exports=api;
  if(api&&api.mapVerdictCard)root.KoscheiVerdictCard=api;
})(typeof globalThis!=='undefined'?globalThis:this,function(browserBase,nodeBase){
  'use strict';
  const base=browserBase||nodeBase;
  if(!base||typeof base.mapVerdictCard!=='function')return base;
  const rawMap=base.mapVerdictCard;
  const obj=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
  const arr=value=>Array.isArray(value)?value:[];
  const text=value=>String(value??'').trim();
  const unique=values=>[...new Set(values.map(text).filter(Boolean))].sort();
  const positiveSlots=values=>[...new Set(values.map(Number).filter(value=>Number.isSafeInteger(value)&&value>0))].sort((a,b)=>a-b);
  const number=value=>{const parsed=Number(value);return Number.isFinite(parsed)?parsed:null};
  const escapeHTML=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
  function normalize(value){
    value=obj(value);
    return{
      wallets:unique(arr(value.wallets)),
      accounts:unique(arr(value.accounts)),
      signatures:unique(arr(value.signatures)),
      slots:positiveSlots(arr(value.slots)),
      evidence_keys:unique(arr(value.evidence_keys))
    };
  }
  function refsPresent(value){
    value=normalize(value);
    return value.wallets.length+value.accounts.length+value.signatures.length+value.slots.length+value.evidence_keys.length>0;
  }
  function normalizeAnalysisSummary(value){
    value=obj(value);
    const decision=obj(value.decision),coverage=obj(value.evidence_coverage);
    return{
      schema_version:text(value.schema_version),
      executive_summary:text(value.executive_summary),
      decision:{
        grade:text(decision.grade)||'-',
        verdict:text(decision.verdict)||'evidence_pending',
        signed:decision.signed===true,
        confidence:text(decision.confidence)||'low',
        readiness:text(decision.readiness)||'evidence_pending',
        ruleset_version:text(decision.ruleset_version),
        signature:text(decision.signature)
      },
      evidence_coverage:{
        architecture_arm_count:number(coverage.architecture_arm_count)??14,
        verified:number(coverage.verified)??0,
        observed:number(coverage.observed)??0,
        inferred:number(coverage.inferred)??0,
        pending:number(coverage.pending)??0,
        not_applicable:number(coverage.not_applicable)??0,
        coverage_percent:number(coverage.coverage_percent)??0,
        coverage_is_risk_score:coverage.coverage_is_risk_score===true
      },
      grade_changing_findings:arr(value.grade_changing_findings).map(obj),
      watch_items:arr(value.watch_items).map(obj),
      non_triggered_observations:arr(value.non_triggered_observations).map(obj),
      unresolved_questions:arr(value.unresolved_questions).map(obj),
      recommended_actions:arr(value.recommended_actions).map(obj)
    };
  }
  function analysisSummaryPresent(summary){
    summary=normalizeAnalysisSummary(summary);
    return Boolean(summary.schema_version||summary.executive_summary||summary.grade_changing_findings.length||summary.unresolved_questions.length);
  }
  function evidenceReferenceHTML(item){
    const keys=unique(arr(item.evidence_keys)),signatures=unique(arr(item.signatures));
    if(!keys.length&&!signatures.length)return'';
    return `<div class="advanced-analysis-refs">${keys.slice(0,4).map(value=>`<code>evidence ${escapeHTML(value)}</code>`).join('')}${signatures.slice(0,4).map(value=>`<code>tx ${escapeHTML(value)}</code>`).join('')}</div>`;
  }
  function findingHTML(item,kind){
    item=obj(item);
    const status=text(item.evidence_status)||'unverified';
    const severity=text(item.severity)||kind;
    return `<li class="advanced-analysis-item ${escapeHTML(kind)}"><div><strong>${escapeHTML(item.rule_id||item.title||'Evidence finding')}</strong><span>${escapeHTML(severity.toUpperCase())} · ${escapeHTML(status.toUpperCase())}</span></div><p>${escapeHTML(item.summary||item.reason||'No narrative was attached.')}</p>${evidenceReferenceHTML(item)}</li>`;
  }
  function unresolvedHTML(item){
    item=obj(item);
    const label=text(item.module)||text(item.title)||text(item.module_id)||text(item.rule_id)||'Evidence question';
    return `<li><strong>${escapeHTML(label)}</strong><p>${escapeHTML(item.reason||'Evidence did not complete in this scan.')}</p></li>`;
  }
  function actionHTML(item){
    item=obj(item);
    return `<li><span>${escapeHTML(item.priority||'—')}</span><div><strong>${escapeHTML(item.action||'Review the attached evidence.')}</strong><p>${escapeHTML(item.reason||'')}</p></div></li>`;
  }
  function advancedAnalysisHTML(summary){
    summary=normalizeAnalysisSummary(summary);
    const decision=summary.decision,coverage=summary.evidence_coverage;
    const findings=summary.grade_changing_findings.map(item=>findingHTML(item,'finding')).join('');
    const watch=summary.watch_items.map(item=>findingHTML(item,'watch')).join('');
    const unresolved=summary.unresolved_questions.slice(0,8).map(unresolvedHTML).join('');
    const actions=summary.recommended_actions.slice(0,6).map(actionHTML).join('');
    return `<section class="advanced-investigation-summary-card" data-advanced-investigation-summary>
      <div class="advanced-analysis-head"><div><span>DECISION ANALYSIS</span><h3>Why this result was produced</h3></div><b>${escapeHTML(decision.grade)}</b></div>
      <p class="advanced-analysis-summary">${escapeHTML(summary.executive_summary||'The deterministic evidence summary is unavailable.')}</p>
      <div class="advanced-analysis-metrics">
        <div><span>Confidence</span><strong>${escapeHTML(decision.confidence.toUpperCase())}</strong><small>${escapeHTML(decision.readiness.replaceAll('_',' '))}</small></div>
        <div><span>Evidence coverage</span><strong>${escapeHTML(coverage.coverage_percent)}%</strong><small>coverage, not a risk score</small></div>
        <div><span>14-arm state</span><strong>${escapeHTML(coverage.verified)}V · ${escapeHTML(coverage.observed)}O</strong><small>${escapeHTML(coverage.pending)} pending · ${escapeHTML(coverage.not_applicable)} N/A</small></div>
      </div>
      <div class="advanced-analysis-grid">
        <div><h4>Grade-changing findings (${summary.grade_changing_findings.length})</h4><ul>${findings||'<li class="advanced-analysis-empty">No verified or observed grade-changing rule was attached.</li>'}</ul></div>
        <div><h4>Watch-only signals (${summary.watch_items.length})</h4><ul>${watch||'<li class="advanced-analysis-empty">No watch-only signal was attached.</li>'}</ul></div>
      </div>
      ${unresolved?`<div class="advanced-analysis-section"><h4>Unresolved evidence questions (${summary.unresolved_questions.length})</h4><ul class="advanced-unresolved">${unresolved}</ul></div>`:''}
      ${actions?`<div class="advanced-analysis-section"><h4>Priority actions</h4><ol class="advanced-actions">${actions}</ol></div>`:''}
      <p class="advanced-analysis-policy">Missing evidence is not safety. INFERRED stays watch-only. UNVERIFIED evidence cannot change the grade. Capability is not proof of malicious intent.</p>
    </section>`;
  }
  function installAdvancedAnalysisStyle(){
    if(typeof document==='undefined'||document.querySelector('style[data-advanced-investigation-summary]'))return;
    const style=document.createElement('style');
    style.dataset.advancedInvestigationSummary='1';
    style.textContent='.advanced-investigation-summary-card{margin-top:18px;padding:20px;border:1px solid #18ffb233;border-radius:22px;background:linear-gradient(180deg,#07131a,#040a0f);box-shadow:0 18px 44px #0006}.advanced-analysis-head{display:flex;justify-content:space-between;align-items:center;gap:16px}.advanced-analysis-head span{color:#6fffd5;font:900 10px var(--k-mono,monospace);letter-spacing:.12em}.advanced-analysis-head h3{margin:5px 0 0;font-size:21px}.advanced-analysis-head>b{display:grid;place-items:center;min-width:62px;height:62px;border-radius:17px;color:#00110d;background:linear-gradient(135deg,#18ffb2,#45cfff);font-size:30px}.advanced-analysis-summary{margin-top:14px;color:#c8dbe4;line-height:1.65}.advanced-analysis-metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:9px;margin-top:15px}.advanced-analysis-metrics>div{padding:13px;border:1px solid #ffffff14;border-radius:15px;background:#ffffff06}.advanced-analysis-metrics span,.advanced-analysis-metrics small{display:block;color:#7893a2;font-size:10px}.advanced-analysis-metrics strong{display:block;margin:5px 0;font:900 20px var(--k-mono,monospace)}.advanced-analysis-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:17px}.advanced-analysis-grid>div,.advanced-analysis-section{padding:14px;border:1px solid #ffffff12;border-radius:17px;background:#ffffff04}.advanced-analysis-grid h4,.advanced-analysis-section h4{margin:0 0 10px;font-size:14px}.advanced-analysis-grid ul,.advanced-unresolved{display:grid;gap:8px;margin:0;padding:0;list-style:none}.advanced-analysis-item,.advanced-unresolved li{padding:11px;border:1px solid #ffffff12;border-radius:13px;background:#02070b}.advanced-analysis-item.finding{border-color:#ff557544}.advanced-analysis-item.watch{border-color:#ffcc6644}.advanced-analysis-item>div{display:flex;justify-content:space-between;gap:10px}.advanced-analysis-item span{color:#8fa7b4;font:800 9px var(--k-mono,monospace)}.advanced-analysis-item p,.advanced-unresolved p,.advanced-actions p{margin:6px 0 0;color:#aebfca;font-size:12px;line-height:1.5}.advanced-analysis-refs{display:flex;flex-wrap:wrap;gap:5px;margin-top:8px}.advanced-analysis-refs code{padding:4px 6px;border-radius:7px;color:#9df7dc;background:#18ffb20d;font-size:9px;word-break:break-all}.advanced-analysis-section{margin-top:12px}.advanced-actions{display:grid;gap:8px;margin:0;padding:0;list-style:none}.advanced-actions li{display:grid;grid-template-columns:30px 1fr;gap:10px;align-items:start}.advanced-actions li>span{display:grid;place-items:center;width:28px;height:28px;border-radius:9px;color:#00110d;background:#45cfff;font-weight:1000}.advanced-actions strong{font-size:12px}.advanced-analysis-empty{padding:11px;color:#7f96a3;border:1px dashed #ffffff1f;border-radius:12px}.advanced-analysis-policy{margin:13px 0 0;color:#748d9b;font:10px var(--k-mono,monospace);line-height:1.55}@media(max-width:720px){.advanced-analysis-metrics,.advanced-analysis-grid{grid-template-columns:1fr}.advanced-analysis-head{align-items:flex-start}}';
    document.head.appendChild(style);
  }
  function renderAdvancedAnalysis(summary){
    if(typeof document==='undefined'||!analysisSummaryPresent(summary))return false;
    installAdvancedAnalysisStyle();
    const host=document.querySelector('[data-customer-arvis-result] .public-investigation-card')||document.querySelector('.public-investigation-card');
    if(!host)return false;
    host.parentElement?.querySelector('[data-advanced-investigation-summary]')?.remove();
    host.insertAdjacentHTML('afterend',advancedAnalysisHTML(summary));
    return true;
  }
  function scheduleAdvancedAnalysis(summary){
    if(typeof document==='undefined'||!analysisSummaryPresent(summary))return;
    setTimeout(()=>renderAdvancedAnalysis(summary),0);
    setTimeout(()=>renderAdvancedAnalysis(summary),80);
  }
  function mapVerdictCard(input,options={}){
    const payload=obj(input.investigation_report||input);
    const vm=rawMap(input,options);
    const referenceMap=obj(payload.evidence_references);
    for(const row of arr(vm?.checklist)){
      row.refs=normalize(referenceMap[row.id]);
      if((row.state==='verified'||row.state==='observed')&&!refsPresent(row.refs)){
        row.state='arm_pending';
        row.status='gray';
        row.value=options.lang==='tr'?'Kanıt referansı bu taramada tamamlanmadı':'Evidence reference did not complete in this scan';
      }
    }
    const corpus=obj(payload.holder_concentration_context),concentration=arr(vm?.checklist).find(row=>row.id==='concentration');
    if(concentration&&corpus.available===true&&number(corpus.top_percentile)!==null&&number(corpus.sample_count)!==null){
      const locale=options.lang==='tr'?'tr-TR':'en-US';
      const share=new Intl.NumberFormat(locale,{maximumFractionDigits:4}).format(Number(corpus.top_share_pct));
      const percentile=new Intl.NumberFormat(locale,{maximumFractionDigits:2}).format(Number(corpus.top_percentile));
      const sample=new Intl.NumberFormat(locale,{maximumFractionDigits:0}).format(Number(corpus.sample_count));
      const line=options.lang==='tr'?`Owner payı %${share}; taranan farklı mint corpus’unda en yoğun üst %${percentile} diliminde (n=${sample})`:`Owner share ${share}%; top ${percentile}% most concentrated among distinct scanned mints (n=${sample})`;
      concentration.value=`${concentration.value} · ${line}`;
      concentration.detail=concentration.detail?`${concentration.detail} · ${line}`:line;
      concentration.corpus_context=corpus;
    }
    const coverage={verified:0,observed:0,window_open:0,not_applicable:0,arm_pending:0};
    for(const row of arr(vm?.checklist))coverage[row.state]=(coverage[row.state]||0)+1;
    const labels=options.lang==='tr'?{verified:'doğrulanmış',observed:'gözlenen',window_open:'izleme penceresinde',not_applicable:'uygulanamaz',arm_pending:'bekleyen'}:{verified:'verified',observed:'observed',window_open:'in monitoring window',not_applicable:'not applicable',arm_pending:'pending'};
    coverage.text=`${coverage.verified} ${labels.verified} · ${coverage.observed} ${labels.observed} · ${coverage.window_open} ${labels.window_open} · ${coverage.not_applicable} ${labels.not_applicable} · ${coverage.arm_pending} ${labels.arm_pending}`;
    vm.coverage=coverage;
    vm.analysis_summary=normalizeAnalysisSummary(payload.analysis_summary||input.analysis_summary);
    scheduleAdvancedAnalysis(vm.analysis_summary);
    return vm;
  }
  return{...base,mapVerdictCard,refsPresent,normalizeEvidenceRefs:normalize,normalizeAnalysisSummary,analysisSummaryPresent,advancedAnalysisHTML,renderAdvancedAnalysis};
});
