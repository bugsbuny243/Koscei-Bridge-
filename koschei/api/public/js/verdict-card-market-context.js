(function(root,factory){
  const api=factory(root.KoscheiVerdictCard,typeof module==='object'&&module.exports?require('./verdict-card.js'):null);
  if(typeof module==='object'&&module.exports)module.exports=api;
  if(api&&api.mapVerdictCard)root.KoscheiVerdictCard=api;
})(typeof globalThis!=='undefined'?globalThis:this,function(browserBase,nodeBase){
  'use strict';
  const base=browserBase||nodeBase;
  if(!base||typeof base.mapVerdictCard!=='function')return base;
  const rawMap=base.mapVerdictCard;
  const obj=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
  const num=value=>{const parsed=Number(value);return Number.isFinite(parsed)?parsed:null};
  const money=(value,locale)=>{const parsed=num(value);return parsed===null?'—':new Intl.NumberFormat(locale,{style:'currency',currency:'USD',maximumFractionDigits:2}).format(parsed)};
  const pct=(value,locale,digits=2)=>{const parsed=num(value);return parsed===null?'—':new Intl.NumberFormat(locale,{maximumFractionDigits:digits}).format(parsed)};
  const stateLabel=(state,tr)=>({
    burned:tr?'yakılmış':'burned',locked_until:tr?'kilitli':'locked',held_by_creator:tr?'creator kontrolünde':'held by creator',
    unverified:tr?'doğrulanamadı':'unverified',not_applicable:tr?'uygulanamaz':'not applicable',source_unavailable:tr?'kaynak alınamadı':'source unavailable'
  }[state]||state||'unverified');
  function recalc(vm,tr){
    const coverage={verified:0,observed:0,window_open:0,not_applicable:0,arm_pending:0};
    vm.checklist.forEach(row=>coverage[row.state]=(coverage[row.state]||0)+1);
    const labels=tr?{verified:'doğrulanmış',observed:'gözlenen',window_open:'izleme penceresinde',not_applicable:'uygulanamaz',arm_pending:'bekleyen'}:{verified:'verified',observed:'observed',window_open:'in monitoring window',not_applicable:'not applicable',arm_pending:'pending'};
    coverage.text=`${coverage.verified} ${labels.verified} · ${coverage.observed} ${labels.observed} · ${coverage.window_open} ${labels.window_open} · ${coverage.not_applicable} ${labels.not_applicable} · ${coverage.arm_pending} ${labels.arm_pending}`;
    vm.coverage=coverage;
  }
  function mapVerdictCard(input,options={}){
    const payload=obj(input.investigation_report||input),vm=rawMap(input,options),tr=options.lang==='tr',locale=tr?'tr-TR':'en-US';
    const lp=obj(payload.lp_control),jupiter=obj(payload.jupiter_market_context),market=obj(payload.market),exit=obj(payload.exit_liquidity||jupiter.exit_liquidity),source=obj(payload.source_context),program=obj(payload.program_security||source.program_security);
    const liquidity=vm.checklist.find(row=>row.id==='liquidity');
    if(liquidity&&lp.status){
      if(lp.status==='not_applicable'){
        liquidity.state='not_applicable';liquidity.status='gray';
        liquidity.value=lp.reason_code==='bonding_curve_no_amm_pool'?(tr?'Bonding curve aşaması — AMM havuzu yok':'Bonding curve stage — no AMM pool'):(tr?'Bu pool collector için uygulanamaz':'Not applicable to this pool collector');
      }else if(lp.available){
        const reserveUSD=num(lp.reserve_liquidity_usd),marketUSD=num(market.liquidity_usd),amount=reserveUSD!==null&&reserveUSD>0?reserveUSD:marketUSD;
        let lock=stateLabel(lp.status,tr);
        if(lp.status==='burned')lock+=` (${pct(lp.burned_share_pct,locale,4)}%)`;
        if(lp.status==='locked_until'&&lp.locked_until)lock+=` ${new Date(lp.locked_until).toLocaleString(tr?'tr-TR':'en-US')}`;
        if(lp.status==='held_by_creator')lock+=` (${pct(lp.creator_lp_share_pct,locale,4)}%)`;
        liquidity.state=['burned','locked_until'].includes(lp.status)?'verified':'observed';
        liquidity.status=liquidity.state==='verified'?'green':'yellow';
        liquidity.value=`${money(amount,locale)} · ${lock}`;
        liquidity.detail=`pool ${lp.pool_address||'—'} · LP ${lp.lp_mint||'—'} · slot ${lp.read_slot||'—'} · token reserve ${lp.token_reserve??'—'} · quote reserve ${lp.quote_reserve??'—'}`;
      }else if(lp.status==='source_unavailable'){
        liquidity.state='arm_pending';liquidity.status='gray';liquidity.value=tr?'LP kanıt kaynağı bu taramada tamamlanmadı':'LP evidence source did not complete in this scan';
      }
    }
    const exitTiers=Array.isArray(exit.tiers)?exit.tiers.filter(tier=>tier&&tier.available&&tier.status==='quoted'):[];
    if(liquidity&&exitTiers.length){
      const summaries=exitTiers.map(tier=>{
        const requested=money(tier.requested_notional_usd,locale),proceeds=money(tier.estimated_proceeds_usd,locale),shortfall=pct(tier.execution_shortfall_pct,locale,2);
        return tr?`${requested} satış → ${proceeds} tahmini gelir · %${shortfall} execution shortfall`:`${requested} sell → ${proceeds} estimated proceeds · ${shortfall}% execution shortfall`;
      });
      const detail=`${tr?'Jupiter read-only exit simülasyonu':'Jupiter read-only exit simulation'}: ${summaries.join(' · ')}`;
      liquidity.detail=liquidity.detail?`${liquidity.detail} · ${detail}`:detail;
      if(!['verified','not_applicable'].includes(liquidity.state)){
        liquidity.state='observed';liquidity.status='yellow';liquidity.value=detail;
      }else{
        liquidity.value=liquidity.value?`${liquidity.value} · ${detail}`:detail;
      }
    }else if(liquidity&&exit.status&&!['not_requested_preflight','exit_liquidity_unavailable'].includes(exit.status)){
      const detail=tr?`Exit simülasyonu tamamlanmadı: ${exit.status}`:`Exit simulation incomplete: ${exit.status}`;
      liquidity.detail=liquidity.detail?`${liquidity.detail} · ${detail}`:detail;
    }
    const programRow=vm.checklist.find(row=>row.id==='program'),programs=Array.isArray(program.programs)?program.programs.filter(Boolean):[];
    if(programRow&&programs.length){
      const shortAddress=value=>{const text=String(value||'');return text.length>18?`${text.slice(0,8)}…${text.slice(-6)}`:text||'—'};
      const summaries=programs.map(item=>{
        const role=item.role||'program';
        let control=item.status||'unverified';
        if(item.immutable)control=tr?'immutable':'immutable';
        else if(item.upgrade_authority_open)control=tr?`upgrade authority açık ${shortAddress(item.upgrade_authority)}`:`upgrade authority open ${shortAddress(item.upgrade_authority)}`;
        else if(item.available)control=tr?'upgrade authority kapalı veya ayarlanmamış':'upgrade authority closed or unset';
        const age=item.age_available?(tr?`son deploy/upgrade ${pct(item.last_deployment_or_upgrade_age_days,locale,2)} gün önce`:`latest deploy/upgrade ${pct(item.last_deployment_or_upgrade_age_days,locale,2)} days ago`):(tr?'deploy/upgrade yaşı alınamadı':'deploy/upgrade age unavailable');
        return `${role} ${shortAddress(item.program_id)} · ${control} · ${age}`;
      });
      const complete=program.authority_coverage_complete===true&&program.age_coverage_complete===true&&programs.every(item=>item.available);
      programRow.state=complete?'verified':'observed';programRow.status=complete?'green':'yellow';programRow.value=summaries.join(' · ');
      const policy=tr?'Upgrade authority bir kabiliyet olgusudur; tek başına kötü niyet kanıtı değildir.':'Upgrade authority is a capability fact; it is not proof of malicious intent by itself.';
      programRow.detail=`${summaries.join(' · ')} · ${policy}`;
    }else if(programRow&&['inspection_failed','rpc_unavailable','partial'].includes(program.status)){
      programRow.state='arm_pending';programRow.status='gray';programRow.value=tr?`Program security kanıtı tamamlanmadı: ${program.status}`:`Program security evidence incomplete: ${program.status}`;
    }
    const concentration=vm.checklist.find(row=>row.id==='concentration');
    if(concentration&&jupiter.sell_impact_available){
      const context=tr?`Jupiter yönlendirme simülasyonu: baskın pozisyon çıkarsa tahmini fiyat etkisi ~%${pct(jupiter.estimated_price_impact_pct,locale,4)} · slot ${jupiter.quote_context_slot||'—'}`:`Jupiter routing simulation: estimated price impact if the dominant position exits ~${pct(jupiter.estimated_price_impact_pct,locale,4)}% · slot ${jupiter.quote_context_slot||'—'}`;
      concentration.detail=concentration.detail?`${concentration.detail} · ${context}`:context;
      concentration.value=`${concentration.value} · ${context}`;
    }
    if(concentration&&jupiter.price_available){
      const source=tr?`Jupiter fiyatı ${money(jupiter.price_usd,locale)} (${jupiter.price_block_id?'block '+jupiter.price_block_id:'zaman damgalı'})`:`Jupiter price ${money(jupiter.price_usd,locale)} (${jupiter.price_block_id?'block '+jupiter.price_block_id:'timestamped'})`;
      concentration.detail=concentration.detail?`${concentration.detail} · ${source}`:source;
    }
    recalc(vm,tr);
    return vm;
  }
  return{...base,mapVerdictCard};
});
