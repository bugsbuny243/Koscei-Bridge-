(function(root,factory){
  const api=factory();
  if(typeof module==='object'&&module.exports)module.exports=api;
  root.KoscheiVerdictCard=api;
})(typeof globalThis!=='undefined'?globalThis:this,function(){
  'use strict';
  const LANG={
    en:{
      signedNoGrade:'The scan is complete and signed. No grade-changing rule was triggered. Missing evidence is not a positive safety signal.',
      signedFinding:'SIGNED TECHNICAL FINDING',gathering:'EVIDENCE WINDOW ACTIVE',
      gatherAge:'Monitoring window active for a token that is {age} old. Verified and observed evidence is shown now; open collection windows remain explicit.',
      gatherNoAge:'Monitoring window active. Verified and observed evidence is shown now; open collection windows remain explicit.',
      disc:'Koschei reports verified on-chain capability and observed behavior. It does not predict intent and is not investment advice.',
      leverage:'Owner control surface',checklist:'20-signal technical coverage',active:'active',revoked:'revoked',tokens:'tokens',
      states:{window_open:'Monitoring window active — evidence accumulating{age}',not_applicable:'Not applicable at this stage',arm_pending:'Evidence arm did not complete in this scan'},
      coverage:{verified:'verified',observed:'observed',window_open:'in monitoring window',not_applicable:'not applicable',arm_pending:'pending'},
      findingTitles:{dominant_holder_exit:'DOMINANT-HOLDER EXIT CAPACITY',liquidity_removal:'LIQUIDITY CONTROL EXPOSURE',creator_sell_acceleration:'CREATOR SELL ACCELERATION',coordinated_holder_exit:'COORDINATED HOLDER EXIT SIGNAL',mint_inflation:'MINT AUTHORITY EXPOSURE',freeze_abuse:'FREEZE AUTHORITY EXPOSURE'},
      labels:{launch:'Launch time / age',mint:'Mint authority',freeze:'Freeze authority',wash:'Wash-trading context',address:'Address behavior',liquidity:'Liquidity amount + lock status',funding:'Creator funding origin',concentration:'Holder concentration (owner-resolved)',sniper:'Sniper timing',firstBuyer:'First-buyer linkage (Sybil)',track:'Creator track record',creatorSell:'Creator sell behavior',dominantExit:'Dominant holder exit',liqMove:'Liquidity movement',program:'Program / contract relations',metadata:'Metadata / impersonation check',claim:'Claim / airdrop surface',mev:'MEV exposure',distribution:'Launch distribution fairness',signed:'Signed final verdict'},
      rows:{mint:'Owner can mint additional supply while mint authority remains active.',freeze:'Owner can freeze holder accounts while freeze authority remains active.',holder:'A single owner-resolved wallet controls {value}% of circulating supply and can materially affect market price.',lp:'Liquidity is verified as unlocked; the withdrawal path remains technically available.',repeat:'This creator cluster previously launched {value} tokens.'}
    },
    tr:{
      signedNoGrade:'Tarama tamamlandı ve imzalandı. Grade değiştiren kural tetiklenmedi. Eksik kanıt, olumlu güvenlik sinyali değildir.',
      signedFinding:'İMZALI TEKNİK BULGU',gathering:'KANIT PENCERESİ AKTİF',
      gatherAge:'Token yaşı {age}. İzleme penceresi aktif; doğrulanan ve gözlenen kanıtlar şimdi gösterilir, açık toplama pencereleri ayrıca belirtilir.',
      gatherNoAge:'İzleme penceresi aktif. Doğrulanan ve gözlenen kanıtlar şimdi gösterilir, açık toplama pencereleri ayrıca belirtilir.',
      disc:'Koschei doğrulanmış zincir üstü kabiliyet ve gözlenen davranışı raporlar. Niyet tahmin etmez ve yatırım tavsiyesi değildir.',
      leverage:'Owner kontrol yüzeyi',checklist:'20 sinyal teknik kapsam',active:'aktif',revoked:'iptal edildi',tokens:'token',
      states:{window_open:'İzleme penceresi aktif — kanıt birikiyor{age}',not_applicable:'Bu aşamada uygulanamaz',arm_pending:'Kanıt kolu bu taramada tamamlanmadı'},
      coverage:{verified:'doğrulanmış',observed:'gözlenen',window_open:'izleme penceresinde',not_applicable:'uygulanamaz',arm_pending:'bekleyen'},
      findingTitles:{dominant_holder_exit:'BASKIN HOLDER ÇIKIŞ KAPASİTESİ',liquidity_removal:'LİKİDİTE KONTROL MARUZİYETİ',creator_sell_acceleration:'CREATOR SATIŞ HIZLANMASI',coordinated_holder_exit:'KOORDİNELİ HOLDER ÇIKIŞ SİNYALİ',mint_inflation:'MINT YETKİSİ MARUZİYETİ',freeze_abuse:'FREEZE YETKİSİ MARUZİYETİ'},
      labels:{launch:'Başlangıç zamanı / yaş',mint:'Mint authority',freeze:'Freeze authority',wash:'Wash-trading bağlamı',address:'Adres davranışı',liquidity:'Likidite miktarı + kilit durumu',funding:'Creator funding kaynağı',concentration:'Holder yoğunluğu (owner-resolved)',sniper:'Sniper zamanlaması',firstBuyer:'İlk alıcı bağlantısı (Sybil)',track:'Creator geçmişi',creatorSell:'Creator satış davranışı',dominantExit:'Baskın holder çıkışı',liqMove:'Likidite hareketi',program:'Program / kontrat ilişkileri',metadata:'Metadata / taklit kontrolü',claim:'Claim / airdrop yüzeyi',mev:'MEV maruziyeti',distribution:'Launch dağılım adaleti',signed:'İmzalı final verdict'},
      rows:{mint:'Mint authority aktif kaldığı sürece owner ek arz basabilir.',freeze:'Freeze authority aktif kaldığı sürece owner holder hesaplarını dondurabilir.',holder:'Owner-resolved tek bir cüzdan dolaşımdaki arzın %{value} kadarını kontrol ediyor ve piyasa fiyatını maddi ölçüde etkileyebilir.',lp:'Likiditenin kilitsiz olduğu doğrulandı; çekim yolu teknik olarak açıktır.',repeat:'Bu creator cluster daha önce {value} token başlattı.'}
    }
  };
  const arr=v=>Array.isArray(v)?v:[];
  const obj=v=>v&&typeof v==='object'&&!Array.isArray(v)?v:{};
  const upper=v=>String(v||'').toUpperCase();
  const first=(...xs)=>xs.find(x=>x!==undefined&&x!==null&&x!=='');
  const short=v=>{const s=String(v||'');return s.length>18?`${s.slice(0,8)}…${s.slice(-6)}`:s};
  const num=v=>{const n=Number(v);return Number.isFinite(n)?n:null};
  const fmt=(value,locale='en-US',digits=4)=>{const n=num(value);return n===null?'—':new Intl.NumberFormat(locale,{maximumFractionDigits:digits}).format(n)};
  const money=(value,locale='en-US')=>{const n=num(value);return n===null?'—':new Intl.NumberFormat(locale,{style:'currency',currency:'USD',maximumFractionDigits:2}).format(n)};
  const metrics=e=>obj(e?.metrics||e?.signals||e);
  const execution=e=>String(metrics(e).execution_status||'').toLowerCase();
  const evidenceState=e=>{
    if(!e)return'';
    if(execution(e)==='not_applicable'||metrics(e).applicable===false||String(e.recommendation||'').toLowerCase()==='not_applicable')return'not_applicable';
    if(['evidence_pending','source_unavailable','insufficient_evidence'].includes(execution(e)))return'arm_pending';
    const s=upper(first(e.evidence_status,e.verification_status,e.status,metrics(e).evidence_status));
    if(e.verified===true||s==='VERIFIED')return'verified';
    if(e.signed===true||['OBSERVED','INFERRED'].includes(s)||execution(e)==='completed')return'observed';
    return'';
  };
  function allModules(payload){return arr(payload.modules).concat(arr(payload.evidence_arms),arr(obj(payload.legacy_14_arm_radar).modules));}
  function findEvidence(payload,keys){
    const all=[...allModules(payload),...arr(payload.evidence),...arr(obj(payload.behavior_signals).signals)];
    return all.find(e=>keys.some(k=>String(e?.module_id||e?.module||e?.rule_id||e?.id||'').toLowerCase().includes(k)));
  }
  const moduleBy=(payload,...ids)=>findEvidence(payload,ids);
  const pathBy=(payload,id)=>arr(obj(payload.threat_anticipation).pathways).find(p=>String(p?.id||'').toLowerCase()===id);
  function launchTime(payload){
    const launch=obj(payload.launch_forensics),source=obj(payload.source_context),signals=obj(obj(payload.final_verdict).signals);
    return first(launch.launch_time,source.launch_time,source.created_at,source.launch_timestamp,source.token_created_at,signals.launch_time,payload.launch_time);
  }
  function asOfTime(payload,options){return first(options.asOf,payload.generated_at,obj(payload.final_verdict).generated_at,obj(payload.launch_forensics).generated_at,new Date().toISOString());}
  function ageInfo(payload,options,isTR){
    const raw=launchTime(payload),asOf=asOfTime(payload,options);const t=raw?new Date(raw).getTime():NaN,a=asOf?new Date(asOf).getTime():NaN;
    if(!Number.isFinite(t)||!Number.isFinite(a))return{label:'',hours:null,raw:''};
    const mins=Math.max(0,Math.round((a-t)/60000));
    if(mins<60)return{label:isTR?`${mins} dakika`:`${mins} minutes`,hours:mins/60,raw};
    const hours=Math.round(mins/60);return{label:isTR?`${hours} saat`:`${hours} hours`,hours,raw};
  }
  function emptyCopy(state,lang,age){
    if(state==='window_open')return lang.states.window_open.replace('{age}',age?` (${age})`:'');
    return lang.states[state]||lang.states.arm_pending;
  }
  function row(id,label,value,state,evidence,detail=''){
    const color=state==='verified'?'green':state==='observed'?'yellow':state==='not_applicable'?'gray':'gray';
    return{id,label,value,state,status:color,detail,evidence_anchor:`#evidence-${id}`,source_status:evidenceState(evidence)};
  }
  function stateOrGap(e,{ageHours,poolExists,transactionSpecific=false}={}){
    const explicit=evidenceState(e);if(explicit)return explicit;
    if(transactionSpecific)return'not_applicable';
    if(poolExists===false)return'not_applicable';
    if(ageHours!==null&&ageHours<24)return'window_open';
    return'arm_pending';
  }
  function caseFinding(payload,langKey,lang){
    const threat=obj(payload.threat_anticipation),exit=obj(threat.exit_capacity),paths=arr(threat.pathways);
    const byId=id=>paths.find(path=>String(path?.id||'')===id);
    const active=path=>path&&['open','observed','watch','limited'].includes(String(path.status||path.capacity||'').toLowerCase());
    const priority=['liquidity_removal','creator_sell_acceleration','coordinated_holder_exit','dominant_holder_exit','mint_inflation','freeze_abuse'].find(id=>active(byId(id)));
    if(!priority)return null;
    const title=lang.findingTitles[priority]||lang.signedFinding;
    if(priority==='dominant_holder_exit'){
      const pct=fmt(exit.owner_percentage,langKey==='tr'?'tr-TR':'en-US');
      const multiple=fmt(exit.position_liquidity_multiple,langKey==='tr'?'tr-TR':'en-US',2);
      const copy=langKey==='tr'?`Owner-resolved cüzdan arzın %${pct} kadarını kontrol ediyor; referans pozisyon gözlenen likiditenin ${multiple} katı. Bu kapasite bulgusudur, satış niyeti değildir.`:`The owner-resolved wallet controls ${pct}% of supply; its reference position is ${multiple}x observed liquidity. This is a capacity finding, not evidence of intent to sell.`;
      return{title,copy};
    }
    const p=byId(priority);return{title,copy:String(p?.summary||lang.signedNoGrade)};
  }
  function mapVerdictCard(input,options={}){
    const payload=obj(input.investigation_report||input);const langKey=options.lang==='tr'?'tr':'en',lang=LANG[langKey],locale=langKey==='tr'?'tr-TR':'en-US';
    const final=obj(payload.final_verdict),signals=obj(final.signals||payload.signals),distribution=obj(payload.holder_distribution),structural=obj(payload.structural_memory),holder=obj(payload.holder_intelligence||obj(payload.legacy_14_arm_radar).holder_intelligence);
    const age=ageInfo(payload,options,langKey==='tr'),launch=obj(payload.launch_forensics),market=obj(payload.market),ledger=obj(payload.trade_ledger_aggregates),actor=obj(obj(payload.actor_investigation).dossier),behavior=obj(payload.behavior_signals);
    const authority=moduleBy(payload,'token_authority_scanner'),authorityM=metrics(authority),holderEv=moduleBy(payload,'holder_concentration','holder'),holderM={...holder,...metrics(holderEv)};
    const lpEv=moduleBy(payload,'liquidity_movement','pool_guardian'),repeatEv=moduleBy(payload,'repeat_actor','actor_dossier');
    const mintKnown=first(authorityM.mint_authority_present,structural.mint_authority_present,signals.mint_authority_present)!==undefined;
    const freezeKnown=first(authorityM.freeze_authority_present,structural.freeze_authority_present,signals.freeze_authority_present)!==undefined;
    const mintActive=first(authorityM.mint_authority_present,structural.mint_authority_present,signals.mint_authority_present)===true;
    const freezeActive=first(authorityM.freeze_authority_present,structural.freeze_authority_present,signals.freeze_authority_present)===true;
    const explicitOwnerResolved=holderM.owner_resolved===true||holderM.owner_resolved_holder===true||holderM.owner_resolved_top_holder===true||holder.available===true;
    const ownerResolvedPct=first(holderM.top_owner_percentage,holderM.owner_resolved_top_holder_pct,explicitOwnerResolved?first(holderM.top_holder_percentage,holderM.largest_holder_percentage):undefined);
    const rawTopPct=first(holderM.top_holder_percentage,distribution.top_1_percentage,structural.largest_holder_percentage);
    const ownerNum=num(ownerResolvedPct),rawNum=num(rawTopPct),concentrationIsRaw=ownerNum===null&&rawNum!==null,concentrationPct=ownerNum!==null?ownerResolvedPct:rawTopPct;
    const repeatCount=first(metrics(repeatEv).repeat_actor_matches,metrics(repeatEv).created_token_count,metrics(repeatEv).previous_token_count,obj(actor.track).created_token_count);
    const poolExists=Boolean(first(market.best_pair_address,metrics(lpEv).best_pair_address,metrics(lpEv).pool_address));
    const liquidityUSD=first(market.liquidity_usd,market.LiquidityUSD,metrics(lpEv).liquidity_usd,metrics(lpEv).best_pair_liquidity_usd);
    const lockStatus=first(metrics(lpEv).lock_status,metrics(lpEv).lp_lock_status);
    const lpUnlocked=first(metrics(lpEv).lp_unlocked,metrics(lpEv).liquidity_unlocked,metrics(lpEv).withdrawable)===true;
    const leverage=[];const push=(id,text,e)=>{if(evidenceState(e)==='verified')leverage.push({id,text,evidence_anchor:`#evidence-${id}`})};
    if(mintActive)push('mint-authority',lang.rows.mint,authority);if(freezeActive)push('freeze-authority',lang.rows.freeze,authority);if(ownerNum!==null&&ownerNum>=50)push('top-owner',lang.rows.holder.replace('{value}',ownerResolvedPct),holderEv);if(lpUnlocked)push('lp-unlocked',lang.rows.lp,lpEv);if(Number(repeatCount)>=1)push('repeat-actor',lang.rows.repeat.replace('{value}',repeatCount),repeatEv);
    const noGrade=String(final.verdict||final.grade||'').toLowerCase().includes('no_grade_trigger')||!final.grade||final.grade==='-',grade=String(final.grade||'').match(/[A-F]/i)?.[0]?.toUpperCase()||'',signed=final.signed===true||Boolean(final.signature);
    let header;if(noGrade&&signed){const finding=caseFinding(payload,langKey,lang);header={state:'signed_finding',tone:finding?'yellow':'neutral',icon:'✓',title:finding?.title||lang.signedFinding,copy:finding?.copy||lang.signedNoGrade,kicker:lang.signedFinding};}else if(noGrade)header={state:'gathering',tone:'neutral',icon:'⏳',title:lang.gathering,copy:age.label?lang.gatherAge.replace('{age}',age.label):lang.gatherNoAge};else header={state:'graded',tone:({A:'green',B:'green',C:'yellow',D:'orange',F:'red'}[grade]||'neutral'),grade,title:grade||'—',copy:final.verdict||''};
    header.ruleset_version=final.ruleset_version||final.rule_version||payload.ruleset_version||'—';header.actor_ruleset_version=final.actor_ruleset_version||payload.actor_ruleset_version||'—';header.signature_short=short(final.signature||payload.signature);header.generated_at=first(final.generated_at,payload.generated_at,'');
    const L=lang.labels,rows=[];
    const addGap=(id,label,e,conditions={})=>{const s=stateOrGap(e,{ageHours:age.hours,...conditions});rows.push(row(id,label,emptyCopy(s,lang,age.label),s,e));};
    if(age.label)rows.push(row('launch',L.launch,`${age.label} old · ${launchTime(payload)}`,launch.available===false?'observed':'verified',launch,`slot ${first(launch.launch_slot,'—')}`));else addGap('launch',L.launch,moduleBy(payload,'launch'));
    if(mintKnown)rows.push(row('mint',L.mint,mintActive?lang.active:lang.revoked,evidenceState(authority)||'observed',authority));else addGap('mint',L.mint,authority);
    if(freezeKnown)rows.push(row('freeze',L.freeze,freezeActive?lang.active:lang.revoked,evidenceState(authority)||'observed',authority));else addGap('freeze',L.freeze,authority);
    if(ledger.available===true||num(ledger.trade_count)>0)rows.push(row('wash',L.wash,`${fmt(ledger.trade_count,locale,0)} trades · ${fmt(ledger.round_trip_wallet_count,locale,0)} round-trip wallets · wash classification not proven`,'observed',ledger));else addGap('wash',L.wash,moduleBy(payload,'trade_ledger','sybil'));
    if(Object.keys(actor).length)rows.push(row('address',L.address,`${arr(actor.tokens).length} token relations · ${arr(actor.related_actors).length} related wallets · ${arr(actor.evidence).length} evidence rows`,'observed',actor));else addGap('address',L.address,moduleBy(payload,'actor_dossier'));
    if(num(liquidityUSD)!==null){const lock=lockStatus?String(lockStatus):emptyCopy('arm_pending',lang,age.label);rows.push(row('liquidity',L.liquidity,`${money(liquidityUSD,locale)} · lock: ${lock}`,'observed',lpEv));}else addGap('liquidity',L.liquidity,lpEv,{poolExists});
    const funding=moduleBy(payload,'funding_cluster','funding');const fundingM=metrics(funding);if(first(fundingM.origin,fundingM.funding_source,fundingM.resolved_owner_count)!==undefined)rows.push(row('funding',L.funding,String(first(fundingM.origin,fundingM.funding_source,`${fundingM.resolved_owner_count} owners resolved`)),evidenceState(funding)||'observed',funding));else addGap('funding',L.funding,funding);
    if(num(concentrationPct)!==null)rows.push(row('concentration',L.concentration,`${fmt(concentrationPct,locale)}%${concentrationIsRaw?' (raw)':''}`,concentrationIsRaw?'observed':evidenceState(holderEv)||'observed',holderEv));else addGap('concentration',L.concentration,holderEv);
    if(num(launch.sniper_count)!==null&&launch.available!==false)rows.push(row('sniper',L.sniper,`${fmt(launch.sniper_count,locale,0)} sniper-classified · ${fmt(launch.owners_with_trade_history,locale,0)}/${fmt(launch.owners_requested,locale,0)} owner histories`,launch.sniper_count>0?'observed':'verified',moduleBy(payload,'sniper')||launch));else addGap('sniper',L.sniper,moduleBy(payload,'sniper'));
    if(num(launch.creator_linked_count)!==null&&launch.available!==false)rows.push(row('first-buyer',L.firstBuyer,`${fmt(launch.creator_linked_count,locale,0)} creator-linked first-buyer relations`,launch.creator_linked_count>0?'observed':'verified',moduleBy(payload,'pump_sybil','pump')||launch));else addGap('first-buyer',L.firstBuyer,moduleBy(payload,'pump_sybil','pump'));
    if(Number(repeatCount)>=0&&repeatCount!==undefined)rows.push(row('track',L.track,`${repeatCount} ${lang.tokens}`,evidenceState(repeatEv)||'observed',repeatEv));else addGap('track',L.track,repeatEv);
    const creatorSell=arr(behavior.signals).find(s=>s.rule_id==='URD-C003')||moduleBy(payload,'urd-c003');if(creatorSell)rows.push(row('creator-sell',L.creatorSell,String(first(creatorSell.summary,metrics(creatorSell).summary,creatorSell.evidence_status)),evidenceState(creatorSell)||'observed',creatorSell));else addGap('creator-sell',L.creatorSell,creatorSell);
    const exit=obj(obj(payload.threat_anticipation).exit_capacity),exitPath=pathBy(payload,'dominant_holder_exit');if(exitPath||exit.available){const status=upper(first(exitPath?.capacity,exitPath?.status,exit.capacity,'UNKNOWN')),position=money(exit.owner_reference_usd_value,locale),liq=money(exit.liquidity_usd,locale),multiple=num(exit.position_liquidity_multiple)!==null?` · ${fmt(exit.position_liquidity_multiple,locale,2)}x liquidity`:'';rows.push(row('dominant-exit',L.dominantExit,`${status} · position ${position} / liquidity ${liq}${multiple}`,upper(exitPath?.evidence_status)==='VERIFIED'?'verified':'observed',exitPath||exit));}else addGap('dominant-exit',L.dominantExit,moduleBy(payload,'urd-c004'));
    const liqMove=moduleBy(payload,'liquidity_movement');if(liqMove&&['verified','observed'].includes(evidenceState(liqMove))){const m=metrics(liqMove);rows.push(row('liq-move',L.liqMove,String(first(liqMove.verdict,m.summary,`${money(first(m.liquidity_usd,liquidityUSD),locale)} observed liquidity`)),evidenceState(liqMove),liqMove));}else addGap('liq-move',L.liqMove,liqMove,{poolExists});
    const program=moduleBy(payload,'program_relation','token_authority');if(program)rows.push(row('program',L.program,String(first(metrics(program).program,metrics(program).token_program,program.verdict,program.module)),evidenceState(program)||'observed',program));else addGap('program',L.program,program);
    addGap('metadata',L.metadata,moduleBy(payload,'metadata'));
    addGap('claim',L.claim,moduleBy(payload,'claim'),{transactionSpecific:true});
    addGap('mev',L.mev,moduleBy(payload,'mev'),{transactionSpecific:true});
    if(launch.available===true)rows.push(row('distribution',L.distribution,`${fmt(launch.owners_with_trade_history,locale,0)}/${fmt(launch.owners_requested,locale,0)} owner histories · ${fmt(launch.ledger_trade_count,locale,0)} ledger trades`,'observed',moduleBy(payload,'launch_distribution')||launch));else addGap('distribution',L.distribution,moduleBy(payload,'launch_distribution'));
    rows.push(row('signed',L.signed,`${header.ruleset_version} · ${header.signature_short||emptyCopy('arm_pending',lang,age.label)}`,signed?'verified':'arm_pending',final));
    const coverage={verified:0,observed:0,window_open:0,not_applicable:0,arm_pending:0};rows.forEach(r=>coverage[r.state]=(coverage[r.state]||0)+1);
    coverage.text=`${coverage.verified} ${lang.coverage.verified} · ${coverage.observed} ${lang.coverage.observed} · ${coverage.window_open} ${lang.coverage.window_open} · ${coverage.not_applicable} ${lang.coverage.not_applicable} · ${coverage.arm_pending} ${lang.coverage.arm_pending}`;
    return{schema_version:'koschei-verdict-card-v4',actor_ruleset_version:header.actor_ruleset_version,unified_radar_ruleset_version:header.ruleset_version,header,coverage,leverage_title:lang.leverage,leverage,checklist_title:lang.checklist,checklist:rows,disclaimer:lang.disc};
  }
  return{mapVerdictCard,LANG};
});
