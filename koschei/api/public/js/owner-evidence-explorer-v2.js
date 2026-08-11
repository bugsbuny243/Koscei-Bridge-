(()=>{
'use strict';
if(window.__koscheiOwnerEvidenceExplorerV2)return;
window.__koscheiOwnerEvidenceExplorerV2=true;

const SVG_NS='http://www.w3.org/2000/svg';
const arr=value=>Array.isArray(value)?value:[];
const obj=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
const text=value=>String(value??'').replace(/\s+/g,' ').trim();
const lower=value=>text(value).toLowerCase();
const short=(value,head=8,tail=6)=>{const raw=text(value);return raw.length>head+tail+3?`${raw.slice(0,head)}…${raw.slice(-tail)}`:raw||'—';};
const el=(tag,className,content)=>{const node=document.createElement(tag);if(className)node.className=className;if(content!==undefined)node.textContent=content;return node;};
const svg=(tag,attrs={})=>{const node=document.createElementNS(SVG_NS,tag);for(const [key,value] of Object.entries(attrs))node.setAttribute(key,String(value));return node;};

function currentReport(){
  const payload=obj(window.OwnerRadarKit?.lastScan);
  return obj(payload.investigation_report||payload.report||payload);
}

function trajectoryFrom(report){
  const actor=obj(report.actor_investigation);
  const memory=obj(actor.operational_memory);
  const candidates=[
    report.funding_trajectory_graph,
    report.persistent_funding_trajectory_graph,
    actor.funding_trajectory_graph,
    actor.persistent_funding_trajectory_graph,
    memory.funding_trajectory_graph,
    memory.persistent_funding_trajectory_graph
  ];
  for(const candidate of candidates){
    const value=obj(candidate);
    if(Object.keys(value).length)return value;
  }
  return {};
}

function stateOf(value){
  const raw=lower(value||'unknown');
  if(raw.includes('verified'))return'verified';
  if(raw.includes('signed'))return'signed';
  if(raw.includes('observed')||raw.includes('watch')||raw.includes('inferred'))return'observed';
  if(raw.includes('unavailable')||raw.includes('failed')||raw.includes('missing')||raw.includes('pending')||raw.includes('unresolved'))return'pending';
  if(raw.includes('not_applicable'))return'na';
  return raw||'unknown';
}

function labelOf(item,fallback){
  return text(item?.title||item?.label||item?.name||item?.module_id||item?.module||item?.rule_id||item?.id||fallback||'Evidence record');
}

function detailOf(item){
  return text(item?.summary||item?.explanation||item?.reason||item?.detail||item?.description||item?.interpretation||item?.verdict||'');
}

function collectEvidence(report){
  const rows=[];
  const seen=new Set();
  const add=(family,path,item,fallbackLabel,statusOverride)=>{
    if(item===undefined||item===null)return;
    const raw=typeof item==='object'?item:{value:item};
    const label=labelOf(raw,fallbackLabel);
    const status=stateOf(statusOverride||raw.evidence_state||raw.evidence_status||raw.status||raw.verification_status||raw.state);
    const key=`${family}|${path}|${label}|${status}`;
    if(seen.has(key))return;
    seen.add(key);
    rows.push({family,path,label,status,detail:detailOf(raw),raw});
  };

  const final=obj(report.final_verdict);
  arr(final.triggered_rules).forEach((item,index)=>add('Verdict',`final_verdict.triggered_rules[${index}]`,item,'Triggered rule','verified'));
  arr(final.watch_flags).forEach((item,index)=>add('Verdict',`final_verdict.watch_flags[${index}]`,item,'Watch flag','observed'));
  arr(final.decision_path).forEach((item,index)=>add('Verdict',`final_verdict.decision_path[${index}]`,item,`Decision step ${index+1}`,final.signed===true?'signed':'observed'));

  const modules=[...arr(report.modules),...arr(report.evidence_arms),...arr(obj(report.legacy_14_arm_radar).modules)];
  modules.forEach((item,index)=>add('Module',`modules[${index}]`,item,'Evidence module'));

  const behavior=obj(report.behavior_signals);
  arr(behavior.signals).forEach((item,index)=>add('Behavior',`behavior_signals.signals[${index}]`,item,'Behavior signal'));
  const signatures=obj(report.behavioral_signatures);
  arr(signatures.matches).forEach((item,index)=>{if(item?.triggered===true)add('Behavior',`behavioral_signatures.matches[${index}]`,item,'Behavioral signature');});

  const actor=obj(report.actor_investigation);
  const dossier=obj(actor.dossier);
  arr(dossier.evidence).forEach((item,index)=>add('Actor',`actor_investigation.dossier.evidence[${index}]`,item,'Actor evidence'));
  arr(actor.evidence).forEach((item,index)=>add('Actor',`actor_investigation.evidence[${index}]`,item,'Actor evidence'));

  const coverage=obj(report.capability_integration);
  const capabilities=obj(coverage.capabilities);
  for(const [key,value] of Object.entries(capabilities))add('Coverage',`capability_integration.capabilities.${key}`,value,key,value?.status);

  const graph=trajectoryFrom(report);
  arr(graph.edges).forEach((edge,index)=>add('Trajectory',`funding_trajectory_graph.edges[${index}]`,{
    title:`${short(edge?.source_id)} → ${short(edge?.target_id)}`,
    summary:`${text(edge?.relation||edge?.evidence_kind||'relation')} · ${text(edge?.source_provider||'provider unknown')}`,
    evidence_state:edge?.evidence_state,
    ...edge
  },'Trajectory edge'));

  arr(report.limitations).forEach((item,index)=>add('Limit',`limitations[${index}]`,{title:'Evidence limitation',summary:item,status:'pending'},'Evidence limitation'));
  arr(final.limitations).forEach((item,index)=>add('Limit',`final_verdict.limitations[${index}]`,{title:'Verdict limitation',summary:item,status:'pending'},'Verdict limitation'));
  return rows;
}

function graphNodes(graph){
  const nodes=new Map();
  for(const node of arr(graph.nodes)){
    const id=text(node?.id);if(!id)continue;
    nodes.set(id,{id,kind:text(node?.kind||'unknown'),role:text(node?.role||''),metadata:obj(node?.metadata)});
  }
  for(const edge of arr(graph.edges)){
    const source=text(edge?.source_id),target=text(edge?.target_id);
    if(source&&!nodes.has(source))nodes.set(source,{id:source,kind:text(edge?.source_kind||'unknown'),role:'',metadata:{}});
    if(target&&!nodes.has(target))nodes.set(target,{id:target,kind:text(edge?.target_kind||'unknown'),role:'',metadata:{}});
  }
  return [...nodes.values()];
}

function graphColumn(node,edges){
  const role=lower(node.role),kind=lower(node.kind);
  if(role.includes('fund')||edges.some(edge=>text(edge?.source_id)===node.id&&lower(edge?.evidence_kind)==='funding'))return'funder';
  if(kind.includes('token')||role.includes('token')||role.includes('mint'))return'token';
  if(kind.includes('verdict')||kind.includes('artifact')||role.includes('verdict')||role.includes('exit')||role.includes('lifecycle'))return'artifact';
  return'actor';
}

function renderGraph(host,graph,detailHost){
  host.textContent='';
  const edges=arr(graph.edges).slice(0,60);
  const allNodes=graphNodes(graph);
  const referenced=new Set();
  edges.forEach(edge=>{referenced.add(text(edge?.source_id));referenced.add(text(edge?.target_id));});
  const nodes=allNodes.filter(node=>referenced.has(node.id)).slice(0,36);
  const visibleIds=new Set(nodes.map(node=>node.id));
  const visibleEdges=edges.filter(edge=>visibleIds.has(text(edge?.source_id))&&visibleIds.has(text(edge?.target_id)));
  if(!nodes.length){host.appendChild(el('div','koschei-explorer-empty','No retained trajectory nodes are available for this investigation.'));return;}

  const columns={funder:[],actor:[],token:[],artifact:[]};
  for(const node of nodes)columns[graphColumn(node,visibleEdges)].push(node);
  const x={funder:110,actor:350,token:600,artifact:850};
  const positions=new Map();
  let maxRows=1;
  for(const [column,list] of Object.entries(columns)){
    maxRows=Math.max(maxRows,list.length);
    list.forEach((node,index)=>positions.set(node.id,{x:x[column],y:88+index*92,column}));
  }
  const height=Math.max(360,150+maxRows*92);
  const canvas=svg('svg',{viewBox:`0 0 960 ${height}`,role:'img','aria-label':'Funding trajectory graph'});
  canvas.classList.add('koschei-trajectory-svg');
  const defs=svg('defs');
  const marker=svg('marker',{id:'koscheiTrajectoryArrow',viewBox:'0 0 10 10',refX:'9',refY:'5',markerWidth:'6',markerHeight:'6',orient:'auto-start-reverse'});
  marker.appendChild(svg('path',{d:'M 0 0 L 10 5 L 0 10 z'}));defs.appendChild(marker);canvas.appendChild(defs);

  for(const [label,column] of [['FUNDING','funder'],['ACTOR','actor'],['TOKEN','token'],['OUTCOME / ARTIFACT','artifact']]){
    const title=svg('text',{x:x[column],y:30,'text-anchor':'middle',class:'koschei-graph-column-title'});title.textContent=label;canvas.appendChild(title);
  }

  visibleEdges.forEach((edge,index)=>{
    const a=positions.get(text(edge?.source_id)),b=positions.get(text(edge?.target_id));if(!a||!b)return;
    const mid=(a.x+b.x)/2;
    const path=svg('path',{d:`M ${a.x+68} ${a.y} C ${mid} ${a.y}, ${mid} ${b.y}, ${b.x-68} ${b.y}`,class:`koschei-graph-edge state-${stateOf(edge?.evidence_state)}`,'marker-end':'url(#koscheiTrajectoryArrow)','data-edge-index':index});
    path.addEventListener('click',()=>showTrajectoryDetail(detailHost,edge));canvas.appendChild(path);
  });

  nodes.forEach(node=>{
    const pos=positions.get(node.id);if(!pos)return;
    const group=svg('g',{class:`koschei-graph-node column-${pos.column}`,tabindex:'0',role:'button','aria-label':`${node.role||node.kind} ${node.id}`});
    const rect=svg('rect',{x:pos.x-68,y:pos.y-26,width:136,height:52,rx:12});
    const title=svg('text',{x:pos.x,y:pos.y-4,'text-anchor':'middle',class:'koschei-graph-node-role'});title.textContent=(node.role||node.kind||'node').replaceAll('_',' ').slice(0,20);
    const value=svg('text',{x:pos.x,y:pos.y+14,'text-anchor':'middle',class:'koschei-graph-node-id'});value.textContent=short(node.id,7,5);
    group.append(rect,title,value);
    const choose=()=>showTrajectoryDetail(detailHost,node);
    group.addEventListener('click',choose);group.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();choose();}});
    canvas.appendChild(group);
  });
  host.appendChild(canvas);
  if(allNodes.length>nodes.length||arr(graph.edges).length>visibleEdges.length){
    host.appendChild(el('div','koschei-explorer-boundary',`Visualization is bounded to ${nodes.length} nodes and ${visibleEdges.length} edges for readability. The complete retained payload remains available in Evidence Explorer.`));
  }
}

function showTrajectoryDetail(host,item){
  if(!host)return;
  host.textContent='';
  const isEdge=Object.prototype.hasOwnProperty.call(item||{},'source_id');
  host.append(el('span','koschei-explorer-eyebrow',isEdge?'SELECTED RELATION':'SELECTED NODE'));
  if(isEdge){
    host.append(el('h4','',`${short(item.source_id)} → ${short(item.target_id)}`));
    host.append(el('p','',`${text(item.relation||item.evidence_kind||'relation')} · ${stateOf(item.evidence_state).toUpperCase()} · ${text(item.source_provider||'provider unknown')}`));
    if(item.observed_at)host.append(el('small','',new Date(item.observed_at).toLocaleString()));
    if(item.signature)host.append(el('code','',text(item.signature)));
  }else{
    host.append(el('h4','',short(item.id,14,10)));
    host.append(el('p','',`${text(item.role||'unclassified role')} · ${text(item.kind||'unknown kind')}`));
  }
  const pre=el('pre','koschei-explorer-json');pre.textContent=JSON.stringify(item,null,2);host.appendChild(pre);
}

function renderTimeline(host,graph){
  host.textContent='';
  const edges=[...arr(graph.edges)].sort((a,b)=>text(a?.observed_at).localeCompare(text(b?.observed_at)));
  if(!edges.length){host.appendChild(el('div','koschei-explorer-empty','No retained trajectory events are available.'));return;}
  const list=el('div','koschei-timeline-list');
  edges.slice(0,120).forEach((edge,index)=>{
    const row=el('article','koschei-timeline-row');
    row.dataset.state=stateOf(edge?.evidence_state);
    const time=el('div','koschei-timeline-time');
    const parsed=new Date(edge?.observed_at||0);time.textContent=Number.isNaN(parsed.getTime())?'TIME UNRESOLVED':parsed.toLocaleString();
    const body=el('div','koschei-timeline-body');
    body.append(el('b','',`${short(edge?.source_id)} → ${short(edge?.target_id)}`),el('span','',`${text(edge?.relation||edge?.evidence_kind||'relation')} · ${stateOf(edge?.evidence_state).toUpperCase()}`));
    const meta=el('small','',`${text(edge?.source_provider||'provider unknown')}${edge?.slot?` · slot ${edge.slot}`:''}${edge?.signature?` · ${short(edge.signature,9,7)}`:''}`);
    body.appendChild(meta);row.append(time,body);list.appendChild(row);
  });
  host.appendChild(list);
  if(edges.length>120)host.appendChild(el('div','koschei-explorer-boundary',`Timeline shows the first 120 of ${edges.length} retained relations. Use Evidence Explorer for the complete payload.`));
}

function renderEvidenceExplorer(host,rows){
  host.textContent='';
  const controls=el('div','koschei-evidence-controls');
  const search=el('input','koschei-evidence-search');search.type='search';search.placeholder='Search evidence, rule, wallet, module, source…';search.setAttribute('aria-label','Search evidence');
  const family=el('select','koschei-evidence-filter');family.setAttribute('aria-label','Filter evidence family');
  ['All families',...new Set(rows.map(row=>row.family))].forEach(value=>{const option=el('option','',value);option.value=value==='All families'?'':value;family.appendChild(option);});
  const state=el('select','koschei-evidence-filter');state.setAttribute('aria-label','Filter evidence state');
  ['All states','verified','signed','observed','pending','na','unknown'].forEach(value=>{const option=el('option','',value);option.value=value==='All states'?'':value;state.appendChild(option);});
  controls.append(search,family,state);host.appendChild(controls);

  const summary=el('div','koschei-evidence-summary');host.appendChild(summary);
  const list=el('div','koschei-evidence-explorer-list');host.appendChild(list);
  const draw=()=>{
    const query=lower(search.value),wantedFamily=family.value,wantedState=state.value;
    const filtered=rows.filter(row=>(!wantedFamily||row.family===wantedFamily)&&(!wantedState||row.status===wantedState)&&(!query||lower(`${row.label} ${row.detail} ${row.path} ${JSON.stringify(row.raw)}`).includes(query)));
    summary.textContent=`${filtered.length} of ${rows.length} evidence records · ${rows.filter(row=>row.status==='verified').length} verified · ${rows.filter(row=>row.status==='signed').length} signed · ${rows.filter(row=>row.status==='pending').length} pending/unresolved`;
    list.textContent='';
    if(!filtered.length){list.appendChild(el('div','koschei-explorer-empty','No evidence record matches the current filters.'));return;}
    filtered.slice(0,160).forEach(row=>{
      const details=document.createElement('details');details.className='koschei-evidence-record';details.dataset.state=row.status;
      const summaryNode=document.createElement('summary');
      const title=el('div','koschei-evidence-record__title');title.append(el('span','',row.family),el('b','',row.label),el('small','',row.path));
      const badge=el('em','',row.status.toUpperCase());summaryNode.append(title,badge);details.appendChild(summaryNode);
      if(row.detail)details.appendChild(el('p','',row.detail));
      const pre=el('pre','koschei-explorer-json');pre.textContent=JSON.stringify(row.raw,null,2);details.appendChild(pre);list.appendChild(details);
    });
    if(filtered.length>160)list.appendChild(el('div','koschei-explorer-boundary',`Showing 160 of ${filtered.length} matching records. Refine the filters to inspect the remainder.`));
  };
  search.addEventListener('input',draw);family.addEventListener('change',draw);state.addEventListener('change',draw);draw();
}

function addTab(tabs,label,view,views){
  const button=el('button','',label);button.type='button';button.dataset.view=view;
  button.addEventListener('click',()=>{
    tabs.querySelectorAll('button').forEach(item=>item.setAttribute('aria-pressed',String(item===button)));
    for(const [name,node] of Object.entries(views))node.hidden=name!==view;
  });
  tabs.appendChild(button);return button;
}

function ensureNavigatorButton(card,section){
  const nav=card.querySelector('.koschei-evidence-nav');if(!nav||nav.querySelector('[data-evidence-explorer-nav]'))return;
  const button=el('button','','Evidence explorer');button.type='button';button.dataset.evidenceExplorerNav='v2';
  button.addEventListener('click',()=>section.scrollIntoView({behavior:'smooth',block:'start'}));nav.appendChild(button);
}

function installRawDebugDisclosure(card){
  const root=card.parentElement||card;
  root.querySelectorAll('pre').forEach(pre=>{
    if(pre.closest('.koschei-evidence-explorer')||pre.closest('details[data-koschei-raw-payload]')||text(pre.textContent).length<800)return;
    const details=document.createElement('details');details.className='koschei-raw-payload';details.dataset.koscheiRawPayload='v2';
    const summary=el('summary','','Raw technical payload');
    const note=el('small','','Collapsed by default. Canonical data is preserved byte-for-byte in this view.');
    pre.parentNode?.insertBefore(details,pre);details.append(summary,note,pre);
  });
}

function installExplorer(card){
  if(card.dataset.evidenceExplorer==='v2'){installRawDebugDisclosure(card);return;}
  const report=currentReport();
  if(!Object.keys(report).length)return;
  const graph=trajectoryFrom(report);
  const rows=collectEvidence(report);
  if(!rows.length&&!arr(graph.edges).length)return;
  const grid=card.querySelector('.arvis-premium-grid');if(!grid)return;
  card.dataset.evidenceExplorer='v2';

  const section=el('article','arvis-premium-section full koschei-evidence-explorer koschei-ux-section-target');
  const head=el('div','arvis-section-head');const copy=el('div','');
  copy.append(el('span','arvis-kicker','EVIDENCE EXPLORER'),el('h3','','Trace the evidence instead of reading a debug dump'),el('p','','Graph and timeline views project retained evidence only. Missing relations remain missing; visualization never creates attribution, identity, intent, wrongdoing, rug, or safety claims.'));
  head.appendChild(copy);section.appendChild(head);

  const metrics=el('div','koschei-explorer-metrics');
  const metric=(label,value)=>{const item=el('div','');item.append(el('span','',label),el('strong','',String(value??0)));metrics.appendChild(item);};
  metric('Evidence records',rows.length);metric('Trajectory nodes',graph.node_count??graphNodes(graph).length);metric('Trajectory edges',graph.edge_count??arr(graph.edges).length);metric('Verified edges',graph.verified_evidence_edge_count??arr(graph.edges).filter(edge=>stateOf(edge?.evidence_state)==='verified').length);
  section.appendChild(metrics);

  const tabs=el('div','koschei-explorer-tabs');section.appendChild(tabs);
  const graphView=el('div','koschei-explorer-view');const timelineView=el('div','koschei-explorer-view');const evidenceView=el('div','koschei-explorer-view');
  timelineView.hidden=true;evidenceView.hidden=true;
  const graphLayout=el('div','koschei-graph-layout');const graphHost=el('div','koschei-graph-host');const detailHost=el('aside','koschei-graph-detail');detailHost.append(el('span','koschei-explorer-eyebrow','TRAJECTORY DETAIL'),el('h4','','Select a node or relation'),el('p','','Click the graph to inspect its canonical evidence object.'));
  graphLayout.append(graphHost,detailHost);graphView.appendChild(graphLayout);
  section.append(graphView,timelineView,evidenceView);
  const views={graph:graphView,timeline:timelineView,evidence:evidenceView};
  const graphButton=addTab(tabs,'Trajectory graph','graph',views);addTab(tabs,'Timeline','timeline',views);addTab(tabs,'Evidence records','evidence',views);graphButton.setAttribute('aria-pressed','true');

  renderGraph(graphHost,graph,detailHost);renderTimeline(timelineView,graph);renderEvidenceExplorer(evidenceView,rows);
  const operator=[...card.querySelectorAll('.arvis-premium-section')].find(item=>text(item.querySelector('.arvis-kicker')?.textContent).toUpperCase().includes('OPERATOR INTELLIGENCE'));
  const rule=[...card.querySelectorAll('.arvis-premium-section')].find(item=>text(item.querySelector('.arvis-kicker')?.textContent).toUpperCase().includes('EXPLAINABLE VERDICT'));
  if(rule)grid.insertBefore(section,rule);else if(operator)operator.insertAdjacentElement('afterend',section);else grid.appendChild(section);
  ensureNavigatorButton(card,section);installRawDebugDisclosure(card);
}

function enhance(root=document){
  root.querySelectorAll?.('[data-arvis-premium-card]').forEach(installExplorer);
}

const observer=new MutationObserver(records=>{
  for(const record of records){
    for(const node of record.addedNodes){
      if(node.nodeType!==1)continue;
      if(node.matches?.('[data-arvis-premium-card]'))installExplorer(node);
      else if(node.querySelector?.('[data-arvis-premium-card]'))enhance(node);
      else{
        const card=node.closest?.('[data-arvis-premium-card]');if(card)installRawDebugDisclosure(card);
      }
    }
  }
});
observer.observe(document.documentElement,{childList:true,subtree:true});
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',()=>enhance());else enhance();
window.addEventListener('koschei:investigation-rendered',()=>enhance());
})();
