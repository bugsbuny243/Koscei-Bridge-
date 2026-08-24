(()=>{
'use strict';
if(window.__koscheiCustomerScanFlowV3)return;
window.__koscheiCustomerScanFlowV3=true;
const $=id=>document.getElementById(id);
const ready=fn=>document.readyState==='loading'?document.addEventListener('DOMContentLoaded',fn,{once:true}):fn();

function isLikelyURL(value){try{const url=new URL(value);return /^https?:$/.test(url.protocol)}catch{return false}}
function isLikelySolanaAddress(value){return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value)}
function isLikelyBase64Transaction(value){const compact=value.replace(/\s+/g,'');return compact.length>120&&compact.length%4===0&&/^[A-Za-z0-9+/]+={0,2}$/.test(compact)}

function mountAdvancedModes(){
  const modebar=document.querySelector('.modebar');if(!modebar||modebar.closest('.customer-scan-advanced'))return;
  const details=document.createElement('details');details.className='customer-scan-advanced';
  const summary=document.createElement('summary');summary.textContent='Advanced scan options';
  modebar.parentNode.insertBefore(details,modebar);details.append(summary,modebar);
  const modeSummary=$('modeSummary');if(modeSummary)details.appendChild(modeSummary);
}

function mountTypeOverride(){
  const kindLabel=$('kindLabel'),targetFields=$('targetFields');if(!kindLabel||!targetFields||kindLabel.closest('.customer-type-override'))return;
  const details=document.createElement('details');details.className='customer-type-override customer-scan-advanced';
  const summary=document.createElement('summary');summary.textContent='Target type override';
  kindLabel.parentNode.insertBefore(details,kindLabel);details.append(summary,kindLabel);
}

function mountDetectionStatus(){
  if($('customerDetectedType'))return $('customerDetectedType');
  const target=$('target');if(!target)return null;
  const node=document.createElement('div');node.className='customer-detected-type';node.id='customerDetectedType';
  node.innerHTML='<span>Target detection</span><b>Waiting for input</b>';
  target.parentElement?.insertAdjacentElement('afterend',node);
  return node;
}

function setDetected(label){const node=$('customerDetectedType');const strong=node?.querySelector('b');if(strong)strong.textContent=label;}

function installDetection(){
  const target=$('target'),kind=$('kind'),transaction=$('transaction');if(!target||!kind)return;
  let manualOverride=false;
  kind.addEventListener('change',()=>{manualOverride=true;setDetected(`Manual override · ${kind.options[kind.selectedIndex]?.text||kind.value}`)});
  const update=()=>{
    const value=target.value.trim();
    if(!value){setDetected('Waiting for input');return}
    if(isLikelyURL(value)){
      if(!manualOverride)kind.value='site';
      setDetected('Site URL detected');
      return;
    }
    if(isLikelyBase64Transaction(value)){
      setDetected('Serialized Solana transaction detected');
      if(transaction&&!transaction.value.trim())transaction.value=value.replace(/\s+/g,'');
      const button=document.querySelector('[data-scan-mode="transaction"]');
      if(button&&button.getAttribute('aria-pressed')!=='true')button.click();
      return;
    }
    if(isLikelySolanaAddress(value)){
      if(!manualOverride)kind.value='token';
      setDetected('Solana address detected · token investigation selected by default');
      return;
    }
    setDetected('Target type unresolved · Koschei will not infer safety from the label');
  };
  target.addEventListener('input',update);target.addEventListener('change',update);update();
}

function simplifyCopy(){
  const hero=document.querySelector('section.surface.panel');
  const heading=hero?.querySelector('h1');if(heading)heading.textContent='Paste it. Check it before you trust it.';
  const sub=hero?.querySelector('p.sub');if(sub)sub.textContent='Start with one target. Koschei keeps the scan simple here and leaves advanced collector choices available only when you need them.';
  const form=$('scanForm');if(form&&!form.querySelector('.customer-scan-helper')){
    const helper=document.createElement('p');helper.className='customer-scan-helper';helper.innerHTML='<strong>One customer flow:</strong> paste a token, wallet, site or serialized transaction. Ambiguous Solana addresses stay explicit instead of being silently reclassified.';
    form.parentNode.insertBefore(helper,form);
  }
  const target=$('target');if(target)target.placeholder='Paste token mint, wallet address, site URL, or transaction';
  const targetLabel=target?.closest('label');if(targetLabel?.firstChild)targetLabel.firstChild.textContent='What do you want to check?';
  const note=$('note');if(note){note.placeholder='Optional: what are you about to do? Example: buy this token, connect to this site, sign this transaction';}
  const noteLabel=note?.closest('label');if(noteLabel?.firstChild)noteLabel.firstChild.textContent='What are you about to do? (optional)';
  const empty=$('empty');if(empty&&!empty.hidden&&!$('result')?.innerHTML.trim())empty.innerHTML='<h2 style="margin-top:16px">Your result will appear here.</h2><p class="sub" style="margin-top:9px">Koschei will show the decision first, then the reasons, unresolved evidence and the technical proof underneath.</p>';
}

function preserveAdvancedState(){
  document.querySelectorAll('[data-scan-mode]').forEach(button=>button.addEventListener('click',()=>{
    const details=button.closest('.customer-scan-advanced');
    if(details&&button.dataset.scanMode!=='token')details.open=false;
  }));
}

ready(()=>{mountAdvancedModes();mountTypeOverride();mountDetectionStatus();simplifyCopy();installDetection();preserveAdvancedState();});
})();