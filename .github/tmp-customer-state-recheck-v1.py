from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path, old, new):
    p = ROOT / path
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, got {count}: {old[:120]!r}")
    p.write_text(text.replace(old, new, 1))


server = "koschei/api/internal/http/server.go"
old = 'mux.HandleFunc("/api/customer/web3/transaction-preflight", solana(requiresDB(h, planTier("professional", method("POST", h.TransactionGuardV2Configured)))))'
new = old + '\n\tmux.HandleFunc("/api/customer/web3/transaction-state-recheck", solana(requiresDB(h, planTier("professional", method("POST", h.TransactionGuardStateRecheck)))))'
replace_once(server, old, new)

inventory = "koschei/api/internal/http/route_inventory.go"
replace_once(
    inventory,
    '"POST /api/v1/token/extensions", "POST /api/v1/address-poisoning/check", "POST /api/customer/web3/transaction-preflight",',
    '"POST /api/v1/token/extensions", "POST /api/v1/address-poisoning/check", "POST /api/customer/web3/transaction-preflight", "POST /api/customer/web3/transaction-state-recheck",',
)

generator = "koschei/api/internal/openapi/generator.go"
replace_once(
    generator,
    'case path == "/api/customer/web3/transaction-preflight":',
    'case path == "/api/customer/web3/transaction-preflight" || path == "/api/customer/web3/transaction-state-recheck":',
)

preflight_verifier = "koschei/api/scripts/verify-customer-transaction-preflight-v1.js"
replace_once(
    preflight_verifier,
    'if(!generator.includes(\'case path == "/api/customer/web3/transaction-preflight":\'))throw new Error("OpenAPI auth classifier missing customer preflight");',
    'if(!generator.includes(\'case path == "/api/customer/web3/transaction-preflight" || path == "/api/customer/web3/transaction-state-recheck":\'))throw new Error("OpenAPI auth classifier missing Professional customer preflight/recheck");',
)

access_test = "koschei/api/internal/http/server_access_test.go"
replace_once(
    access_test,
    'Professional covers transaction preflight and advanced radar surfaces. Job',
    'Professional covers transaction preflight, state witness recheck, and advanced radar surfaces. Job',
)
replace_once(
    access_test,
    'want := []string{"starter", "starter", "starter", "starter", "starter", "starter", "professional", "professional", "professional", "professional", "professional", "professional", "professional"}',
    'want := []string{"starter", "starter", "starter", "starter", "starter", "starter", "professional", "professional", "professional", "professional", "professional", "professional", "professional", "professional"}',
)

js = "koschei/api/public/js/customer-transaction-preflight-v1.js"
replace_once(
    js,
    "const endpoint='/api/customer/web3/transaction-preflight';\n",
    "const endpoint='/api/customer/web3/transaction-preflight';\nconst recheckEndpoint='/api/customer/web3/transaction-state-recheck';\nlet pendingRecheck=null;\n",
)

marker = "function working(){\n"
addition = """function clearPendingRecheck(){
  pendingRecheck=null;
}
function prepareStateRecheck(data){
  clearPendingRecheck();
  const permit=data?.enforcement_permit;
  const witness=data?.state_witness;
  if(data?.enforcement_permit_issued===true&&permit?.token&&data?.state_witness_complete===true&&witness?.complete===true){
    pendingRecheck={permitToken:String(permit.token),network:String(data?.network||'solana-mainnet'),stateWitness:witness,expiresAt:String(permit?.claims?.expires_at||'')};
  }
}
function mountStateRecheck(){
  if(!pendingRecheck)return;
  const article=result.querySelector('[data-customer-transaction-preflight-result]');
  if(!article||article.querySelector('[data-customer-state-recheck]'))return;
  const panel=document.createElement('div');
  panel.className='section';
  panel.dataset.customerStateRecheck='1';
  panel.innerHTML=`<h3>Fresh state recheck before signing</h3><p class=\"historySummary\">A state-bound permit is available. Paste the exact same serialized transaction again immediately before signing. Koschei will re-read only the bounded witnessed account set. The transaction is not signed or broadcast.</p><textarea id=\"stateRecheckTransaction\" class=\"input mono\" rows=\"5\" autocomplete=\"off\" spellcheck=\"false\" placeholder=\"Paste the same base64 transaction again\"></textarea><p class=\"actions\" style=\"margin-top:12px\"><button class=\"btn\" id=\"stateRecheckRun\" type=\"button\">Recheck state now</button></p><p class=\"fine\">Permit expires ${esc(pendingRecheck.expiresAt||'soon')}. Permit and witness remain only in page memory and are cleared after this recheck or when the page closes.</p><div id=\"stateRecheckResult\"></div>`;
  article.appendChild(panel);
  document.getElementById('stateRecheckRun')?.addEventListener('click',runStateRecheck);
}
async function runStateRecheck(){
  const snapshot=pendingRecheck;
  const editor=document.getElementById('stateRecheckTransaction');
  const output=document.getElementById('stateRecheckResult');
  const button=document.getElementById('stateRecheckRun');
  const serialized=editor?.value.trim()||'';
  if(!snapshot||!serialized)return;
  if(button){button.disabled=true;button.textContent='Rechecking witnessed state…';}
  if(output)output.innerHTML='<p class=\"historySummary\">Collecting fresh bounded account-state evidence. No safety claim is made until the server returns a verified decision.</p>';
  try{
    const response=await fetch(recheckEndpoint,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({permit_token:snapshot.permitToken,transaction:serialized,network:snapshot.network,state_witness:snapshot.stateWitness})});
    const data=await response.json().catch(()=>({}));
    const decision=data?.decision||{};
    const safe=data?.safe_to_proceed===true;
    if(output){
      const title=safe?'STATE UNCHANGED — SERVER SAYS SAFE TO PROCEED':'DO NOT RELY ON PRIOR PREFLIGHT';
      const detail=decision?.reason||data?.message||data?.code||`HTTP ${response.status}`;
      output.innerHTML=`<div class=\"public-signal ${safe?'verified':'arm_pending'}\"><span><b>${esc(title)}</b><small>${esc(String(decision?.status||data?.code||'state recheck incomplete').toUpperCase())}</small></span><em>${safe?'PROCEED':'WITHHOLD'}</em></div><p class=\"historySummary\" style=\"margin-top:10px\">${esc(detail)}</p>`;
    }
  }catch(error){
    if(output)output.innerHTML=`<div class=\"public-signal arm_pending\"><span><b>STATE RECHECK UNAVAILABLE</b><small>${esc(error?.message||'Fresh state evidence could not be collected.')}</small></span><em>WITHHOLD</em></div>`;
  }finally{
    if(editor)editor.value='';
    clearPendingRecheck();
    if(button){button.disabled=true;button.textContent='State recheck consumed';}
  }
}

"""
replace_once(js, marker, addition + marker)
replace_once(
    js,
    "</div></article>`;\n}\n\nform.addEventListener",
    "</div></article>`;\n  mountStateRecheck();\n}\n\nform.addEventListener",
)
replace_once(
    js,
    "    render(data);\n    transaction.value='';",
    "    prepareStateRecheck(data);\n    render(data);\n    transaction.value='';",
)
replace_once(
    js,
    "},true);\n})();\n",
    "},true);\nwindow.addEventListener('pagehide',clearPendingRecheck);\n})();\n",
)

verifier = ROOT / "koschei/api/scripts/verify-customer-state-recheck-v1.js"
verifier.write_text(r'''const fs=require('fs');
const path=require('path');
const root=path.resolve(__dirname,'..');
const server=fs.readFileSync(path.join(root,'internal/http/server.go'),'utf8');
const inventory=fs.readFileSync(path.join(root,'internal/http/route_inventory.go'),'utf8');
const generator=fs.readFileSync(path.join(root,'internal/openapi/generator.go'),'utf8');
const ui=fs.readFileSync(path.join(root,'public/js/customer-transaction-preflight-v1.js'),'utf8');
const route='mux.HandleFunc("/api/customer/web3/transaction-state-recheck", solana(requiresDB(h, planTier("professional", method("POST", h.TransactionGuardStateRecheck)))))';
if(!server.includes(route))throw new Error('customer state recheck must reuse existing handler behind Professional planTier');
if(!inventory.includes('POST /api/customer/web3/transaction-state-recheck'))throw new Error('customer state recheck missing from route inventory');
if(!generator.includes('path == "/api/customer/web3/transaction-state-recheck"'))throw new Error('OpenAPI auth classifier missing customer state recheck');
for(const required of ["const recheckEndpoint='/api/customer/web3/transaction-state-recheck'",'permit_token:snapshot.permitToken','state_witness:snapshot.stateWitness',"credentials:'same-origin'",'data?.safe_to_proceed===true','clearPendingRecheck();',"window.addEventListener('pagehide',clearPendingRecheck)"])if(!ui.includes(required))throw new Error('customer state recheck UI contract missing: '+required);
if(ui.includes('localStorage')||ui.includes('sessionStorage'))throw new Error('customer preflight/recheck must not persist transaction or permit material in browser storage');
if(!ui.includes("transaction.value='';"))throw new Error('successful preflight must still clear raw transaction textarea');
if(!ui.includes("if(editor)editor.value='';"))throw new Error('state recheck must clear repasted raw transaction after request');
console.log('customer state recheck v1 contract ok');
''')
