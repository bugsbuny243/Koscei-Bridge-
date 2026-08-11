'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const account=fs.readFileSync(path.join(root,'public','account.html'),'utf8');
const holder=fs.readFileSync(path.join(root,'public','kosch-access.html'),'utf8');
const js=fs.readFileSync(path.join(root,'public','js','customer-access-v2.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','customer-access-v2.css'),'utf8');
const wallet=fs.readFileSync(path.join(root,'internal','handlers','wallet_ownership.go'),'utf8');
const token=fs.readFileSync(path.join(root,'internal','handlers','token_access.go'),'utf8');
const premium=fs.readFileSync(path.join(root,'internal','handlers','premium_access_status.go'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden pattern ${pattern}`);}

for(const [html,label] of [[account,'account html'],[holder,'holder html']]){
  requireText(html,'<html lang="en">',label);
  requireText(html,'/css/customer-operations-v2.css?v=1',label);
  requireText(html,'/css/customer-access-v2.css?v=1',label);
  requireText(html,'/js/customer-access-v2.js?v=2',label);
  requireText(html,'id="accessStateCard"',label);
  requireText(html,'id="accessThresholds"',label);
  requireText(html,'/scan?mode=deep',`${label} canonical Deep Scan route`);
}
requireText(holder,'not an equity, revenue-share, yield, or guaranteed-return promise','holder utility boundary');
requireText(holder,'does not request a seed phrase, private key, token approval, custody transfer, or transaction signature','holder self-custody boundary');
requireText(holder,'Missing evidence is not inactivity.','holder evidence-completeness boundary');
requireText(account,'No hardcoded legacy thresholds and no incomplete-state downgrade.','account dynamic threshold boundary');
requireText(account,'All three sources must agree.','account consensus boundary');
requireText(account,'does not authorize a transaction, token approval, or transfer','account message-signature boundary');
if(account.includes('/kosch-access'))throw new Error('account html must use canonical /kosch route');

requireText(wallet,'writeJSON(w, http.StatusOK, map[string]any{"ok": true, "linked": false})','authoritative unlinked wallet state');
requireText(wallet,'writeJSON(w, http.StatusOK, map[string]any{"ok": true, "linked": true, "wallet_address": wallet, "network": network','authoritative linked wallet state');
requireText(wallet,'Statement: Sign this message to link your wallet. This does not authorize a transaction.','server wallet challenge authority boundary');
requireText(wallet,'"verified": true','server wallet verification success field');
requireText(wallet,'"unlinked": true','server wallet unlink success field');

for(const field of ['GateEnabled     bool','Configured      bool','WalletVerified  bool','Network         string','Amount          string','Tier            string'])requireText(token,field,`token access field ${field}`);
requireText(token,'writeJSON(w, http.StatusOK, map[string]any{"ok": true, "access": evaluation})','token access response envelope');
requireText(token,'"basic":      tokenTierThresholdEnv','backend Basic threshold source');
requireText(token,'"pro":        tokenTierThresholdEnv','backend Pro threshold source');
requireText(token,'"enterprise": tokenTierThresholdEnv','backend Enterprise threshold source');

for(const field of ['Active              bool','Source              string','TokenGateEnabled    bool','TokenConfigured     bool','WalletVerified      bool','TokenTier           string','RequiredTokenTier   string'])requireText(premium,field,`premium access field ${field}`);
requireText(premium,'"ok":     true','premium response ok marker');
requireText(premium,'"access": decidePremiumAccess(tokenAccess, quota)','premium authoritative decision');
requireText(premium,'RequiredTokenTier: "basic"','premium required tier source');
requireText(premium,'status.Active = true','premium active decision');

requireText(js,"read('/api/auth/wallet/status')",'wallet source');
requireText(js,"read('/api/auth/token-access')",'token access source');
requireText(js,"read('/api/auth/premium-access')",'premium source');
requireText(js,"data.ok!==true||typeof data.linked!=='boolean'",'wallet HTTP-200 completeness gate');
requireText(js,"data.ok!==true||!access",'access envelope completeness gate');
requireText(js,"gate===null||configured===null||walletVerified===null||!network||tier===null||!hasValue(access.amount)",'token structural completeness gate');
requireText(js,"active===null||gate===null||configured===null||walletVerified===null||tier===null||required===null||!hasValue(access.token_amount)||!source",'premium structural completeness gate');
requireText(js,"if(!wallet.available||!token.available||!premium.available)",'three-source availability gate');
requireText(js,'token.gate!==premium.gate||token.configured!==premium.configured||token.walletVerified!==premium.walletVerified||token.tier!==premium.tier','token/premium consistency gate');
requireText(js,'wallet.linked!==token.walletVerified||wallet.linked!==premium.walletVerified','wallet verification consistency gate');
requireText(js,'token.walletAddress!==wallet.address','wallet address consistency gate');
requireText(js,'premium.active!==shouldBeActive','premium/token decision consistency gate');
requireText(js,"setState('active','ACTIVE'",'consensus active state');
requireText(js,"setState('inactive','INACTIVE'",'evidence-complete inactive state');
requireText(js,"setState('unavailable','UNAVAILABLE'",'unavailable boundary');
requireText(js,"setState('unavailable','CONFLICT'",'conflict boundary');
requireText(js,'isObject(access?.thresholds)?access.thresholds:null','backend threshold object source');
requireText(js,"host.appendChild(el('div','ops-empty','Tier thresholds are unavailable",'missing threshold boundary');
requireText(js,"write('/api/auth/wallet/challenge'",'wallet challenge');
requireText(js,"provider.signMessage",'verification message signature');
requireText(js,"text(challenge?.wallet_address)!==wallet",'challenge wallet consistency');
requireText(js,"verified?.ok!==true||verified?.verified!==true||text(verified?.wallet_address)!==wallet",'verification response completeness');
requireText(js,"data?.ok!==true||data?.unlinked!==true",'unlink response completeness');
requireText(js,"network:currentNetwork",'dynamic verification network');
requireText(js,"window.confirm('Remove the verified wallet link",'unlink confirmation');
requireText(js,"KoscheiAuth.requireAuth('/login.html')",'canonical login continuation');

for(const forbidden of ['signTransaction','signAllTransactions','sendTransaction','signAndSendTransaction']){
  if(js.includes(forbidden))throw new Error(`customer access controller must not contain transaction authority: ${forbidden}`);
}
forbid(js,/\bfetch\s*\(/,'raw fetch bypassing KoscheiAuth');
forbid(js,/Authorization/i,'manual bearer header');
forbid(js,/\blocalStorage\b|\bsessionStorage\b/,'browser auth/access persistence');
forbid(js,/\.innerHTML\s*=/,'API-derived innerHTML');
forbid(js,/Math\.random\s*\(/,'synthetic access evidence');
forbid(js,/const\s+obj\s*=.*\?value:\{\}/,'missing access object coerced to empty object');
for(const stale of ['250K KOSCH','2M KOSCH','250000 KOSCH','2000000 KOSCH']){
  if(account.includes(stale)||holder.includes(stale)||js.includes(stale))throw new Error(`access UI must not hardcode backend threshold: ${stale}`);
}
if(/[İıŞşĞğÇçÖöÜü]/.test(holder))throw new Error('holder access page must remain on the unified English product surface');
requireText(css,'.access-state-card','access state styles');
requireText(css,'.access-thresholds','dynamic threshold styles');
requireText(css,'.access-security-boundary','self-custody boundary styles');
console.log('customer access evidence-complete contract: ok');
