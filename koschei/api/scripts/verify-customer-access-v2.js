'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const account=fs.readFileSync(path.join(root,'public','account.html'),'utf8');
const js=fs.readFileSync(path.join(root,'public','js','customer-access-v2.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','customer-access-v2.css'),'utf8');
const wallet=fs.readFileSync(path.join(root,'internal','handlers','wallet_ownership.go'),'utf8');
const premium=fs.readFileSync(path.join(root,'internal','handlers','premium_access_status.go'),'utf8');
const plan=fs.readFileSync(path.join(root,'internal','handlers','plan_access.go'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden pattern ${pattern}`);}

requireText(account,'<html lang="en">','account language');
requireText(account,'Professional Access','account Professional identity');
requireText(account,'Your identity opens the door. The entitlement opens the system.','identity/access separation');
requireText(account,'Koschei Professional is the single operational customer plan','single operational plan');
requireText(account,'id="plan"','plan field');
requireText(account,'id="outputCapacity"','output capacity field');
requireText(account,'API-key management requires an active Professional entitlement.','Professional API key boundary');
requireText(account,'/js/customer-access-v2.js?v=3','account access controller');
requireText(account,'/pricing','pricing route');
requireText(account,'/css/koschei-universe-v1.css?v=1','universe stylesheet');
forbid(account,/KOSCH Access|TOKEN ACCESS EVIDENCE|Official mint snapshot|LIVE TOKEN POLICY|ARVIS EARLY ACCESS|STARTER\+|ENTERPRISE\+/i,'retired access UI');

requireText(wallet,'Statement: Sign this message to link your wallet. This does not authorize a transaction.','wallet identity authority boundary');
requireText(wallet,'"verified": true','wallet verification success field');
requireText(wallet,'"unlinked": true','wallet unlink success field');
requireText(premium,'Source:           "entitlement"','premium entitlement source');
requireText(premium,'Plan:             evaluation.Plan','premium plan response');
requireText(premium,'OutputsRemaining: evaluation.OutputsRemaining','premium output response');
forbid(premium,/TokenGate|TokenTier|token_amount|KOSCH/i,'token-backed premium access');
requireText(plan,'FROM entitlements','backend entitlement authority');
requireText(plan,"status='active'",'active entitlement requirement');
requireText(plan,'func (h *Handler) RequirePlanTier','paid route authorization');

requireText(js,"read('/api/auth/wallet/status')",'wallet identity source');
requireText(js,"read('/api/auth/premium-access')",'SaaS access source');
forbid(js,/\/api\/auth\/token-access/,'retired token access source');
requireText(js,"text(access.source)!=='entitlement'",'entitlement source completeness gate');
requireText(js,"setText('outputCapacity'",'capacity rendering');
requireText(js,'Token holdings are not part of this decision.','token separation rendering');
requireText(js,"write('/api/auth/wallet/challenge'",'wallet challenge');
requireText(js,'provider.signMessage','verification message signature');
requireText(js,'This does not change your SaaS plan.','wallet identity-only message');
requireText(js,'Your SaaS entitlement is unchanged.','wallet unlink plan isolation');
requireText(js,"KoscheiAuth.requireAuth('/login.html')",'canonical login continuation');
for(const forbidden of ['signTransaction','signAllTransactions','sendTransaction','signAndSendTransaction'])if(js.includes(forbidden))throw new Error(`customer access controller must not contain transaction authority: ${forbidden}`);
forbid(js,/\bfetch\s*\(/,'raw fetch bypassing KoscheiAuth');
forbid(js,/Authorization/i,'manual bearer header');
forbid(js,/\blocalStorage\b|\bsessionStorage\b/,'browser auth/access persistence');
forbid(js,/\.innerHTML\s*=/,'API-derived innerHTML');
forbid(js,/Math\.random\s*\(/,'synthetic access evidence');
forbid(js,/token_(?:tier|amount)|KOSCH balance|mint_address/i,'token access state in controller');
requireText(css,'.access-state-card','access state styles');
requireText(css,'.access-thresholds','plan capacity styles');
requireText(css,'.access-security-boundary','security boundary styles');
console.log('customer Professional access contract: ok');
