'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const account=fs.readFileSync(path.join(root,'public','account.html'),'utf8');
const holder=fs.readFileSync(path.join(root,'public','kosch-access.html'),'utf8');
const js=fs.readFileSync(path.join(root,'public','js','customer-access-v2.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','customer-access-v2.css'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
for(const [html,label] of [[account,'account html'],[holder,'holder html']]){
  requireText(html,'<html lang="en">',label);
  requireText(html,'/css/customer-operations-v2.css?v=1',label);
  requireText(html,'/css/customer-access-v2.css?v=1',label);
  requireText(html,'/js/customer-access-v2.js?v=1',label);
  requireText(html,'id="accessStateCard"',label);
  requireText(html,'id="accessThresholds"',label);
}
requireText(holder,'not an equity, revenue-share, yield, or guaranteed-return promise','holder utility boundary');
requireText(holder,'does not request a seed phrase, private key, token approval, custody transfer, or transaction signature','holder self-custody boundary');
requireText(account,'No hardcoded legacy thresholds','account dynamic threshold boundary');

requireText(js,"read('/api/auth/wallet/status')",'wallet source');
requireText(js,"read('/api/auth/token-access')",'token access source');
requireText(js,"read('/api/auth/premium-access')",'premium source');
requireText(js,"write('/api/auth/wallet/challenge'",'wallet challenge');
requireText(js,"provider.signMessage",'verification signature');
requireText(js,"write('/api/auth/wallet/verify'",'wallet verify');
requireText(js,"write('/api/auth/wallet/unlink'",'wallet unlink');
requireText(js,"obj(access?.thresholds)",'backend threshold source');
requireText(js,"host.textContent=''",'threshold DOM reset');
requireText(js,"card.append(el('span'",'safe threshold DOM rendering');
requireText(js,"setState('unavailable','UNAVAILABLE'",'premium unavailable boundary');
requireText(js,"setState('unavailable','CONFLICT'",'wallet source conflict boundary');
requireText(js,"tokenWallet!==wallet.address",'wallet source consistency check');
requireText(js,"network:currentNetwork",'dynamic verification network');
requireText(js,"confirm('Remove the verified wallet link",'unlink confirmation');

for(const forbidden of ['signTransaction','signAllTransactions','sendTransaction','signAndSendTransaction']){
  if(js.includes(forbidden))throw new Error(`customer access controller must not contain transaction authority: ${forbidden}`);
}
if(/\bfetch\s*\(/.test(js))throw new Error('customer access account data must flow through KoscheiAuth.apiCall');
for(const stale of ['250K KOSCH','2M KOSCH','250000 KOSCH','2000000 KOSCH']){
  if(account.includes(stale)||holder.includes(stale)||js.includes(stale))throw new Error(`access UI must not hardcode backend threshold: ${stale}`);
}
if(/[İıŞşĞğÇçÖöÜü]/.test(holder))throw new Error('holder access page must remain on the unified English product surface');
requireText(css,'.access-state-card','access state styles');
requireText(css,'.access-thresholds','dynamic threshold styles');
requireText(css,'.access-security-boundary','self-custody boundary styles');
console.log('customer access v2 contract: ok');
