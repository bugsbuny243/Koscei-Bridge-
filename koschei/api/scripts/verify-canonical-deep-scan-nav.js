'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const shell=fs.readFileSync(path.join(root,'public','js','koschei-global-shell.js'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden pattern ${pattern}`);}

requireText(shell,"['/scan?mode=deep','Deep Scan']",'canonical deep scan global nav');
requireText(shell,"if(href==='/scan?mode=deep')return current==='/scan'&&mode==='deep'",'deep scan active state');
requireText(shell,"if(href==='/scan')return current==='/scan'&&mode!=='deep'",'token scan active state');
requireText(shell,"if(current!=='/security-radar'||window.KoscheiInvestigationShare",'legacy share compatibility');
requireText(shell,"if(current==='/security-radar')document.title='ARVIS Security Radar — Koschei Web3'",'ARVIS radar title remains inside Koschei Web3');
requireText(shell,'installBoundedAPIFetch();','bounded API fetch remains installed');
requireText(shell,'translate(document.body);','translation compatibility remains installed');
requireText(shell,"path.indexOf('/api/token/scan')===0",'token scan timeout policy remains supported');

forbid(shell,/function\s+installLandingQuickCheck\b/,'latent homepage quick-check runtime');
forbid(shell,/installLandingQuickCheck\s*\(/,'latent quick-check invocation');
forbid(shell,/\/security-radar\?target=/,'legacy radar user navigation');
forbid(shell,/\['\/security-radar','Security Radar'\]/,'legacy radar global nav');
forbid(shell,/fetch\s*\(\s*['"]\/api\/token\/scan/,'global shell token decision request');
forbid(shell,/fetch\s*\(\s*['"]\/api\/arvis\/preflight/,'global shell preflight decision request');
forbid(shell,/data\.score\s*\|\|\s*data\.risk_index/,'global shell risk zero fallback');
requireText(shell,"script.src='/js/investigation-share.js?v=1'",'legacy investigation share loader preserved');
console.log('canonical deep scan global navigation contract: ok');
