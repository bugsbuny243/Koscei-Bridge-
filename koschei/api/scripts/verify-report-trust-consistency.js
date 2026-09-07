const fs = require('fs');

function read(file) {
  return fs.readFileSync(file, 'utf8');
}

function need(file, text) {
  const body = read(file);
  if (!body.includes(text)) throw new Error(`${file} missing ${text}`);
}

function reject(file, text) {
  const body = read(file);
  if (body.includes(text)) throw new Error(`${file} contains retired ${text}`);
}

// Investigation/report evidence contract. The internal controller may retain
// compatibility parsing for old quick-preflight responses, but the customer UI
// no longer exposes free Quick Check execution.
need('public/js/public-solana-scan.js', 'Pending evidence arms and monitoring windows');
need('public/js/public-solana-scan.js', 'Missing evidence = no safety decision');
need('public/js/public-solana-scan.js', '/api/public/transaction-simulate');
need('public/js/lp-control-evidence-card.js', 'Havuz hareket geçmişi bu taramada doğrulanamadı');
need('public/scan.html', 'PROFESSIONAL · CLASSIC INVESTIGATION CONSOLE');
need('public/scan.html', 'Missing evidence is shown as a limitation, not converted into a safety claim.');
need('public/scan.html', 'Transaction simulation never signs or broadcasts.');
need('public/scan.html', 'Free Quick Check execution has been removed');
need('public/scan.html', '/css/koschei.css?v=1');
need('public/scan.html', '/css/koschei.css?v=1');
reject('public/scan.html', 'data-scan-mode="quick"');
reject('public/scan.html', 'Professional+');

// Homepage keeps the same evidence and authority boundaries while becoming
// the cinematic Universe Gateway. Solana is the only production-live chain.
need('public/index.html', 'One address. Full threat context.');
need('public/index.html', 'Solana is the live production core today.');
need('public/index.html', 'without inventing certainty');
need('public/index.html', 'Professional operation · no private keys · no custody · unknown stays unknown');
need('public/index.html', 'Enter the universe');
need('public/index.html', '/css/koschei.css?v=1');
need('public/index.html', '/css/koschei.css?v=1');
need('public/index.html', '/js/koschei-home-universe-v2.js?v=1');
reject('public/index.html', '/js/homepage-preflight-v2.js?v=1');
reject('public/index.html', '/js/koschei-security-world.js?v=1');
reject('public/index.html', 'STATIC HTML + VANILLA JS');
reject('public/index.html', 'Ethereum</b><small>LIVE');
reject('public/index.html', 'TRON</b><small>LIVE');

console.log('Professional investigation, report and Universe Gateway trust consistency contract verified');
