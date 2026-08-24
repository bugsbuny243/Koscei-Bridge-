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

// Investigation/report evidence contract.
need('public/js/public-solana-scan.js', 'Pending evidence arms and monitoring windows');
need('public/js/public-solana-scan.js', 'QUICK PREFLIGHT');
need('public/js/public-solana-scan.js', 'Missing evidence = no safety decision');
need('public/js/public-solana-scan.js', '/api/public/transaction-simulate');
need('public/js/lp-control-evidence-card.js', 'Havuz hareket geçmişi bu taramada doğrulanamadı');
need('public/scan.html', 'Evidence-backed investigation');
need('public/scan.html', 'Missing evidence is shown as a limitation, not converted into a safety claim.');
need('public/scan.html', 'Transaction simulation never signs or broadcasts.');
need('public/scan.html', '/css/koschei-enterprise-v3.css?v=1');

// The homepage is now customer-first while preserving the same evidence and
// authority boundaries. The contract must protect those boundaries instead of
// freezing retired architecture-first marketing copy.
need('public/index.html', 'Check it before you trust it.');
need('public/index.html', 'One scan. Four questions answered.');
need('public/index.html', 'The proof still matters.');
need('public/index.html', 'Production signing enforcement remains a separate validation milestone');
need('public/index.html', 'Unknown stays unknown');
need('public/index.html', 'no synthetic certainty');
need('public/index.html', '/css/koschei-enterprise-v3.css?v=1');
reject('public/index.html', '/js/homepage-preflight-v2.js?v=1');
reject('public/index.html', '/js/koschei-security-world.js?v=1');
reject('public/index.html', 'STATIC HTML + VANILLA JS');

console.log('investigation, report and homepage trust consistency contract verified');
