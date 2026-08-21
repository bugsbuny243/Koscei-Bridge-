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

// The homepage is the Koschei Web3 security-control-plane surface. Preserve
// the evidence/authority boundary without depending on decorative simulation
// or the retired scanner-first homepage preflight script.
need('public/index.html', 'See the execution.');
need('public/index.html', 'NO VALID PROOF = NO SIGNATURE');
need('public/index.html', 'Production enforcement is not yet enabled.');
need('public/index.html', 'Missing evidence, incomplete observation or an unverified runtime boundary is surfaced as uncertainty.');
need('public/index.html', '/css/koschei-enterprise-v3.css?v=1');
reject('public/index.html', '/js/homepage-preflight-v2.js?v=1');
reject('public/index.html', '/js/koschei-security-world.js?v=1');
reject('public/index.html', 'STATIC HTML + VANILLA JS');

console.log('investigation, report and homepage trust consistency contract verified');
