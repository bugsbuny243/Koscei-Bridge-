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

// Canonical investigation/report evidence contract.
need('public/js/public-solana-scan.js', 'Pending evidence arms and monitoring windows');
need('public/js/public-solana-scan.js', 'QUICK PREFLIGHT');
need('public/js/public-solana-scan.js', 'Missing evidence = no safety decision');
need('public/js/public-solana-scan.js', '/api/public/transaction-simulate');
need('public/js/lp-control-evidence-card.js', 'Havuz hareket geçmişi bu taramada doğrulanamadı');
need('public/scan.html', 'One scan page · four evidence modes');
need('public/scan.html', 'Missing evidence never becomes safety.');

// The homepage is now the Koschei Web3 security-control-plane surface. It must
// preserve the evidence/authority boundary without depending on the retired
// scanner-first homepage preflight script.
need('public/index.html', 'See the execution.');
need('public/index.html', 'NO VALID PROOF = NO SIGNATURE');
need('public/index.html', 'visualization layer · not a synthetic live verdict');
need('public/index.html', '/js/koschei-security-world.js?v=1');
need('public/index.html', 'A dashboard score is not an authorization primitive; reproducible evidence is.');
reject('public/index.html', '/js/homepage-preflight-v2.js?v=1');

console.log('canonical scan, report and homepage trust consistency contract verified');
