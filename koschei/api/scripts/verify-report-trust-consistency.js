const fs = require('fs');
function need(file, text) {
  const body = fs.readFileSync(file, 'utf8');
  if (!body.includes(text)) throw new Error(`${file} missing ${text}`);
}
need('public/js/public-solana-scan.js', 'Pending evidence arms and monitoring windows');
need('public/js/public-solana-scan.js', 'QUICK PREFLIGHT');
need('public/js/public-solana-scan.js', 'Missing evidence = no safety decision');
need('public/js/public-solana-scan.js', '/api/public/transaction-simulate');
need('public/js/lp-control-evidence-card.js', 'Havuz hareket geçmişi bu taramada doğrulanamadı');
need('public/index.html', 'signed_verdicts_total');
need('public/index.html', 'EVIDENCE BOUNDARY');
need('public/index.html', 'Missing evidence is never converted into safety.');
need('public/scan.html', 'One scan page · four evidence modes');
need('public/scan.html', 'Missing evidence never becomes safety.');
console.log('canonical scan and report trust consistency contract verified');
