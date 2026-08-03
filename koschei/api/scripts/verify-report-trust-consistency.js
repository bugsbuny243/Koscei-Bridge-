const fs = require('fs');
function need(file, text) {
  const body = fs.readFileSync(file, 'utf8');
  if (!body.includes(text)) throw new Error(`${file} missing ${text}`);
}
need('public/js/public-solana-scan.js', 'Bekleyen kanıt kolları ve izleme pencereleri');
need('public/js/public-solana-scan.js', 'HIZLI ÖN KONTROL');
need('public/js/lp-control-evidence-card.js', 'Havuz hareket geçmişi bu taramada doğrulanamadı');
need('public/index.html', 'signed_verdicts_total');
need('public/index.html', 'EVIDENCE BOUNDARY');
need('public/index.html', 'Missing evidence is never converted into safety.');
need('public/safe-check.html', 'Holder and liquidity evidence were not evaluated in this result.');
need('public/safe-check.html', 'Missing evidence = no decision');
console.log('report trust consistency contract verified');
