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
reject('public/scan.html', 'data-scan-mode="quick"');
reject('public/scan.html', 'Professional+');

// Homepage trust contract. The current two-surface product keeps one public
// evidence-first landing page and one authenticated customer panel. Pin this
// verifier to security/product invariants rather than retired cinematic assets.
need('public/index.html', 'See the blind spot.');
need('public/index.html', 'missing evidence stays unknown');
need('public/index.html', 'Solana live production core');
need('public/index.html', 'Evidence first');
need('public/index.html', 'No custody · no private keys');
need('public/index.html', 'ARVIS is not a generic risk-score machine.');
need('public/index.html', 'never invented certainty');
need('public/index.html', 'Solana is the live core; additional chain adapters remain expansion work until their evidence paths are production-ready.');
need('public/index.html', 'STRUCTURE ONLY · NOT LIVE TELEMETRY');
need('public/index.html', 'NO FABRICATION');
need('public/index.html', 'Unknown stays unknown');
need('public/index.html', '/css/koschei-home.css?v=1');
reject('public/index.html', 'Ethereum</b><small>LIVE');
reject('public/index.html', 'TRON</b><small>LIVE');
reject('public/index.html', '100% secure');

console.log('Professional investigation, report and homepage trust consistency contract verified');
