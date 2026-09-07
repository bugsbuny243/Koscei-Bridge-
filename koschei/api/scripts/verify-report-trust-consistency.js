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

// Investigation/report evidence contract remains unchanged while the legacy
// investigation console remains available behind compatibility routes.
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

// The public product homepage is one clean surface and points customers to the
// single operational customer panel.
need('public/index.html', 'See the blind spot.');
need('public/index.html', 'missing evidence stays unknown');
need('public/index.html', 'Solana live production core');
need('public/index.html', 'Material conclusions stay traceable to evidence');
need('public/index.html', 'STRUCTURE ONLY · NOT LIVE TELEMETRY');
need('public/index.html', 'Customer Panel');
need('public/index.html', '/css/koschei-home.css?v=1');
reject('public/index.html', '/css/koschei.css?v=1');
reject('public/index.html', '/js/koschei-global-shell.js');
reject('public/index.html', '/js/koschei-home-universe-v2.js');
reject('public/index.html', '/js/homepage-preflight-v2.js');
reject('public/index.html', '/js/koschei-security-world.js');
reject('public/index.html', 'Ethereum</b><small>LIVE');
reject('public/index.html', 'TRON</b><small>LIVE');

// Exposure and feedback are no longer standalone product surfaces.
need('public/dashboard.html', 'id="exposureForm"');
need('public/dashboard.html', 'id="feedbackForm"');
need('public/js/koschei-dashboard.js', '/api/v1/radar/exposure?target=');
need('public/js/koschei-dashboard.js', '/api/analytics/event');
for (const retired of ['public/exposure-report.html','public/feedback.html','public/security-ecosystem.html','public/token-vesting.html']) {
  if (fs.existsSync(retired)) throw new Error(`retired standalone surface returned: ${retired}`);
}

const homepage = read('public/index.html');
if ((homepage.match(/<link rel="stylesheet"/g) || []).length !== 1) {
  throw new Error('public/index.html must load exactly one stylesheet');
}
const dashboard = read('public/dashboard.html');
if ((dashboard.match(/<link rel="stylesheet"/g) || []).length !== 1) {
  throw new Error('public/dashboard.html must load exactly one stylesheet');
}

console.log('Professional investigation/report trust and hardened two-surface contract verified');
