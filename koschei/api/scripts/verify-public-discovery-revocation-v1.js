'use strict';
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const cases = fs.readFileSync(path.join(root, 'internal', 'handlers', 'public_dossier_cases_v2.go'), 'utf8');
const routes = fs.readFileSync(path.join(root, 'internal', 'http', 'dossier_routes.go'), 'utf8');
const live = fs.readFileSync(path.join(root, 'internal', 'handlers', 'public_radar_live.go'), 'utf8');
const legacy = fs.readFileSync(path.join(root, 'internal', 'handlers', 'public_dossier_cases.go'), 'utf8');
const browser = fs.readFileSync(path.join(root, 'public', 'js', 'public-soc.js'), 'utf8');

function requireText(source, needle, label) {
  if (!source.includes(needle)) throw new Error(`${label}: missing ${needle}`);
}
function forbid(source, pattern, label) {
  if (pattern.test(source)) throw new Error(`${label}: forbidden pattern ${pattern}`);
}

const handlerStart = cases.indexOf('func (h *Handler) PublicDossierCasesV2');
const loaderStart = cases.indexOf('func (h *Handler) loadPublicDossierCasesV2');
if (handlerStart < 0 || loaderStart <= handlerStart) throw new Error('canonical public case handler boundary missing');
const handler = cases.slice(handlerStart, loaderStart);
requireText(handler, 'w.Header().Set("Cache-Control", "no-store")', 'revocable discovery cache policy');
requireText(handler, 'loaded, err := h.loadPublicDossierCasesV2(r, limit)', 'canonical verified registry loader');
if (handler.indexOf('w.Header().Set("Cache-Control", "no-store")') > handler.indexOf('h.loadPublicDossierCasesV2')) {
  throw new Error('revocable discovery cache policy must be set before database loading/error response');
}
forbid(handler, /stale-while-revalidate|max-age\s*=\s*[1-9]/i, 'stale publication discovery cache');

requireText(routes, 'mux.HandleFunc("/api/public/cases", requiresDB(h, method(http.MethodGet, h.PublicDossierCasesV2)))', 'production canonical registry route');
requireText(routes, 'mux.HandleFunc("/api/public/soc/feed", requiresDB(h, method(http.MethodGet, h.PublicRadarLiveFeed)))', 'independent live radar route');
forbid(routes, /PublicSOCFeed|PublicDossierCases\)\)/, 'legacy publication discovery handler on production route');

// Live radar is deliberately not owner-publication discovery. Keep its separate
// signed-verdict contract instead of accidentally coupling it to dossier hide.
requireText(live, 'this endpoint does not require an owner publication', 'live radar publication boundary');
requireText(live, 'buildPublicRadarLiveEvents(items, now)', 'live radar signed verdict projection');
requireText(legacy, 'func (h *Handler) PublicSOCFeed', 'legacy SOC code remains identifiable but unrouted');

// Browser requests already bypass the HTTP cache. Server-side no-store closes
// the same stale visibility window for CDNs, proxies and non-browser clients.
requireText(browser, "fetch(endpoint, { cache: 'no-store'", 'browser no-store discovery fetch');

console.log('public discovery revocation v1 contract: ok');
