'use strict';
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const cases = fs.readFileSync(path.join(root, 'internal', 'handlers', 'public_dossier_cases_v2.go'), 'utf8');
const portable = fs.readFileSync(path.join(root, 'internal', 'handlers', 'public_dossier_registry_drive.go'), 'utf8');
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
const buildStart = cases.indexOf('func buildPublicDossierCaseV2');
if (handlerStart < 0 || loaderStart <= handlerStart || buildStart <= loaderStart) throw new Error('canonical public case handler boundary missing');
const handler = cases.slice(handlerStart, loaderStart);
const loader = cases.slice(loaderStart, buildStart);
requireText(handler, 'w.Header().Set("Cache-Control", "no-store")', 'revocable discovery cache policy');
requireText(handler, 'loaded, err := h.loadPublicDossierCasesV2(r, limit)', 'canonical verified registry loader');
forbid(handler, /stale-while-revalidate|max-age\s*=\s*[1-9]/i, 'stale publication discovery cache');

requireText(loader, 'db := h.DB', 'revocation-critical primary database read');
requireText(loader, 'Publication visibility is revocable security state.', 'primary read security rationale');
forbid(loader, /h\.DBRead/, 'potentially lagging read replica in revocation-critical registry');
requireText(loader, "WHERE p.status='public'", 'current publication visibility gate');
requireText(loader, 'verifyPublicationLedgerReadback(', 'current publication ledger verification');
requireText(loader, 'verifyStoredDossierBundle(canonical, caseRef, storedHash.String)', 'current immutable dossier verification');

requireText(portable, 'func (h *Handler) PublicDossierCasesPortable', 'portable public registry handler');
requireText(portable, 'h.loadPublicDossierCasesV2(r, limit)', 'primary database remains first registry source');
requireText(portable, 'loadPublicDossierRegistrySnapshotFromDrive(r, limit)', 'Drive fallback loader');
requireText(portable, 'drive.GetLatestJSONByName(r.Context(), publicCaseRegistryDriveObjectName)', 'Drive snapshot lookup');
requireText(portable, 'parsePublicDossierRegistrySnapshot(payload, limit)', 'Drive snapshot semantic validation');
requireText(portable, 'item.BundleHash', 'immutable bundle hash gate');
requireText(portable, 'registry_object_sha256', 'Drive object checksum provenance');
requireText(portable, 'Cache-Control", "no-store', 'portable no-store policy');
forbid(portable, /stale-while-revalidate|max-age\s*=\s*[1-9]/i, 'stale Drive publication discovery cache');

requireText(routes, 'mux.HandleFunc("/api/public/cases", method(http.MethodGet, h.PublicDossierCasesPortable))', 'portable production registry route');
requireText(routes, 'mux.HandleFunc("/api/owner/dossier/public-registry/sync", requiresDB(h, ownerOnly(h, method(http.MethodPost, h.OwnerPublicDossierRegistrySync))))', 'owner-only registry snapshot sync route');
requireText(routes, 'mux.HandleFunc("/api/public/soc/feed", requiresDB(h, method(http.MethodGet, h.PublicRadarLiveFeed)))', 'independent live radar route');
forbid(routes, /PublicSOCFeed|PublicDossierCases\)\)/, 'legacy publication discovery handler on production route');

// Live radar remains independent from owner-publication discovery.
requireText(live, 'this endpoint does not require an owner publication', 'live radar publication boundary');
requireText(live, 'buildPublicRadarLiveEvents(items, now)', 'live radar signed verdict projection');
requireText(legacy, 'func (h *Handler) PublicSOCFeed', 'legacy SOC code remains identifiable but unrouted');

// Browser requests bypass HTTP cache; server-side no-store closes the same stale
// visibility window for DB and Drive-backed registry reads.
requireText(browser, "fetch(endpoint, { cache: 'no-store'", 'browser no-store discovery fetch');

console.log('public discovery revocation v1 contract: ok');
