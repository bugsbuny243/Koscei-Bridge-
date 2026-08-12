'use strict';
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const direct = fs.readFileSync(path.join(root, 'internal', 'handlers', 'public_exposure_authorization.go'), 'utf8');
const dossier = fs.readFileSync(path.join(root, 'internal', 'handlers', 'dossier_page.go'), 'utf8');
const readable = fs.readFileSync(path.join(root, 'internal', 'handlers', 'public_case_operational_v2.go'), 'utf8');
const ledger = fs.readFileSync(path.join(root, 'internal', 'handlers', 'publication_ledger_readback.go'), 'utf8');
const linkage = fs.readFileSync(path.join(root, 'migrations', '099_dossier_publication_transition_linkage.sql'), 'utf8');

function requireText(source, needle, label) {
  if (!source.includes(needle)) throw new Error(`${label}: missing ${needle}`);
}
function forbid(source, pattern, label) {
  if (pattern.test(source)) throw new Error(`${label}: forbidden pattern ${pattern}`);
}

requireText(direct, 'func loadPublicExposureRecord(ctx context.Context, db *sql.DB, caseRef string) (publicExposureRecord, error)', 'shared direct exposure loader');
requireText(direct, 'SELECT e.canonical_bundle,e.bundle_hash,', 'single snapshot immutable export');
requireText(direct, 'p.transition_id::text', 'current publication transition readback');
requireText(direct, 'pe.transition_id::text,pe.case_ref,pe.actor,pe.action', 'immutable event transition readback');
requireText(direct, 'JOIN dossier_exports e ON e.case_ref=p.case_ref', 'immutable export join');
requireText(direct, 'LEFT JOIN dossier_publication_events pe ON pe.transition_id=p.transition_id', 'ledger event join');
requireText(direct, "WHERE p.case_ref=$1 AND p.status='public'", 'current public authorization gate');
requireText(direct, 'verifyPublicationLedgerReadback(', 'ledger verifier');
requireText(direct, 'verifyStoredDossierBundle(canonical, caseRef, storedHash)', 'bundle verifier');
requireText(direct, 'fmt.Errorf("%w: publication ledger mismatch", errPublicExposureNotAuthorized)', 'ledger mismatch fail closed');
requireText(direct, 'publicExposureNotAuthorized(err error) bool', 'authorization error classifier');
requireText(direct, 'publicExposureIntegrityFailed(err error) bool', 'integrity error classifier');
requireText(direct, 'w.Header().Set("Cache-Control", "public, max-age=0, must-revalidate")', 'revocable cache authorization');
requireText(direct, 'w.Header().Set("X-Koschei-Publication-Ledger", record.LedgerStatus)', 'safe ledger provenance');
requireText(direct, 'w.Header().Set("X-Koschei-Published-By", record.PublishedBy)', 'safe publisher provenance');
forbid(direct, /X-Koschei-Transition-ID|X-Transition-ID/i, 'transition identifier exposure');
forbid(direct, /max-age=31536000|stale-while-revalidate/, 'stale authorization cache');

for (const [source, label] of [[dossier, 'raw dossier'], [readable, 'readable case']]) {
  requireText(source, 'loadPublicExposureRecord(r.Context(), h.DB, caseRef)', `${label} uses shared loader`);
  requireText(source, 'publicExposureNotAuthorized(err)', `${label} hides unauthorized records`);
  requireText(source, 'applyPublicExposureHeaders(w, record)', `${label} uses revocable exposure headers`);
  forbid(source, /SELECT\s+e\.canonical_bundle/si, `${label} duplicate authorization SQL`);
  forbid(source, /JOIN\s+dossier_publications/si, `${label} bypass publication query`);
  forbid(source, /max-age=31536000|stale-while-revalidate=300/, `${label} stale visibility authorization`);
}
requireText(dossier, 'w.Header().Set("ETag", `"`+bundle.BundleHash+`"`)', 'immutable dossier content ETag');
requireText(readable, 'publicExposureIntegrityFailed(err)', 'readable case preserves integrity conflict classification');

requireText(ledger, 'publicationLedgerLegacyUnlinked = "legacy_unlinked"', 'legacy publication lineage allowed without fabricated proof');
requireText(ledger, 'publicationLedgerVerified       = "verified"', 'linked publication lineage state');
requireText(linkage, 'NEW.transition_id := gen_random_uuid();', 'database-owned transition identity');
requireText(linkage, 'DEFERRABLE INITIALLY DEFERRED', 'state-event write linkage at commit');

console.log('public exposure authorization v1 contract: ok');
