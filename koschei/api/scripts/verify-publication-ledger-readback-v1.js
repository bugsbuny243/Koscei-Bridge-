'use strict';
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const projection = fs.readFileSync(path.join(root, 'internal', 'handlers', 'public_dossier_cases_v2.go'), 'utf8');
const verifier = fs.readFileSync(path.join(root, 'internal', 'handlers', 'publication_ledger_readback.go'), 'utf8');
const migration = fs.readFileSync(path.join(root, 'migrations', '099_dossier_publication_transition_linkage.sql'), 'utf8');

function requireText(source, needle, label) {
  if (!source.includes(needle)) throw new Error(`${label}: missing ${needle}`);
}
function forbid(source, pattern, label) {
  if (pattern.test(source)) throw new Error(`${label}: forbidden pattern ${pattern}`);
}

requireText(verifier, 'publicationLedgerVerified       = "verified"', 'verified lineage state');
requireText(verifier, 'publicationLedgerLegacyUnlinked = "legacy_unlinked"', 'legacy lineage state');
requireText(verifier, 'if !readback.TransitionID.Valid || transitionID == "" {', 'legacy transition detection');
requireText(verifier, 'eventTransitionID != transitionID', 'transition identity equality');
requireText(verifier, 'publication ledger actor does not match publisher', 'actor publisher verification');
for (const field of ['status', 'published_by', 'public_title', 'public_summary', 'redaction_profile', 'featured']) {
  requireText(verifier, `name: "${field}"`, `ledger snapshot ${field}`);
}
requireText(verifier, 'case "publish", "hide", "feature", "unfeature", "update", "draft":', 'allowed action vocabulary');

requireText(projection, 'PublishedBy             string         `json:"published_by"`', 'public publisher provenance');
requireText(projection, 'PublicationLedgerStatus string         `json:"publication_ledger_status"`', 'public lineage status');
requireText(projection, 'PublicationAction       string         `json:"publication_action,omitempty"`', 'public action provenance');
requireText(projection, 'LEFT JOIN dossier_publication_events pe ON pe.transition_id=p.transition_id', 'ledger event readback join');
requireText(projection, 'p.transition_id::text', 'internal current transition readback');
requireText(projection, 'pe.transition_id::text', 'internal event transition readback');
requireText(projection, 'verifyPublicationLedgerReadback(', 'deterministic readback verifier call');
requireText(projection, 'loaded.InvalidLedgerPublications++', 'linked mismatch accounting');
requireText(projection, 'loaded.LedgerVerifiedPublications++', 'verified linkage accounting');
requireText(projection, 'loaded.LegacyUnlinkedPublications++', 'legacy linkage accounting');
requireText(projection, 'public dossier withheld from registry: publication ledger readback failure', 'mismatch fail closed');
requireText(projection, '"publication_ledger_complete":  ledgerComplete', 'ledger completeness envelope');
requireText(projection, '"ledger_verified_publications": loaded.LedgerVerifiedPublications', 'verified count envelope');
requireText(projection, '"legacy_unlinked_publications": loaded.LegacyUnlinkedPublications', 'legacy count envelope');
requireText(projection, '"invalid_ledger_publications":  loaded.InvalidLedgerPublications', 'invalid ledger count envelope');
requireText(projection, '"publication_ledger_readback_verified":    true', 'ledger readback policy');
requireText(projection, '"legacy_publication_lineage_declared":      true', 'legacy disclosure policy');
requireText(projection, '"transition_identifiers_public":            false', 'transition privacy policy');

// Transition UUIDs are an internal join key, not a public identifier.
forbid(projection, /json:\"transition_id/, 'transition id JSON exposure');
forbid(projection, /TransitionID\s+string\s+`json:/, 'transition id public field');

// Wave 28 remains the source of the write-side invariant used by readback.
requireText(migration, 'DEFERRABLE INITIALLY DEFERRED', 'write-side commit-time linkage');
requireText(migration, 'NEW.transition_id := gen_random_uuid();', 'database-owned transition ids');
requireText(migration, 'NEW.transition_id := publication.transition_id;', 'database-owned event linkage');

console.log('publication ledger readback v1 contract: ok');
