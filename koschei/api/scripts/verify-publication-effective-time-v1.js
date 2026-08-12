'use strict';
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const migration = fs.readFileSync(path.join(root, 'migrations', '100_dossier_publication_effective_time.sql'), 'utf8');
const resolver = fs.readFileSync(path.join(root, 'internal', 'handlers', 'publication_effective_time.go'), 'utf8');
const registry = fs.readFileSync(path.join(root, 'internal', 'handlers', 'public_dossier_cases_v2.go'), 'utf8');
const exposure = fs.readFileSync(path.join(root, 'internal', 'handlers', 'public_exposure_authorization.go'), 'utf8');
const browser = fs.readFileSync(path.join(root, 'public', 'js', 'public-soc.js'), 'utf8');
const page = fs.readFileSync(path.join(root, 'public', 'cases.html'), 'utf8');

function requireText(source, needle, label) {
  if (!source.includes(needle)) throw new Error(`${label}: missing ${needle}`);
}
function requirePattern(source, pattern, label) {
  if (!pattern.test(source)) throw new Error(`${label}: missing pattern ${pattern}`);
}
function forbid(source, pattern, label) {
  if (pattern.test(source)) throw new Error(`${label}: forbidden pattern ${pattern}`);
}

requireText(migration, 'CREATE OR REPLACE FUNCTION prepare_dossier_publication_effective_time()', 'publication effective-time trigger function');
requireText(migration, "IF TG_OP = 'INSERT' THEN", 'insert time ownership');
requireText(migration, "IF OLD.status IS DISTINCT FROM NEW.status AND NEW.status = 'public' THEN", 'republish interval reset');
requireText(migration, 'NEW.published_at := now();', 'database-owned published_at');
requireText(migration, 'NEW.published_at := OLD.published_at;', 'public update/hide interval preservation');
requireText(migration, 'CREATE TRIGGER dossier_publications_effective_time_contract', 'publication time trigger');
requireText(migration, 'BEFORE INSERT OR UPDATE ON dossier_publications', 'publication time trigger timing');
requireText(migration, 'CREATE OR REPLACE FUNCTION prepare_dossier_publication_event_time_contract()', 'event time trigger function');
requireText(migration, 'NEW.created_at := now();', 'database-owned immutable event timestamp');
requireText(migration, "'publication_time_contract', 'db-owned-v1'", 'database-owned time marker');
requireText(migration, 'CREATE TRIGGER dossier_publication_events_time_contract', 'event time trigger');
requireText(migration, 'BEFORE INSERT ON dossier_publication_events', 'event time trigger timing');

requireText(resolver, 'publicationTimeContractDBOwnedV1 = "db-owned-v1"', 'time contract identity');
requireText(resolver, 'publicationTimeDBVerified', 'db-verified time state');
requireText(resolver, 'publicationTimeLegacyEvent', 'legacy event time state');
requireText(resolver, 'publicationTimeLegacyColumn', 'legacy column time state');
requireText(resolver, 'if !readback.PublishEventTransitionID.Valid', 'db-owned transition requirement');
requireText(resolver, 'storedPublishedAt.Time.Equal(readback.PublishEventAt.Time)', 'state/event timestamp equality');
requireText(resolver, 'case "":', 'legacy event handling');
requireText(resolver, 'unsupported publication time contract', 'unknown contract fail closed');
forbid(resolver, /time\.Now\s*\(/, 'resolver wall-clock dependency');

for (const [source, label] of [[registry, 'registry'], [exposure, 'direct exposure']]) {
  requireText(source, 'LEFT JOIN LATERAL (', `${label} latest publish event lookup`);
  requireText(source, "WHERE pte.case_ref=p.case_ref AND pte.action='publish'", `${label} publish action time source`);
  requireText(source, "pte.publication_state->>'publication_time_contract'", `${label} time contract readback`);
  requireText(source, 'resolvePublicationEffectiveTime(publishedAt, timeReadback)', `${label} effective time resolver`);
}
requireText(registry, 'PublicationTimeStatus   string         `json:"publication_time_status"`', 'public time provenance field');
requireText(registry, 'COALESCE(pt.created_at,p.published_at) DESC', 'registry order uses effective public time');
requirePattern(registry, /"publication_effective_time_event_backed":\s+true/, 'registry effective-time policy');
requirePattern(registry, /"db_owned_publication_time_v1":\s+true/, 'registry db-owned time policy');
requireText(registry, 'public dossier withheld from registry: publication effective time failure', 'registry time mismatch fail closed');
forbid(registry, /json:\"publish_event_transition_id|json:\"transition_id/, 'internal time/transition identifier exposure');

requireText(exposure, 'PublicationTimeStatus string', 'direct time provenance');
requireText(exposure, 'w.Header().Set("X-Koschei-Publication-Time", record.PublicationTimeStatus)', 'direct time provenance header');
requireText(exposure, 'fmt.Errorf("%w: publication effective time mismatch", errPublicExposureIntegrity)', 'direct time mismatch integrity failure');

requireText(browser, "const ALLOWED_PUBLICATION_TIME_STATES = new Set(['db_verified', 'legacy_event', 'legacy_column'])", 'browser time provenance allowlist');
requireText(browser, 'policy.publication_effective_time_event_backed !== true', 'browser effective-time policy gate');
requireText(browser, 'policy.db_owned_publication_time_v1 !== true', 'browser db-owned time policy gate');
requireText(browser, 'publicationTimeLabel(item)', 'browser time provenance label');
requireText(browser, 'Public since ${safeDate(item.published_at)}', 'browser current interval label');
requireText(page, '“Public since” means the start of the current public exposure interval', 'page interval semantics');
requireText(page, 'Hide followed by republish starts a new public exposure interval', 'page republish semantics');
requireText(page, '/js/public-soc.js?v=6', 'effective-time-aware asset version');

console.log('publication effective time v1 contract: ok');
