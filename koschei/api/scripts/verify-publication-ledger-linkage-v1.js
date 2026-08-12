'use strict';
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const migration = fs.readFileSync(path.join(root, 'migrations', '099_dossier_publication_transition_linkage.sql'), 'utf8');
const baseMigration = fs.readFileSync(path.join(root, 'migrations', '083_public_dossier_publications.sql'), 'utf8');
const owner = fs.readFileSync(path.join(root, 'internal', 'handlers', 'public_dossier_cases.go'), 'utf8');
const worker = fs.readFileSync(path.join(root, 'internal', 'handlers', 'autopublish_worker.go'), 'utf8');

function requireText(source, needle, label) {
  if (!source.includes(needle)) throw new Error(`${label}: missing ${needle}`);
}
function forbid(source, pattern, label) {
  if (pattern.test(source)) throw new Error(`${label}: forbidden pattern ${pattern}`);
}

requireText(baseMigration, 'BEFORE UPDATE OR DELETE ON dossier_publication_events', 'immutable publication event ledger');
requireText(baseMigration, "RAISE EXCEPTION 'dossier publication audit events are immutable'", 'immutable event mutation rejection');

for (const table of ['dossier_publications', 'dossier_publication_events']) {
  requireText(migration, `ALTER TABLE ${table}\n    ADD COLUMN IF NOT EXISTS transition_id uuid;`, `${table} transition id`);
}
requireText(migration, 'dossier_publications_transition_unique_idx', 'current-state transition uniqueness');
requireText(migration, 'dossier_publication_events_transition_unique_idx', 'event transition uniqueness');
requireText(migration, "CHECK (published_by IN ('owner','koschei-autopublish/v1')) NOT VALID", 'publisher allowlist for new transitions');
requireText(migration, "CHECK (actor IN ('owner','autopublish')) NOT VALID", 'actor allowlist for new events');

requireText(migration, 'CREATE OR REPLACE FUNCTION prepare_dossier_publication_transition()', 'database transition preparation');
requireText(migration, 'NEW.transition_id := gen_random_uuid();', 'database-owned fresh transition id');
requireText(migration, 'BEFORE INSERT OR UPDATE ON dossier_publications', 'transition id generation trigger');

requireText(migration, 'CREATE OR REPLACE FUNCTION prepare_dossier_publication_event_link()', 'event linkage preparation');
requireText(migration, 'NEW.transition_id := publication.transition_id;', 'event transition binding');
requireText(migration, "WHEN 'owner' THEN 'owner'", 'owner publisher actor mapping');
requireText(migration, "WHEN 'koschei-autopublish/v1' THEN 'autopublish'", 'autopublish publisher actor mapping');
requireText(migration, "IF NEW.action = 'hidden' THEN", 'first hidden action normalization');
for (const field of ['status', 'featured', 'public_title', 'public_summary', 'redaction_profile', 'published_by']) {
  requireText(migration, `'${field}', publication.${field}`, `canonical event snapshot ${field}`);
}
requireText(migration, 'BEFORE INSERT ON dossier_publication_events', 'event linkage trigger');

requireText(migration, 'CREATE OR REPLACE FUNCTION enforce_dossier_publication_transition_event()', 'commit-time transition verifier');
requireText(migration, "IF TG_OP = 'UPDATE' AND NEW.transition_id IS NOT DISTINCT FROM OLD.transition_id THEN", 'fresh update transition enforcement');
requireText(migration, "ELSIF OLD.status IS DISTINCT FROM NEW.status THEN", 'status transition action derivation');
requireText(migration, "ELSIF OLD.featured IS DISTINCT FROM NEW.featured THEN", 'feature transition action derivation');
requireText(migration, 'AND e.action = expected_action', 'event action binding');
requireText(migration, 'AND e.publication_state->>\'public_summary\' = NEW.public_summary', 'event state snapshot binding');
requireText(migration, 'CREATE CONSTRAINT TRIGGER dossier_publications_transition_event_guard', 'constraint trigger');
requireText(migration, 'DEFERRABLE INITIALLY DEFERRED', 'commit-time deferred verification');
requireText(migration, "RAISE EXCEPTION 'dossier publication state is missing its matching immutable transition event'", 'orphan state rejection');

// The database owns linkage IDs. Application writers only own business intent
// and must continue to write state + immutable event in one transaction.
forbid(owner, /transition_id/i, 'owner must not own transition identifiers');
forbid(worker, /transition_id/i, 'autopublish must not own transition identifiers');
const ownerStart = owner.indexOf('func (h *Handler) OwnerDossierPublication');
const ownerEnd = owner.indexOf('func (h *Handler) loadPublicDossierCases');
if (ownerStart < 0 || ownerEnd <= ownerStart) throw new Error('owner publication function boundary missing');
const ownerFn = owner.slice(ownerStart, ownerEnd);
requireText(ownerFn, 'tx, err := h.DB.BeginTx(r.Context(), nil)', 'owner publication transaction');
requireText(ownerFn, 'INSERT INTO dossier_publications', 'owner state write');
requireText(ownerFn, 'INSERT INTO dossier_publication_events', 'owner audit write');
requireText(ownerFn, 'if err := tx.Commit(); err != nil', 'owner atomic commit');

const recordStart = worker.indexOf('func (w *autopublishWorker) record');
const verifyStart = worker.indexOf('func verifyAutopublishPublicationBundle');
if (recordStart < 0 || verifyStart <= recordStart) throw new Error('autopublish record function boundary missing');
const recordFn = worker.slice(recordStart, verifyStart);
requireText(recordFn, 'tx, err := w.DB.BeginTx(ctx, nil)', 'autopublish transaction');
requireText(recordFn, 'INSERT INTO dossier_publications', 'autopublish state write');
requireText(recordFn, 'INSERT INTO dossier_publication_events', 'autopublish audit write');
requireText(recordFn, 'if err := tx.Commit(); err != nil', 'autopublish atomic commit');

console.log('publication ledger linkage v1 contract: ok');
