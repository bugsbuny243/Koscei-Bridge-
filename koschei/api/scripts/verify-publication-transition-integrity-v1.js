'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const integrity=fs.readFileSync(path.join(root,'internal','handlers','dossier_integrity.go'),'utf8');
const owner=fs.readFileSync(path.join(root,'internal','handlers','public_dossier_cases.go'),'utf8');
const worker=fs.readFileSync(path.join(root,'internal','handlers','autopublish_worker.go'),'utf8');
const policy=fs.readFileSync(path.join(root,'internal','handlers','autopublish_policy.go'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden pattern ${pattern}`);}

requireText(integrity,'len(canonical) == 0 || caseRef == "" || storedHash == ""','stored hash required by shared verifier');
requireText(integrity,'if storedHash != computed','stored hash exact equality');

const ownerStart=owner.indexOf('func (h *Handler) OwnerDossierPublication');
const loadStart=owner.indexOf('func (h *Handler) loadPublicDossierCases');
if(ownerStart<0||loadStart<=ownerStart)throw new Error('owner publication function boundary missing');
const ownerFn=owner.slice(ownerStart,loadStart);
requireText(ownerFn,'tx, err := h.DB.BeginTx(r.Context(), nil)','owner publication transaction');
requireText(ownerFn,'if input.Status == "public" {','public-only integrity branch');
requireText(ownerFn,'SELECT canonical_bundle,bundle_hash','owner canonical + stored hash source');
requireText(ownerFn,'FOR SHARE','owner export lock');
requireText(ownerFn,'verifyStoredDossierBundle(canonical, input.CaseRef, storedHash)','owner exact bundle verification');
requireText(ownerFn,'"Immutable dossier integrity verification failed"','owner integrity failure response');
requireText(ownerFn,'} else if !previousExists {','depublication/new draft branch remains separate from public integrity gate');
requireText(ownerFn,'SELECT 1 FROM dossier_exports WHERE case_ref=$1','non-public existence-only check');
requireText(ownerFn,"public_title=CASE WHEN EXCLUDED.public_title<>'' THEN EXCLUDED.public_title ELSE dossier_publications.public_title END",'hide/draft preserves existing title when omitted');
requireText(ownerFn,"public_summary=CASE WHEN EXCLUDED.public_summary<>'' THEN EXCLUDED.public_summary ELSE dossier_publications.public_summary END",'hide/draft preserves existing summary when omitted');
requireText(ownerFn,'"public_transition_integrity_verified": integrityVerified','owner audit integrity marker');
requireText(ownerFn,'if integrityVerified {','owner bundle hash audit only after verification');
requireText(ownerFn,'if input.Status == "public" {','public response projection only after verified transition');
forbid(ownerFn,/json\.Unmarshal\s*\(/,'owner weak parse-only publication check');

const legacyLoad=owner.slice(loadStart,owner.indexOf('func buildPublicDossierCase'));
requireText(legacyLoad,'e.canonical_bundle,e.bundle_hash','legacy public projection stored-hash source');
requireText(legacyLoad,'verifyStoredDossierBundle(canonical, caseRef, storedHash)','legacy public projection exact verifier');
forbid(legacyLoad,/json\.Unmarshal\s*\(/,'legacy public projection weak parse-only check');

requireText(worker,'StoredHash string','autopublish candidate stored hash');
requireText(worker,'SELECT e.case_ref, e.canonical_bundle, e.bundle_hash','autopublish candidate immutable source');
requireText(worker,'verifyStoredDossierBundle(candidate.Canonical, candidate.CaseRef, candidate.StoredHash)','autopublish pre-policy integrity check');
requireText(worker,'Reasons:       []string{"canonical_bundle_integrity_failed"}','autopublish integrity failure reason');
requireText(worker,'SELECT pg_advisory_xact_lock(hashtext($1))','autopublish per-case transaction serialization');
requireText(worker,'if decision.Publish {','autopublish publication branch');
requireText(worker,'verifyAutopublishPublicationBundle(ctx, tx, caseRef, bundleHash)','autopublish TOCTOU re-verification');
requireText(worker,'SELECT canonical_bundle,bundle_hash','autopublish transaction immutable source');
requireText(worker,'FOR SHARE','autopublish export lock');
requireText(worker,'bundle.BundleHash != strings.TrimSpace(expectedHash)','autopublish decision-to-export hash binding');
requireText(worker,'"integrity_verified": true','autopublish audit integrity marker');
requireText(worker,'"bundle_hash":        bundleHash','autopublish audit bundle hash');
requireText(worker,'VALUES ($1,\'publish\',$2,$3::jsonb)','autopublish publication event');
requireText(worker,'autopublishPublishedBy   = "koschei-autopublish/v1"','autopublish publisher identity');
requireText(worker,'WHERE p.case_ref IS NULL','autopublish does not override owner publication state');
forbid(worker,/json\.Unmarshal\(candidate\.Canonical/,'autopublish weak parse-only candidate check');

requireText(policy,'// Evidence-first publication policy. evaluateAutopublish is intentionally pure:','pure policy declaration');
const evalStart=policy.indexOf('func evaluateAutopublish');
const sortedStart=policy.indexOf('func sortedAutopublishReasons');
if(evalStart<0||sortedStart<=evalStart)throw new Error('autopublish pure policy boundary missing');
const evalFn=policy.slice(evalStart,sortedStart);
forbid(evalFn,/\b(?:sql\.|DB\.|Query|Exec|time\.Now|os\.)/,'autopublish policy I/O or clock access');

console.log('publication transition integrity v1 contract: ok');
