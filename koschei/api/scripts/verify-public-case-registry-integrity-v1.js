'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const integrity=fs.readFileSync(path.join(root,'internal','handlers','dossier_integrity.go'),'utf8');
const casesGo=fs.readFileSync(path.join(root,'internal','handlers','public_dossier_cases_v2.go'),'utf8');
const dossierPage=fs.readFileSync(path.join(root,'internal','handlers','dossier_page.go'),'utf8');
const readableCase=fs.readFileSync(path.join(root,'internal','handlers','public_case_operational_v2.go'),'utf8');
const casesHTML=fs.readFileSync(path.join(root,'public','cases.html'),'utf8');
const casesJS=fs.readFileSync(path.join(root,'public','js','public-soc.js'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden pattern ${pattern}`);}

requireText(integrity,'func verifyStoredDossierBundle(canonical []byte, caseRef, storedHash string) (dossierBundle, error)','shared dossier integrity verifier');
requireText(integrity,'publicDossierCaseRefPattern.MatchString(caseRef)','canonical case-ref format gate');
requireText(integrity,'decoder.UseNumber()','large JSON integer preservation');
requireText(integrity,'json.Marshal(bundle)','canonical byte re-encoding');
requireText(integrity,'bytes.Equal(canonical, reencoded)','exact canonical byte equality');
requireText(integrity,'json.Marshal(bundle.dossierBody)','bundle hash scope');
requireText(integrity,'computed := dossierSHA256(bodyBytes)','body SHA-256 recomputation');
requireText(integrity,'bundleHash != computed','embedded bundle-hash equality');
requireText(integrity,'storedHash != "" && storedHash != computed','database bundle-hash equality');

requireText(casesGo,'const publicCaseRegistrySchemaVersion = "koschei-public-case-registry-v1"','versioned public registry envelope');
requireText(casesGo,'LEFT JOIN dossier_exports e ON e.case_ref=p.case_ref','missing export remains visible to integrity accounting');
requireText(casesGo,'COUNT(*) OVER()','total public publication accounting');
requireText(casesGo,'e.canonical_bundle,e.bundle_hash','canonical bytes and stored hash source');
requireText(casesGo,'verifyStoredDossierBundle(canonical, caseRef, storedHash.String)','public case immutable verification');
requireText(casesGo,'loaded.InvalidPublications++','invalid publication accounting');
requireText(casesGo,'loaded.UninspectedPublications = loaded.TotalPublications - loaded.InspectedPublications','truncated registry accounting');
requireText(casesGo,'loaded.InvalidPublications == 0 && loaded.UninspectedPublications == 0','registry completeness rule');
requireText(casesGo,'registryStatus = "degraded"','integrity-failure state');
requireText(casesGo,'registryStatus = "partial"','inspection-limit state');
for(const field of ['total_publications','inspected_publications','invalid_publications','uninspected_publications'])requireText(casesGo,`"${field}"`,`registry envelope ${field}`);
requireText(casesGo,'"canonical_bundle_hash_reverified"','public hash-verification policy');
requireText(casesGo,'"partial_registry_declared"','partial registry policy');

requireText(dossierPage,"JOIN dossier_publications p ON p.case_ref=e.case_ref AND p.status='public'",'raw dossier explicit-public gate');
requireText(dossierPage,'SELECT e.canonical_bundle,e.bundle_hash','raw dossier canonical/hash source');
requireText(dossierPage,'verifyStoredDossierBundle(raw, caseRef, storedHash)','raw dossier immutable verification');
forbid(dossierPage,/json\.Unmarshal\s*\(/,'raw dossier weak parse-only integrity check');

requireText(readableCase,"WHERE e.case_ref=$1 AND p.status='public'",'readable case explicit-public gate');
requireText(readableCase,'SELECT e.canonical_bundle,e.bundle_hash','readable case canonical/hash source');
requireText(readableCase,'verifyStoredDossierBundle(canonical, caseRef, storedHash)','readable case immutable verification');
forbid(readableCase,/json\.Unmarshal\s*\(/,'readable case weak parse-only integrity check');

requireText(casesHTML,'canonical bytes, case reference, embedded bundle hash, and stored bundle hash are reverified','public integrity explanation');
requireText(casesHTML,'Aggregate registry totals are shown only when every public publication in the response has been inspected','public aggregate boundary');
requireText(casesHTML,'fails canonical bundle or hash verification','public failure boundary');
requireText(casesHTML,'/js/public-soc.js?v=4','case registry controller version');

requireText(casesJS,"const REGISTRY_SCHEMA = 'koschei-public-case-registry-v1'",'frontend registry schema');
requireText(casesJS,"const CASE_REF_PATTERN = /^KD1-[a-z2-7]{32}$/",'frontend case-ref gate');
requireText(casesJS,"const BUNDLE_HASH_PATTERN = /^sha256:[0-9a-f]{64}$/",'frontend bundle-hash gate');
requireText(casesJS,"const ALLOWED_GRADES = new Set(['A', 'B', 'C', 'D', 'F', 'WITHHOLD'])",'frontend grade allowlist');
requireText(casesJS,"if (grade) return ALLOWED_GRADES.has(grade) ? grade : 'UNAVAILABLE'",'unknown grade is unavailable');
requireText(casesJS,"return status === 'WITHHOLD' ? 'WITHHOLD' : 'UNAVAILABLE'",'WITHHOLD-only status fallback');
requireText(casesJS,'inspected !== count + invalid || total !== inspected + uninspected','registry count equations');
requireText(casesJS,"const expectedStatus = invalid > 0 ? 'degraded' : uninspected > 0 ? 'partial' : 'operational'",'registry status derivation');
requireText(casesJS,'payload.registry_complete !== expectedComplete','registry completeness validation');
requireText(casesJS,'policy.canonical_bundle_hash_reverified !== true','integrity policy validation');
requireText(casesJS,"if (!registryComplete) nodes.push(partialRegistryWarning())",'partial registry warning');
requireText(casesJS,"forEach(id => setText(id, 'UNAVAILABLE'))",'incomplete aggregate suppression');
requireText(casesJS,'raw.href = rawDossierURL(item)','local raw dossier URL derivation');
if(casesJS.includes("item.public_url ||"))throw new Error('cases js: API-controlled public_url must not drive href');
if(casesJS.includes("|| 'WITHHOLD'")||casesJS.includes("||\"WITHHOLD\""))throw new Error('cases js: missing verdict must not default to WITHHOLD');
forbid(casesJS,/Math\.random\s*\(/,'synthetic case evidence');
if(/\/api\/(?:auth|watchlist|v1\/unified\/reports)/.test(casesJS))throw new Error('cases js: public registry must not read account-private APIs');

console.log('public case registry integrity v1 contract: ok');
