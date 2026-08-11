'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const manifestPath=path.join(root,'public','security-ecosystem.json');
const launches=fs.readFileSync(path.join(root,'public','launches.html'),'utf8');
const aliases=fs.readFileSync(path.join(root,'internal','http','static_aliases.go'),'utf8');
const manifest=JSON.parse(fs.readFileSync(manifestPath,'utf8'));

function requireValue(condition,label){if(!condition)throw new Error(label);}
function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}

requireValue(manifest.ok===true,'manifest must remain ok');
requireValue(manifest.product==='Koschei ARVIS','product identity changed');
requireValue(manifest.version==='security-ecosystem-v6-canonical-scan-boundary','manifest version must be v6 canonical scan boundary');
requireValue(manifest.surface==='Security Evidence Ecosystem','canonical surface label missing');
requireValue(manifest.ecosystem?.runtime_integration_state==='incubation_only','runtime integration boundary changed');
requireValue(manifest.ecosystem?.official_asset?.identity_only===true,'KOSCH must remain identity/access only');
requireValue(manifest.incubation_policy?.sentinel_runtime_integrated===false,'Sentinel runtime boundary changed');
requireValue(manifest.incubation_policy?.language_runtime_integrated===false,'language runtime boundary changed');
requireValue(manifest.incubation_policy?.sentinel_verdict_authority===false,'Sentinel must not gain verdict authority');
requireValue(manifest.incubation_policy?.future_integration_requires_explicit_owner_approval===true,'future integration approval boundary changed');
requireValue(manifest.provider_policy?.missing_provider_data==='unavailable_or_withheld_not_fabricated','missing-provider fail-closed policy changed');
requireValue(Array.isArray(manifest.immutable_rules)&&manifest.immutable_rules.includes('No evidence, no claim'),'no-evidence/no-claim rule missing');
requireValue(manifest.access_model?.premium?.includes('deep scan'),'premium canonical Deep Scan capability missing');
requireValue(!manifest.access_model?.premium?.includes('security radar'),'legacy Security Radar capability must not be advertised as canonical');
const surfaces=Array.isArray(manifest.customer_surfaces)?manifest.customer_surfaces:[];
requireValue(surfaces.includes('/scan?mode=deep'),'canonical Deep Scan customer surface missing');
requireValue(surfaces.includes('/kosch'),'canonical KOSCH customer surface missing');
requireValue(!surfaces.includes('/security-radar'),'legacy security-radar must not be a canonical customer surface');
requireValue(!surfaces.includes('/kosch-access'),'legacy KOSCH alias must not be a canonical customer surface');

requireText(launches,'content="0;url=/scan?mode=deep"','launches canonical redirect');
requireText(launches,'href="/scan?mode=deep"','launches canonical action');
requireText(launches,"location.replace('/scan?mode=deep')",'launches JavaScript redirect');
if(launches.includes('/security-radar'))throw new Error('launches must not send users to legacy security-radar');

requireText(aliases,'[]string{"/security-radar", "/security-radar/", "/security-radar.html"}','legacy inbound radar aliases');
requireText(aliases,'registerScanModeRedirect(mux, route, "deep")','legacy radar deep-mode preservation');
requireText(aliases,'http.StatusPermanentRedirect','legacy alias permanent redirect contract');
console.log('canonical product contract v6: ok');
