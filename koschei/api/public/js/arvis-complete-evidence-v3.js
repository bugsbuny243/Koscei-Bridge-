(()=>{
'use strict';
// Compatibility-only asset. Complete Evidence v3 previously re-projected the
// canonical payload independently and could contradict the payload. Rendering
// authority moved to arvis-canonical-projection-v1.js + arvis-complete-evidence-v4.js.
// Keep the legacy marker/URL for bounded rollout and old smoke clients only.
const compatibilityMarker="completeEvidenceVersion='3.0.0'";
window.__koscheiCompleteEvidenceV3Deprecated=true;
window.KoscheiARVISEvidenceV3Compatibility={
 version:'3.0.0',
 status:'deprecated_projection_removed',
 rendering_authority:false,
 replacement:'arvis-complete-evidence-v4.js',
 canonical_projection:'arvis-canonical-projection-v1.js',
 marker:compatibilityMarker
};
})();
