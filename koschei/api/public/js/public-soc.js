(() => {
  'use strict';

  const statusNode = document.getElementById('soc-status');
  const updatedNode = document.getElementById('soc-updated');
  const contentNode = document.getElementById('case-grid');
  const searchNode = document.getElementById('case-search');
  const gradeNode = document.getElementById('case-grade');
  const visibleNode = document.getElementById('case-visible');
  const number = new Intl.NumberFormat('en-US');
  const date = new Intl.DateTimeFormat('en-US', { dateStyle: 'medium', timeStyle: 'medium' });
  const REQUEST_TIMEOUT_MS = 12000;
  const REGISTRY_SCHEMA = 'koschei-public-case-registry-v1';
  const CASE_REF_PATTERN = /^KD1-[a-z2-7]{32}$/;
  const BUNDLE_HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
  const ALLOWED_GRADES = new Set(['A', 'B', 'C', 'D', 'F', 'WITHHOLD']);
  const ALLOWED_LEDGER_STATES = new Set(['verified', 'legacy_unlinked']);
  const ALLOWED_PUBLISHERS = new Set(['owner', 'koschei-autopublish/v1']);
  const ALLOWED_PUBLICATION_ACTIONS = new Set(['publish', 'hide', 'feature', 'unfeature', 'update', 'draft']);
  const ALLOWED_PUBLICATION_TIME_STATES = new Set(['db_verified', 'legacy_event', 'legacy_column']);
  let current = [];
  let registryComplete = false;
  let invalidPublicationCount = 0;
  let uninspectedPublicationCount = 0;
  let invalidLedgerPublicationCount = 0;
  let legacyUnlinkedPublicationCount = 0;

  function setText(id, value) {
    const node = document.getElementById(id);
    if (node) node.textContent = String(value);
  }

  function safeDate(value) {
    if (value === undefined || value === null || String(value).trim() === '') return '—';
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? '—' : date.format(parsed);
  }

  function validTimestamp(value) {
    if (value === undefined || value === null || String(value).trim() === '') return false;
    return !Number.isNaN(new Date(value).getTime());
  }

  function el(tag, className, value) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined) node.textContent = String(value);
    return node;
  }

  function isObject(value) {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
  }

  function numeric(value) {
    if (value === undefined || value === null || String(value).trim() === '') return null;
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  function nonNegativeInteger(value) {
    const parsed = numeric(value);
    return Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
  }

  function proof(label, value, className) {
    const box = el('div', className || '');
    const parsed = nonNegativeInteger(value);
    box.append(el('span', '', label), el('b', '', parsed === null ? '—' : number.format(parsed)));
    return box;
  }

  function caseURL(item) {
    return `/case/${encodeURIComponent(item.case_ref || '')}`;
  }

  function rawDossierURL(item) {
    return `/dossier/${encodeURIComponent(item.case_ref || '')}`;
  }

  function caseTime(item) {
    const raw = item.produced_at || item.published_at;
    if (!raw) return 0;
    const value = new Date(raw).getTime();
    return Number.isFinite(value) ? value : 0;
  }

  function normalizedGrade(item) {
    const grade = String(item?.verdict_grade || '').trim().toUpperCase();
    if (grade) return ALLOWED_GRADES.has(grade) ? grade : 'UNAVAILABLE';
    const status = String(item?.verdict_status || '').trim().toUpperCase();
    return status === 'WITHHOLD' ? 'WITHHOLD' : 'UNAVAILABLE';
  }

  function publicationTimeLabel(item) {
    switch (String(item?.publication_time_status || '')) {
      case 'db_verified': return 'DB time verified';
      case 'legacy_event': return 'Legacy immutable event time';
      case 'legacy_column': return 'Legacy stored time';
      default: return 'Publication time unavailable';
    }
  }

  function aggregate(items, field) {
    if (!items.length) return 0;
    const values = items.map(item => nonNegativeInteger(item?.[field]));
    if (values.some(value => value === null)) return null;
    return values.reduce((sum, value) => sum + value, 0);
  }

  function registryEnvelope(payload) {
    if (!isObject(payload) || payload.schema_version !== REGISTRY_SCHEMA) throw new Error('public case registry schema is unavailable or unsupported');
    if (!Array.isArray(payload.cases)) throw new Error('public case registry collection is unavailable');
    const count = nonNegativeInteger(payload.count);
    const total = nonNegativeInteger(payload.total_publications);
    const inspected = nonNegativeInteger(payload.inspected_publications);
    const invalid = nonNegativeInteger(payload.invalid_publications);
    const uninspected = nonNegativeInteger(payload.uninspected_publications);
    const ledgerVerified = nonNegativeInteger(payload.ledger_verified_publications);
    const legacyUnlinked = nonNegativeInteger(payload.legacy_unlinked_publications);
    const invalidLedger = nonNegativeInteger(payload.invalid_ledger_publications);
    if ([count, total, inspected, invalid, uninspected, ledgerVerified, legacyUnlinked, invalidLedger].some(value => value === null)) {
      throw new Error('public case registry counts are unavailable');
    }
    if (count !== payload.cases.length || inspected !== count + invalid || total !== inspected + uninspected) {
      throw new Error('public case registry counts are structurally inconsistent');
    }
    if (ledgerVerified + legacyUnlinked + invalidLedger !== inspected) {
      throw new Error('publication ledger counts are structurally inconsistent');
    }
    if (typeof payload.registry_complete !== 'boolean' || typeof payload.publication_ledger_complete !== 'boolean') {
      throw new Error('public case registry completeness is unavailable');
    }
    const expectedComplete = invalid === 0 && uninspected === 0;
    const expectedStatus = invalid > 0 ? 'degraded' : uninspected > 0 ? 'partial' : 'operational';
    if (payload.registry_complete !== expectedComplete || payload.registry_status !== expectedStatus) {
      throw new Error('public case registry status is inconsistent');
    }
    const expectedLedgerComplete = invalidLedger === 0 && uninspected === 0 && legacyUnlinked === 0;
    const expectedLedgerStatus = invalidLedger > 0 ? 'degraded' : uninspected > 0 ? 'partial' : legacyUnlinked > 0 ? 'legacy_mixed' : 'verified';
    if (payload.publication_ledger_complete !== expectedLedgerComplete || payload.publication_ledger_status !== expectedLedgerStatus) {
      throw new Error('publication ledger status is inconsistent');
    }
    if (!validTimestamp(payload.generated_at)) throw new Error('public case registry timestamp is unavailable');
    const policy = payload.publication_policy;
    if (!isObject(policy)
      || policy.immutable_source_bundle !== true
      || policy.canonical_bundle_hash_reverified !== true
      || policy.publication_ledger_readback_verified !== true
      || policy.publication_effective_time_event_backed !== true
      || policy.db_owned_publication_time_v1 !== true
      || policy.legacy_publication_lineage_declared !== true
      || policy.transition_identifiers_public !== false
      || policy.partial_registry_declared !== true) {
      throw new Error('public case registry integrity policy is incomplete');
    }
    const seen = new Set();
    for (const item of payload.cases) {
      if (!isObject(item) || !CASE_REF_PATTERN.test(String(item.case_ref || '')) || !BUNDLE_HASH_PATTERN.test(String(item.bundle_hash || ''))) {
        throw new Error('public case registry contains an invalid immutable case identity');
      }
      if (seen.has(item.case_ref)) throw new Error('public case registry contains a duplicate case reference');
      seen.add(item.case_ref);
      if (Object.prototype.hasOwnProperty.call(item, 'transition_id')) throw new Error('public case registry exposed an internal transition identifier');
      if (!ALLOWED_LEDGER_STATES.has(String(item.publication_ledger_status || ''))) throw new Error('public case registry contains an invalid publication ledger state');
      if (!ALLOWED_PUBLISHERS.has(String(item.published_by || ''))) throw new Error('public case registry contains an invalid publisher identity');
      if (!ALLOWED_PUBLICATION_TIME_STATES.has(String(item.publication_time_status || '')) || !validTimestamp(item.published_at)) {
        throw new Error('public case registry contains an invalid publication effective time');
      }
      if (item.publication_ledger_status === 'verified' && !ALLOWED_PUBLICATION_ACTIONS.has(String(item.publication_action || ''))) {
        throw new Error('verified publication ledger record is missing its immutable action');
      }
      if (item.publication_ledger_status === 'legacy_unlinked' && String(item.publication_action || '').trim() !== '') {
        throw new Error('legacy publication lineage must not invent a linked action');
      }
    }
    return {
      cases: payload.cases,
      complete: payload.registry_complete,
      ledgerComplete: payload.publication_ledger_complete,
      invalid,
      uninspected,
      invalidLedger,
      legacyUnlinked,
      ledgerVerified,
      total,
      inspected,
      generatedAt: payload.generated_at,
      status: payload.registry_status,
      ledgerStatus: payload.publication_ledger_status
    };
  }

  async function fetchJSON(endpoint) {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort('koschei_api_timeout'), REQUEST_TIMEOUT_MS);
    try {
      const response = await fetch(endpoint, { cache: 'no-store', headers: { Accept: 'application/json' }, signal: controller.signal });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || payload.ok !== true) throw new Error(payload.error || `HTTP ${response.status}`);
      return payload;
    } catch (error) {
      if (error?.name === 'AbortError') throw new Error(`evidence service did not respond within ${REQUEST_TIMEOUT_MS / 1000} seconds`);
      throw error;
    } finally {
      window.clearTimeout(timer);
    }
  }

  // Immutable dossiers remain separately verifiable, but the public showcase
  // presents one current investigation per target. Older bundles are revisions,
  // not separate actors or separate incidents.
  function currentCases(items) {
    const groups = new Map();
    for (const item of Array.isArray(items) ? items : []) {
      const key = `${item.target_kind || 'unavailable'}:${item.target_id || item.case_ref || ''}`;
      const group = groups.get(key) || [];
      group.push(item);
      groups.set(key, group);
    }
    const out = [];
    for (const group of groups.values()) {
      group.sort((a, b) => caseTime(b) - caseTime(a));
      out.push({ ...group[0], revision_count: group.length, previous_case_refs: group.slice(1).map(item => item.case_ref) });
    }
    return out.sort((a, b) => caseTime(b) - caseTime(a));
  }

  function empty(message, className = 'soc-empty') {
    contentNode.replaceChildren(el('div', className, message));
  }

  function partialRegistryWarning() {
    const parts = [];
    if (invalidPublicationCount > 0) parts.push(`${number.format(invalidPublicationCount)} explicitly public record(s) failed required integrity verification`);
    if (invalidLedgerPublicationCount > 0) parts.push(`${number.format(invalidLedgerPublicationCount)} publication-ledger mismatch(es)`);
    if (uninspectedPublicationCount > 0) parts.push(`${number.format(uninspectedPublicationCount)} public record(s) were outside this response's inspection limit`);
    const detail = parts.length ? parts.join('; ') : 'registry completeness could not be established';
    return el('div', 'soc-error', `INCOMPLETE REGISTRY — ${detail}. Valid records below remain individually verifiable; aggregate totals are unavailable.`);
  }

  function legacyLedgerWarning() {
    return el('div', 'soc-empty', `LEGACY LINEAGE — ${number.format(legacyUnlinkedPublicationCount)} published case(s) predate transition-linked audit enforcement. Their dossier integrity is still reverified, but Koschei does not retroactively invent a publication-transition proof.`);
  }

  function caseCard(item) {
    const card = el('article', `soc-card${item.featured === true ? ' featured' : ''}`);
    const top = el('div', 'soc-card-top');
    const identity = el('div');
    identity.append(el('span', 'soc-tag', item.target_kind || 'UNAVAILABLE'));
    identity.append(el('span', 'soc-tag', item.publication_ledger_status === 'verified' ? `Ledger verified · ${item.published_by}` : 'Legacy publication lineage'));
    identity.append(el('span', 'soc-tag', publicationTimeLabel(item)));
    identity.append(el('h3', '', item.title || item.case_ref || 'Published ARVIS case'));
    identity.append(el('p', '', item.summary || 'Immutable ARVIS evidence case.'));
    if (Number(item.revision_count || 1) > 1) identity.append(el('span', 'soc-tag', `${number.format(item.revision_count)} immutable revisions · latest shown`));
    top.append(identity, el('span', 'soc-tag', normalizedGrade(item)));

    const ref = el('div', 'soc-case-ref', `${item.case_ref || 'case unavailable'} · ${item.target_display || item.target_id || 'target unavailable'}`);
    const proofs = el('div', 'soc-proof');
    proofs.append(
      proof('Evidence rows', item.evidence_rows),
      proof('Verified', item.verified_rows, 'verified'),
      proof('Observed', item.observed_rows, 'observed'),
      proof('Unknown', item.unknown_rows, 'unknown')
    );
    const hash = el('div', 'soc-hash', `Immutable bundle hash\n${item.bundle_hash || 'unavailable'}\nPublic since ${safeDate(item.published_at)} · ${publicationTimeLabel(item)}`);
    const actions = el('div', 'soc-card-actions');
    const open = el('a', 'soc-btn primary', 'Open readable case'); open.href = caseURL(item);
    const raw = el('a', 'soc-btn soc-mono', 'Raw technical record'); raw.href = rawDossierURL(item);
    const verifier = el('span', 'soc-btn soc-mono', 'Verification path'); verifier.title = item.independent_verification_path || 'Verification path unavailable';
    actions.append(open, raw, verifier);
    card.append(top, ref, proofs, hash, actions);
    return card;
  }

  function renderFiltered() {
    const query = String(searchNode?.value || '').trim().toLowerCase();
    const wantedGrade = String(gradeNode?.value || '').trim().toUpperCase();
    const filtered = current.filter(item => {
      const grade = normalizedGrade(item);
      const haystack = `${item.case_ref || ''} ${item.target_kind || ''} ${item.target_id || ''} ${item.target_display || ''} ${item.title || ''} ${item.summary || ''} ${grade} ${item.publication_ledger_status || ''} ${item.publication_time_status || ''} ${item.published_by || ''}`.toLowerCase();
      return (!wantedGrade || grade === wantedGrade) && (!query || haystack.includes(query));
    });
    if (visibleNode) visibleNode.textContent = `${filtered.length}/${current.length}`;
    const nodes = [];
    if (!registryComplete) nodes.push(partialRegistryWarning());
    if (legacyUnlinkedPublicationCount > 0) nodes.push(legacyLedgerWarning());
    if (!filtered.length) {
      nodes.push(el('div', 'soc-empty', current.length ? 'No published case matches the current filters.' : 'No explicitly published verifiable case is available yet. Private scans are not automatically listed here.'));
      contentNode.replaceChildren(...nodes);
      return;
    }
    nodes.push(...filtered.map(caseCard));
    contentNode.replaceChildren(...nodes);
  }

  function renderCases(payload) {
    const envelope = registryEnvelope(payload);
    registryComplete = envelope.complete;
    invalidPublicationCount = envelope.invalid;
    uninspectedPublicationCount = envelope.uninspected;
    invalidLedgerPublicationCount = envelope.invalidLedger;
    legacyUnlinkedPublicationCount = envelope.legacyUnlinked;
    current = currentCases(envelope.cases);
    if (registryComplete) {
      const featured = current.filter(item => item.featured === true).length;
      const verified = aggregate(current, 'verified_rows');
      const observed = aggregate(current, 'observed_rows');
      setText('metric-cases', number.format(current.length));
      setText('metric-featured', number.format(featured));
      setText('metric-verified', verified === null ? 'UNAVAILABLE' : number.format(verified));
      setText('metric-observed', observed === null ? 'UNAVAILABLE' : number.format(observed));
      setText('metric-refresh', '60 sec');
    } else {
      ['metric-cases', 'metric-featured', 'metric-verified', 'metric-observed'].forEach(id => setText(id, 'UNAVAILABLE'));
      setText('metric-refresh', 'retry in 60 sec');
    }
    renderFiltered();
    return envelope;
  }

  function renderDegraded(error) {
    current = [];
    registryComplete = false;
    invalidPublicationCount = 0;
    uninspectedPublicationCount = 0;
    invalidLedgerPublicationCount = 0;
    legacyUnlinkedPublicationCount = 0;
    empty('DEGRADED DEPENDENCY — The public evidence registry could not be verified. Blank counters must not be interpreted as safe, quiet, or empty.', 'soc-error');
    ['metric-cases', 'metric-featured', 'metric-verified', 'metric-observed'].forEach(id => setText(id, 'UNAVAILABLE'));
    setText('metric-refresh', 'retry in 60 sec');
    if (visibleNode) visibleNode.textContent = '—/—';
    if (statusNode) statusNode.textContent = 'DEGRADED · public evidence registry unavailable';
    if (updatedNode) updatedNode.textContent = `Last attempt: ${safeDate(new Date())} · ${String(error?.message || 'dependency error')}`;
  }

  async function load() {
    if (statusNode) statusNode.textContent = 'Refreshing the public evidence registry';
    try {
      const payload = await fetchJSON('/api/public/cases?limit=100');
      const envelope = renderCases(payload);
      if (statusNode) {
        statusNode.textContent = envelope.complete
          ? envelope.ledgerComplete
            ? 'Public evidence registry online · publication ledger verified'
            : `Public evidence registry online · ${number.format(envelope.legacyUnlinked)} legacy publication lineage record(s)`
          : envelope.status === 'degraded' ? 'DEGRADED · public evidence registry integrity failure' : 'PARTIAL · public evidence registry truncated';
      }
      if (updatedNode) {
        const details = [];
        if (envelope.invalid > 0) details.push(`${number.format(envelope.invalid)} integrity failure(s)`);
        if (envelope.invalidLedger > 0) details.push(`${number.format(envelope.invalidLedger)} ledger mismatch(es)`);
        if (envelope.uninspected > 0) details.push(`${number.format(envelope.uninspected)} uninspected publication(s)`);
        if (envelope.legacyUnlinked > 0) details.push(`${number.format(envelope.legacyUnlinked)} legacy lineage record(s)`);
        updatedNode.textContent = details.length
          ? `Updated: ${safeDate(envelope.generatedAt)} · ${details.join(' · ')}`
          : `Updated: ${safeDate(envelope.generatedAt)}`;
      }
    } catch (error) {
      renderDegraded(error);
    } finally {
      window.setTimeout(load, 60000);
    }
  }

  searchNode?.addEventListener('input', renderFiltered);
  gradeNode?.addEventListener('change', renderFiltered);
  load();
})();
