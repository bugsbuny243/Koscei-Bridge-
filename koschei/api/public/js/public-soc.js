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
  let current = [];

  function setText(id, value) {
    const node = document.getElementById(id);
    if (node) node.textContent = String(value);
  }

  function safeDate(value) {
    const parsed = new Date(value || 0);
    return Number.isNaN(parsed.getTime()) ? '—' : date.format(parsed);
  }

  function el(tag, className, value) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined) node.textContent = String(value);
    return node;
  }

  function proof(label, value, className) {
    const box = el('div', className || '');
    box.append(el('span', '', label), el('b', '', number.format(Number(value || 0))));
    return box;
  }

  function caseURL(item) {
    return `/case/${encodeURIComponent(item.case_ref || '')}`;
  }

  function caseTime(item) {
    const value = new Date(item.produced_at || item.published_at || 0).getTime();
    return Number.isFinite(value) ? value : 0;
  }

  function normalizedGrade(item) {
    return String(item.verdict_grade || item.verdict_status || 'WITHHOLD').trim().toUpperCase() || 'WITHHOLD';
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
      const key = `${item.target_kind || 'unknown'}:${item.target_id || item.case_ref || ''}`;
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

  function caseCard(item) {
    const card = el('article', `soc-card${item.featured ? ' featured' : ''}`);
    const top = el('div', 'soc-card-top');
    const identity = el('div');
    identity.append(el('span', 'soc-tag', item.target_kind || 'unknown'));
    identity.append(el('h3', '', item.title || item.case_ref || 'Published ARVIS case'));
    identity.append(el('p', '', item.summary || 'Immutable ARVIS evidence case.'));
    if (Number(item.revision_count || 1) > 1) identity.append(el('span', 'soc-tag', `${number.format(item.revision_count)} immutable revisions · latest shown`));
    top.append(identity, el('span', 'soc-tag', normalizedGrade(item)));

    const ref = el('div', 'soc-case-ref', `${item.case_ref || 'case unavailable'} · ${item.target_display || item.target_id || 'target withheld'}`);
    const proofs = el('div', 'soc-proof');
    proofs.append(
      proof('Evidence rows', item.evidence_rows),
      proof('Verified', item.verified_rows, 'verified'),
      proof('Observed', item.observed_rows, 'observed'),
      proof('Unknown', item.unknown_rows, 'unknown')
    );
    const hash = el('div', 'soc-hash', `Immutable bundle hash\n${item.bundle_hash || 'unavailable'}\nPublished ${safeDate(item.published_at)}`);
    const actions = el('div', 'soc-card-actions');
    const open = el('a', 'soc-btn primary', 'Open readable case'); open.href = caseURL(item);
    const raw = el('a', 'soc-btn soc-mono', 'Raw technical record'); raw.href = item.public_url || `/dossier/${encodeURIComponent(item.case_ref || '')}`;
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
      const haystack = `${item.case_ref || ''} ${item.target_kind || ''} ${item.target_id || ''} ${item.target_display || ''} ${item.title || ''} ${item.summary || ''} ${grade}`.toLowerCase();
      return (!wantedGrade || grade === wantedGrade) && (!query || haystack.includes(query));
    });
    if (visibleNode) visibleNode.textContent = `${filtered.length}/${current.length}`;
    if (!filtered.length) {
      empty(current.length ? 'No published case matches the current filters.' : 'No explicitly published verifiable case is available yet. Private scans are not automatically listed here.');
      return;
    }
    contentNode.replaceChildren(...filtered.map(caseCard));
  }

  function renderCases(payload) {
    current = currentCases(payload.cases);
    const featured = current.filter(item => item.featured).length;
    const verified = current.reduce((sum, item) => sum + Number(item.verified_rows || 0), 0);
    const observed = current.reduce((sum, item) => sum + Number(item.observed_rows || 0), 0);
    setText('metric-cases', number.format(current.length));
    setText('metric-featured', number.format(featured));
    setText('metric-verified', number.format(verified));
    setText('metric-observed', number.format(observed));
    setText('metric-refresh', '60 sec');
    renderFiltered();
  }

  function renderDegraded(error) {
    current = [];
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
      renderCases(payload);
      if (statusNode) statusNode.textContent = 'Public evidence registry online';
      if (updatedNode) updatedNode.textContent = `Updated: ${safeDate(payload.generated_at)}`;
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
