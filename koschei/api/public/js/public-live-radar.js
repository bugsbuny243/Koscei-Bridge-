(() => {
  'use strict';

  const statusNode = document.getElementById('soc-status');
  const updatedNode = document.getElementById('soc-updated');
  const eventsNode = document.getElementById('soc-events');
  const boundariesNode = document.getElementById('soc-boundaries');
  const searchNode = document.getElementById('live-search');
  const gradeNode = document.getElementById('live-grade');
  const visibleNode = document.getElementById('live-visible');
  const number = new Intl.NumberFormat('en-US');
  const date = new Intl.DateTimeFormat('en-US', { dateStyle: 'medium', timeStyle: 'medium' });
  const REQUEST_TIMEOUT_MS = 12000;
  let currentEvents = [];

  function setText(id, value) {
    const node = document.getElementById(id);
    if (node) node.textContent = String(value);
  }

  function safeDate(value) {
    if (value === undefined || value === null || String(value).trim() === '') return '—';
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? '—' : date.format(parsed);
  }

  function el(tag, className, value) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined) node.textContent = String(value);
    return node;
  }

  function numeric(value) {
    if (value === undefined || value === null || String(value).trim() === '') return null;
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  async function fetchJSON(endpoint) {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort('koschei_api_timeout'), REQUEST_TIMEOUT_MS);
    try {
      const response = await fetch(endpoint, { cache: 'no-store', headers: { Accept: 'application/json' }, signal: controller.signal });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || payload.ok !== true) throw new Error(payload.status || payload.error || `HTTP ${response.status}`);
      return payload;
    } catch (error) {
      if (error?.name === 'AbortError') throw new Error(`live radar did not respond within ${REQUEST_TIMEOUT_MS / 1000} seconds`);
      throw error;
    } finally {
      window.clearTimeout(timer);
    }
  }

  function empty(message, className = 'soc-empty') {
    eventsNode.replaceChildren(el('div', className, message));
  }

  function normalizedGrade(item) {
    return String(item?.grade || '').trim().toUpperCase();
  }

  function derivedGradeCount(grade) {
    return currentEvents.filter(item => normalizedGrade(item) === grade).length;
  }

  function summaryGradeCount(grades, grade) {
    if (!Object.prototype.hasOwnProperty.call(grades, grade)) return derivedGradeCount(grade);
    const parsed = numeric(grades[grade]);
    return parsed === null ? null : parsed;
  }

  function eventRow(item) {
    const grade = normalizedGrade(item) || '—';
    const riskIndex = numeric(item.risk_index);
    const evidenceRows = numeric(item.evidence_rows);
    const row = el('article', `soc-event grade-${grade.toLowerCase()}`);
    row.append(el('time', '', safeDate(item.occurred_at)));

    const body = el('div');
    const heading = el('strong');
    heading.append(el('span', 'soc-tag', grade));
    heading.append(document.createTextNode(` ${String(item.risk_level || 'unknown').toUpperCase()} · ${riskIndex === null ? '—' : number.format(riskIndex)}/100`));
    body.append(heading);
    body.append(el('p', '', `${item.target_kind || 'target'} · ${item.target || 'withheld'} · ${item.provider || item.source || 'source unavailable'}`));
    if (item.verdict) body.append(el('p', '', item.verdict));
    if (item.recommendation) body.append(el('p', '', item.recommendation));

    const proof = el('div', 'soc-event-proof', `${evidenceRows === null ? '—' : number.format(evidenceRows)} EVIDENCE ROWS\n${item.verifiable ? 'SIGNED / VERIFIABLE' : 'VERIFICATION UNAVAILABLE'}`);
    row.append(body, proof);
    return row;
  }

  function pipelineText(status) {
    switch (String(status || '').toLowerCase()) {
      case 'healthy': return 'HEALTHY';
      case 'processing': return 'PROCESSING';
      case 'selective_auto_volume': return 'SELECTIVE AUTO VOLUME';
      case 'waiting_for_stream': return 'WAITING FOR STREAM';
      case 'waiting_for_enriched_targets': return 'WAITING FOR ENRICHED TARGETS';
      case 'waiting_for_processing': return 'WAITING FOR PROCESSING';
      case 'stale': return 'STALE';
      case 'degraded': return 'DEGRADED';
      default: return String(status || 'UNKNOWN').toUpperCase();
    }
  }

  function renderFiltered() {
    const query = String(searchNode?.value || '').trim().toLowerCase();
    const wantedGrade = String(gradeNode?.value || '').trim().toUpperCase();
    const filtered = currentEvents.filter(item => {
      const grade = normalizedGrade(item);
      const haystack = `${grade} ${item.risk_level || ''} ${item.target_kind || ''} ${item.target || ''} ${item.provider || item.source || ''} ${item.verdict || ''} ${item.recommendation || ''}`.toLowerCase();
      return (!wantedGrade || grade === wantedGrade) && (!query || haystack.includes(query));
    });
    if (visibleNode) visibleNode.textContent = `${filtered.length}/${currentEvents.length}`;
    if (!filtered.length) {
      empty(currentEvents.length ? 'No live result matches the current filters.' : 'No signed A/B/C/D/F live-radar result is available in the current feed window. Quiet evidence is not replaced with synthetic activity.');
      return;
    }
    eventsNode.replaceChildren(...filtered.map(eventRow));
  }

  function metricValue(value) {
    return value === null ? 'UNAVAILABLE' : number.format(value);
  }

  function render(payload) {
    const summary = payload.summary || {};
    const grades = summary.grade_counts || {};
    currentEvents = Array.isArray(payload.events) ? payload.events : [];

    const liveResults = numeric(summary.live_results);
    const gradeF = summaryGradeCount(grades, 'F');
    const gradeD = summaryGradeCount(grades, 'D');
    const gradeA = summaryGradeCount(grades, 'A');
    const gradeB = summaryGradeCount(grades, 'B');
    setText('metric-cases', number.format(liveResults === null ? currentEvents.length : liveResults));
    setText('metric-featured', metricValue(gradeF));
    setText('metric-verified', metricValue(gradeD));
    setText('metric-observed', gradeA === null || gradeB === null ? 'UNAVAILABLE' : `${number.format(gradeA)} / ${number.format(gradeB)}`);
    const refresh = numeric(payload.refresh_seconds);
    setText('metric-refresh', `${refresh === null ? 15 : refresh} sec`);
    renderFiltered();

    const boundaries = Array.isArray(payload.boundaries) ? payload.boundaries : [];
    if (boundariesNode) boundariesNode.replaceChildren(...(boundaries.length ? boundaries.map(value => el('div', '', value)) : [el('div', '', 'No public disclosure boundary list was returned by the feed.')]));
    if (statusNode) statusNode.textContent = `ARVIS live radar · ${pipelineText(payload.pipeline_status)}`;
    if (updatedNode) updatedNode.textContent = `Updated: ${safeDate(payload.generated_at)}`;
  }

  function renderDegraded(error) {
    currentEvents = [];
    empty('DEGRADED DEPENDENCY — Live radar data could not be verified. A published case is not substituted for a live event, and unavailable counts are not displayed as zero.', 'soc-error');
    ['metric-cases', 'metric-featured', 'metric-verified', 'metric-observed'].forEach(id => setText(id, 'UNAVAILABLE'));
    setText('metric-refresh', 'retry in 15 sec');
    if (visibleNode) visibleNode.textContent = '—/—';
    if (statusNode) statusNode.textContent = 'ARVIS live radar · DEGRADED';
    if (updatedNode) updatedNode.textContent = `Last attempt: ${safeDate(new Date())} · ${String(error?.message || 'dependency error')}`;
    if (boundariesNode) boundariesNode.replaceChildren(el('div', 'soc-error', 'Public disclosure boundaries could not be refreshed without a valid API response.'));
  }

  async function load() {
    if (statusNode) statusNode.textContent = 'Refreshing ARVIS live radar';
    try {
      render(await fetchJSON('/api/public/soc/feed'));
    } catch (error) {
      renderDegraded(error);
    } finally {
      window.setTimeout(load, 15000);
    }
  }

  searchNode?.addEventListener('input', renderFiltered);
  gradeNode?.addEventListener('change', renderFiltered);
  load();
})();
