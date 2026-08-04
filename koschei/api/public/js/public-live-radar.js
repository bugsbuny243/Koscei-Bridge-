(() => {
  'use strict';

  const statusNode = document.getElementById('soc-status');
  const updatedNode = document.getElementById('soc-updated');
  const eventsNode = document.getElementById('soc-events');
  const boundariesNode = document.getElementById('soc-boundaries');
  const number = new Intl.NumberFormat('tr-TR');
  const date = new Intl.DateTimeFormat('tr-TR', { dateStyle: 'medium', timeStyle: 'medium' });
  const REQUEST_TIMEOUT_MS = 12000;

  function setText(id, value) {
    const node = document.getElementById(id);
    if (node) node.textContent = String(value);
  }

  function safeDate(value) {
    const parsed = new Date(value || 0);
    return Number.isNaN(parsed.getTime()) ? '—' : date.format(parsed);
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = String(text);
    return node;
  }

  async function fetchJSON(endpoint) {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort('koschei_api_timeout'), REQUEST_TIMEOUT_MS);
    try {
      const response = await fetch(endpoint, {
        cache: 'no-store',
        headers: { Accept: 'application/json' },
        signal: controller.signal
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || payload.ok !== true) throw new Error(payload.status || payload.error || `HTTP ${response.status}`);
      return payload;
    } catch (error) {
      if (error?.name === 'AbortError') throw new Error(`radar servisi ${REQUEST_TIMEOUT_MS / 1000} saniyede yanıt vermedi`);
      throw error;
    } finally {
      window.clearTimeout(timer);
    }
  }

  function empty(message, className = 'soc-empty') {
    eventsNode.replaceChildren(el('div', className, message));
  }

  function eventRow(item) {
    const row = el('article', `soc-event grade-${String(item.grade || '').toLowerCase()}`);
    row.append(el('time', '', safeDate(item.occurred_at)));

    const body = el('div');
    const heading = el('strong');
    heading.append(el('span', 'soc-tag', item.grade || '—'));
    heading.append(document.createTextNode(` ${String(item.risk_level || 'unknown').toUpperCase()} · ${number.format(Number(item.risk_index || 0))}/100`));
    body.append(heading);
    body.append(el('p', '', `${item.target_kind || 'hedef'} · ${item.target || 'gizlendi'} · ${item.provider || item.source || 'kaynak bilinmiyor'}`));
    if (item.verdict) body.append(el('p', '', item.verdict));
    if (item.recommendation) body.append(el('p', '', item.recommendation));

    const proof = el('div', 'soc-event-proof', `${number.format(Number(item.evidence_rows || 0))} KANIT\n${item.verifiable ? 'İMZALI SONUÇ' : 'DOĞRULAMA YOK'}`);
    row.append(body, proof);
    return row;
  }

  function pipelineText(status) {
    switch (String(status || '').toLowerCase()) {
      case 'healthy': return 'SAĞLIKLI';
      case 'processing': return 'İŞLENİYOR';
      case 'selective_auto_volume': return 'SEÇİCİ OTOMATİK';
      case 'waiting_for_stream': return 'AKIŞ BEKLENİYOR';
      case 'waiting_for_enriched_targets': return 'ZENGİNLEŞTİRİLMİŞ HEDEF BEKLENİYOR';
      case 'waiting_for_processing': return 'İŞLEME BEKLENİYOR';
      case 'stale': return 'AKIŞ BAYAT';
      case 'degraded': return 'DEGRADED';
      default: return String(status || 'BİLİNMİYOR').toUpperCase();
    }
  }

  function render(payload) {
    const summary = payload.summary || {};
    const grades = summary.grade_counts || {};
    const events = Array.isArray(payload.events) ? payload.events : [];

    setText('metric-cases', number.format(Number(summary.live_results || events.length || 0)));
    setText('metric-featured', number.format(Number(grades.F || 0)));
    setText('metric-verified', number.format(Number(grades.D || 0)));
    setText('metric-observed', `${number.format(Number(grades.A || 0))} / ${number.format(Number(grades.B || 0))}`);
    setText('metric-refresh', `${Number(payload.refresh_seconds || 15)} sn`);

    if (!events.length) {
      empty('Son 24 saatte imzalı A/B/C/D/F radar sonucu yok. Bu alan yayınlanmış dossier vitriniyle doldurulmaz ve WITHHOLD sonucu harf notu gibi gösterilmez.');
    } else {
      eventsNode.replaceChildren(...events.map(eventRow));
    }

    const boundaries = Array.isArray(payload.boundaries) ? payload.boundaries : [];
    if (boundariesNode) boundariesNode.replaceChildren(...boundaries.map(value => el('div', '', value)));
    if (statusNode) statusNode.textContent = `ARVIS canlı radar · ${pipelineText(payload.pipeline_status)}`;
    if (updatedNode) updatedNode.textContent = `Son güncelleme: ${safeDate(payload.generated_at)}`;
  }

  function renderDegraded(error) {
    empty('DEGRADED DEPENDENCY — Canlı radar verisi doğrulanamadı. Yayınlanmış tek bir vaka, canlı akışmış gibi gösterilmiyor.', 'soc-error');
    ['metric-cases', 'metric-featured', 'metric-verified', 'metric-observed'].forEach(id => setText(id, '—'));
    setText('metric-refresh', '15 sn sonra tekrar');
    if (statusNode) statusNode.textContent = 'ARVIS canlı radar · DEGRADED';
    if (updatedNode) updatedNode.textContent = `Son deneme: ${safeDate(new Date())} · ${String(error?.message || 'bağımlılık hatası')}`;
    if (boundariesNode) boundariesNode.replaceChildren(el('div', 'soc-error', 'Kaynak durumu API yanıtı olmadan doğrulanamadı.'));
  }

  async function load() {
    if (statusNode) statusNode.textContent = 'ARVIS canlı radar güncelleniyor';
    try {
      render(await fetchJSON('/api/public/soc/feed'));
    } catch (error) {
      renderDegraded(error);
    } finally {
      window.setTimeout(load, 15000);
    }
  }

  load();
})();
