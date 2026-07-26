(() => {
  'use strict';

  const statusNode = document.getElementById('soc-status');
  const updatedNode = document.getElementById('soc-updated');
  const contentNode = document.getElementById('soc-events');
  const boundariesNode = document.getElementById('soc-boundaries');
  const number = new Intl.NumberFormat('tr-TR');
  const date = new Intl.DateTimeFormat('tr-TR', { dateStyle: 'medium', timeStyle: 'medium' });
  const REQUEST_TIMEOUT_MS = 12000;

  const changeLabels = {
    loader_changed: 'Program loader değişti',
    programdata_address_changed: 'ProgramData adresi değişti',
    bytecode_changed: 'Program bytecode değişti',
    upgrade_authority_opened: 'Upgrade authority açıldı',
    upgrade_authority_changed: 'Upgrade authority değişti',
    source_match_lost: 'Kaynak-bytecode eşleşmesi kayboldu',
    program_not_executable: 'Program executable değil',
    source_binary_mismatch: 'Kaynak-bytecode uyuşmazlığı',
    upgrade_authority_open: 'Upgrade authority açık'
  };

  function setText(id, value) {
    const node = document.getElementById(id);
    if (node) node.textContent = value;
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
      if (!response.ok || payload.ok !== true) throw new Error(payload.error || `HTTP ${response.status}`);
      return payload;
    } catch (error) {
      if (error?.name === 'AbortError') throw new Error(`kanıt servisi ${REQUEST_TIMEOUT_MS / 1000} saniyede yanıt vermedi`);
      throw error;
    } finally {
      window.clearTimeout(timer);
    }
  }

  function eventTitle(item) {
    if (item.type === 'program_deployment_changed') return 'Solana program dağıtımı değişti';
    if (item.type === 'program_control_risk_observed') return 'Solana program kontrol riski';
    return item.title || item.case_ref || 'ARVIS kanıt yayını';
  }

  function isProgramRisk(item) {
    return item.type === 'program_deployment_changed' || item.type === 'program_control_risk_observed';
  }

  function riskLabels(item) {
    const values = Array.isArray(item.change_types) ? item.change_types : [];
    return values.map(value => changeLabels[value] || value).join(' · ');
  }

  function eventRow(item) {
    const programRisk = isProgramRisk(item);
    const row = el('article', `soc-event${programRisk ? ' program-risk-event' : ''}`);
    row.append(el('time', '', safeDate(item.occurred_at)));

    const body = el('div');
    const title = el('a', '', eventTitle(item));
    title.href = item.public_url || '#';
    title.style.color = 'inherit';
    title.style.textDecoration = 'none';
    const strong = el('strong');
    strong.append(title);
    body.append(strong);

    if (programRisk) {
      const severity = String(item.severity || 'high').toUpperCase();
      body.append(el('p', '', `${severity} · Solana programı · ${item.target || 'program gizlendi'}`));
      const labels = riskLabels(item);
      if (labels) body.append(el('p', '', labels));
      if (item.description) body.append(el('p', '', item.description));
    } else {
      body.append(el('p', '', `${item.target_kind || 'hedef'} · ${item.target || 'gizlendi'} · ${item.description || ''}`));
    }

    const proofNode = el('div', 'soc-event-proof');
    if (programRisk) {
      proofNode.textContent = `${String(item.severity || 'high').toUpperCase()} PROGRAM ALARMI\n${item.verifiable ? 'HASH DOĞRULANABİLİR' : 'DOĞRULAMA BEKLİYOR'}`;
      proofNode.title = item.event_hash || '';
    } else {
      proofNode.textContent = `${number.format(Number(item.evidence_rows || 0))} kanıt\n${item.verifiable ? 'HASH DOĞRULANABİLİR' : 'DOĞRULAMA BEKLİYOR'}`;
      proofNode.title = item.bundle_hash || '';
    }
    row.append(body, proofNode);
    return row;
  }

  function renderLive(payload) {
    const summary = payload.summary || {};
    const events = Array.isArray(payload.events) ? payload.events : [];
    setText('metric-cases', number.format(Number(summary.published_cases || 0)));
    setText('metric-featured', number.format(Number(summary.program_risk_events || 0)));
    setText('metric-verified', number.format(Number(summary.verified_evidence_rows || 0)));
    setText('metric-observed', number.format(Number(summary.observed_evidence_rows || 0)));
    setText('metric-refresh', `${Number(payload.refresh_seconds || 15)} sn`);
    if (!events.length) {
      contentNode.replaceChildren(el('div', 'soc-empty', 'Yeni doğrulanmış yayın veya HIGH/CRITICAL program alarmı yok. Koschei hareket varmış gibi sahte olay üretmez.'));
    } else {
      contentNode.replaceChildren(...events.map(eventRow));
    }
    const boundaries = Array.isArray(payload.boundaries) ? payload.boundaries : [];
    if (boundariesNode) boundariesNode.replaceChildren(...boundaries.map(value => el('div', '', value)));
  }

  function renderDegraded(error) {
    contentNode.replaceChildren(el('div', 'soc-error', 'DEGRADED DEPENDENCY — Kanıt servisine erişilemiyor. Güncel doğrulanmış sonuç üretilmedi; boş sayaçlar güvenli veya olaysız anlamına gelmez.'));
    ['metric-cases', 'metric-featured', 'metric-verified', 'metric-observed'].forEach(id => setText(id, 'DOĞRULANAMADI'));
    setText('metric-refresh', '15 sn sonra tekrar');
    if (statusNode) statusNode.textContent = 'DEGRADED · açık kanıt servisi erişilemiyor';
    if (updatedNode) updatedNode.textContent = `Son deneme: ${safeDate(new Date())} · ${String(error?.message || 'bağımlılık hatası')}`;
    if (boundariesNode) boundariesNode.replaceChildren(el('div', 'soc-error', 'Yayın sınırları da güncel API yanıtı olmadan doğrulanamadı.'));
  }

  async function load() {
    if (statusNode) statusNode.textContent = 'ARVIS açık kanıt ve program risk akışı güncelleniyor';
    try {
      const payload = await fetchJSON('/api/public/soc/feed');
      renderLive(payload);
      if (statusNode) statusNode.textContent = 'ARVIS açık kanıt ve program risk akışı çalışıyor';
      if (updatedNode) updatedNode.textContent = `Son güncelleme: ${safeDate(payload.generated_at)}`;
    } catch (error) {
      renderDegraded(error);
    } finally {
      window.setTimeout(load, 15000);
    }
  }

  load();
})();
