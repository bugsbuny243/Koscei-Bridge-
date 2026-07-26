(() => {
  'use strict';

  const statusNode = document.getElementById('soc-status');
  const updatedNode = document.getElementById('soc-updated');
  const contentNode = document.getElementById('soc-events');
  const boundariesNode = document.getElementById('soc-boundaries');
  const number = new Intl.NumberFormat('tr-TR');
  const date = new Intl.DateTimeFormat('tr-TR', { dateStyle: 'medium', timeStyle: 'medium' });
  const REQUEST_TIMEOUT_MS = 12000;

  const labels = {
    loader_changed: 'Program loader değişti', programdata_address_changed: 'ProgramData adresi değişti',
    bytecode_changed: 'Program bytecode değişti', upgrade_authority_opened: 'Upgrade authority açıldı',
    upgrade_authority_changed: 'Upgrade authority değişti', program_not_executable: 'Program executable değil',
    source_binary_mismatch: 'Kaynak ve bytecode uyuşmuyor', upgrade_authority_open: 'Upgrade authority açık'
  };

  function setText(id, value) { const node = document.getElementById(id); if (node) node.textContent = value; }
  function safeDate(value) { const parsed = new Date(value || 0); return Number.isNaN(parsed.getTime()) ? '—' : date.format(parsed); }
  function el(tag, className, text) { const node = document.createElement(tag); if (className) node.className = className; if (text !== undefined) node.textContent = String(text); return node; }

  async function fetchJSON(endpoint) {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort('koschei_api_timeout'), REQUEST_TIMEOUT_MS);
    try {
      const response = await fetch(endpoint, { cache: 'no-store', headers: { Accept: 'application/json' }, signal: controller.signal });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || payload.ok !== true) throw new Error(payload.error || `HTTP ${response.status}`);
      return payload;
    } catch (error) {
      if (error?.name === 'AbortError') throw new Error(`kanıt servisi ${REQUEST_TIMEOUT_MS / 1000} saniyede yanıt vermedi`);
      throw error;
    } finally { window.clearTimeout(timer); }
  }

  function isProgram(item) { return item.target_kind === 'solana_program'; }
  function decision(item) {
    if (isProgram(item)) return String(item.severity).toLowerCase() === 'critical' ? 'BLOKLA' : 'UYAR';
    const grade = String(item.verdict || '').toUpperCase();
    if (grade === 'WITHHOLD' || grade === '-' || !grade) return 'İŞLEMİ BEKLET';
    if (grade === 'F' || grade === 'D') return 'BLOKLA';
    if (grade === 'C' || grade === 'B') return 'YÜKSEK DİKKAT';
    return 'KANITLA DEVAM';
  }

  function eventRow(item) {
    const program = isProgram(item);
    const row = el('article', `soc-event${program ? ' program-risk-event' : ''}`);
    row.append(el('time', '', safeDate(item.occurred_at)));
    const body = el('div');
    const title = el('a', '', item.title || item.event_ref || item.case_ref || 'ARVIS güvenlik olayı');
    title.href = item.public_url || '#';
    title.style.color = 'inherit';
    title.style.textDecoration = 'none';
    const strong = el('strong'); strong.append(title); body.append(strong);
    body.append(el('p', '', `${decision(item)} · ${item.target_kind || 'hedef'} · ${item.target || 'gizlendi'}`));
    if (program) {
      const riskText = (Array.isArray(item.change_types) ? item.change_types : []).map(value => labels[value] || value).join(' · ');
      if (riskText) body.append(el('p', '', riskText));
    }
    if (item.description) body.append(el('p', '', item.description));
    const proof = el('div', 'soc-event-proof');
    proof.textContent = program
      ? `${String(item.severity || 'high').toUpperCase()} PROGRAM RİSKİ\n${item.verifiable ? 'YENİDEN HASH EDİLEBİLİR' : 'DOĞRULAMA BEKLİYOR'}`
      : `${number.format(Number(item.evidence_rows || 0))} KANIT\n${item.verifiable ? 'BUNDLE DOĞRULANABİLİR' : 'DOĞRULAMA BEKLİYOR'}`;
    proof.title = item.verification_hash || item.bundle_hash || '';
    row.append(body, proof);
    return row;
  }

  function render(payload) {
    const summary = payload.summary || {};
    const events = Array.isArray(payload.events) ? payload.events : [];
    setText('metric-cases', number.format(Number(summary.published_cases || 0)));
    setText('metric-featured', number.format(Number(summary.program_risk_events || 0)));
    setText('metric-verified', number.format(Number(summary.verified_evidence_rows || 0)));
    setText('metric-observed', number.format(Number(summary.observed_evidence_rows || 0)));
    setText('metric-refresh', `${Number(payload.refresh_seconds || 15)} sn`);
    contentNode.replaceChildren(...(events.length ? events.map(eventRow) : [el('div', 'soc-empty', 'Yeni doğrulanmış güvenlik olayı yok. ARVIS sahte alarm üretmez.') ]));
    const boundaries = Array.isArray(payload.boundaries) ? payload.boundaries : [];
    if (boundariesNode) boundariesNode.replaceChildren(...boundaries.map(value => el('div', '', value)));
  }

  function renderDegraded(error) {
    contentNode.replaceChildren(el('div', 'soc-error', 'DEGRADED DEPENDENCY — Kanıt servisine erişilemiyor. Boş akış güvenli anlamına gelmez.'));
    ['metric-cases', 'metric-featured', 'metric-verified', 'metric-observed'].forEach(id => setText(id, 'DOĞRULANAMADI'));
    setText('metric-refresh', '15 sn sonra tekrar');
    if (statusNode) statusNode.textContent = 'DEGRADED · güvenlik kanıt servisi erişilemiyor';
    if (updatedNode) updatedNode.textContent = `Son deneme: ${safeDate(new Date())} · ${String(error?.message || 'bağımlılık hatası')}`;
    if (boundariesNode) boundariesNode.replaceChildren(el('div', 'soc-error', 'Yayın sınırları API olmadan doğrulanamadı.'));
  }

  async function load() {
    if (statusNode) statusNode.textContent = 'ARVIS canlı güvenlik akışı güncelleniyor';
    try {
      const payload = await fetchJSON('/api/public/soc/feed');
      render(payload);
      if (statusNode) statusNode.textContent = 'ARVIS canlı güvenlik radarı çalışıyor';
      if (updatedNode) updatedNode.textContent = `Son güncelleme: ${safeDate(payload.generated_at)}`;
    } catch (error) { renderDegraded(error); }
    finally { window.setTimeout(load, 15000); }
  }

  load();
})();
