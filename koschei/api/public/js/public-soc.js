(() => {
  'use strict';

  const statusNode = document.getElementById('soc-status');
  const updatedNode = document.getElementById('soc-updated');
  const contentNode = document.getElementById('case-grid');
  const number = new Intl.NumberFormat('tr-TR');
  const date = new Intl.DateTimeFormat('tr-TR', { dateStyle: 'medium', timeStyle: 'medium' });
  const REQUEST_TIMEOUT_MS = 12000;

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
      const response = await fetch(endpoint, { cache: 'no-store', headers: { Accept: 'application/json' }, signal: controller.signal });
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

  function decision(item) {
    const grade = String(item.verdict_grade || '').toUpperCase();
    const status = String(item.verdict_status || '').toLowerCase();
    if (grade === 'WITHHOLD' || grade === '-' || status.includes('withhold')) return ['İŞLEMİ BEKLET', 'withhold'];
    if (status.includes('block') || grade === 'F' || grade === 'D') return ['BLOKLA', 'block'];
    if (status.includes('warn') || status.includes('review') || grade === 'C' || grade === 'B') return ['YÜKSEK DİKKAT', 'warn'];
    if (status.includes('allow') || grade === 'A') return ['KANITLA DEVAM', 'allow'];
    return ['İŞLEMİ BEKLET', 'withhold'];
  }

  function proof(label, value, className) {
    const box = el('div', className || '');
    box.append(el('span', '', label), el('b', '', number.format(Number(value || 0))));
    return box;
  }

  function caseCard(item) {
    const [decisionLabel, decisionClass] = decision(item);
    const card = el('article', `soc-card${item.featured ? ' featured' : ''}`);
    const top = el('div', 'soc-card-top');
    const identity = el('div');
    identity.append(el('span', 'soc-tag', item.target_kind || 'hedef'));
    identity.append(el('h3', '', item.title || item.case_ref));
    identity.append(el('p', '', item.summary || 'Değişmez ARVIS güvenlik vakası.'));
    const verdict = el('span', `soc-tag ${decisionClass}`, decisionLabel);
    top.append(identity, verdict);

    const ref = el('div', 'soc-case-ref', `${item.case_ref} · ${item.target_display || 'hedef gizlendi'}`);
    const proofs = el('div', 'soc-proof');
    proofs.append(
      proof('Kanıt', item.evidence_rows),
      proof('Doğrulandı', item.verified_rows, 'verified'),
      proof('Gözlendi', item.observed_rows, 'observed'),
      proof('Çıkarım', item.inferred_rows, 'unknown')
    );
    const hash = el('div', 'soc-hash', `Değişmez bundle hash\n${item.bundle_hash || 'kullanılamıyor'}\nYayın ${safeDate(item.published_at)}`);
    const actions = el('div', 'soc-card-actions');
    const open = el('a', 'soc-btn primary', 'Güvenlik sonucunu aç');
    open.href = `/case/${encodeURIComponent(item.case_ref || '')}`;
    const raw = el('a', 'soc-btn soc-mono', 'Değişmez kanıt');
    raw.href = item.public_url || `/dossier/${encodeURIComponent(item.case_ref || '')}`;
    const verifier = el('span', 'soc-btn soc-mono', 'Bağımsız doğrulama');
    verifier.title = item.independent_verification_path || '';
    actions.append(open, raw, verifier);
    card.append(top, ref, proofs, hash, actions);
    return card;
  }

  function render(payload) {
    const cases = Array.isArray(payload.cases) ? payload.cases : [];
    setText('metric-cases', number.format(cases.length));
    setText('metric-featured', number.format(cases.filter(item => item.featured).length));
    setText('metric-verified', number.format(cases.reduce((sum, item) => sum + Number(item.verified_rows || 0), 0)));
    setText('metric-observed', number.format(cases.reduce((sum, item) => sum + Number(item.observed_rows || 0), 0)));
    setText('metric-refresh', '60 sn');
    if (!cases.length) {
      contentNode.replaceChildren(el('div', 'soc-empty', 'Henüz kullanıcı tarafından görünür yapılmış doğrulanabilir vaka yok. Özel taramalar private kalır.'));
      return;
    }
    contentNode.replaceChildren(...cases.map(caseCard));
  }

  function renderDegraded(error) {
    contentNode.replaceChildren(el('div', 'soc-error', 'DEGRADED DEPENDENCY — Kanıt servisine erişilemiyor. Boş ekran güvenli anlamına gelmez.'));
    ['metric-cases', 'metric-featured', 'metric-verified', 'metric-observed'].forEach(id => setText(id, 'DOĞRULANAMADI'));
    setText('metric-refresh', '60 sn sonra tekrar');
    if (statusNode) statusNode.textContent = 'DEGRADED · güvenlik kanıt servisi erişilemiyor';
    if (updatedNode) updatedNode.textContent = `Son deneme: ${safeDate(new Date())} · ${String(error?.message || 'bağımlılık hatası')}`;
  }

  async function load() {
    if (statusNode) statusNode.textContent = 'ARVIS güvenlik vakaları güncelleniyor';
    try {
      const payload = await fetchJSON('/api/public/cases?limit=100');
      render(payload);
      if (statusNode) statusNode.textContent = 'ARVIS güvenlik vaka akışı çalışıyor';
      if (updatedNode) updatedNode.textContent = `Son güncelleme: ${safeDate(payload.generated_at)}`;
    } catch (error) {
      renderDegraded(error);
    } finally {
      window.setTimeout(load, 60000);
    }
  }

  load();
})();
