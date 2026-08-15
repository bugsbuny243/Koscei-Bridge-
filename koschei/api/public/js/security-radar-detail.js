(() => {
  'use strict';

  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
  const num = (value, digits = 0) => {
    const n = Number(value);
    return Number.isFinite(n) ? n.toLocaleString('tr-TR', { maximumFractionDigits: digits }) : '—';
  };
  const short = value => {
    const text = String(value || '');
    return text.length > 30 ? `${text.slice(0, 13)}…${text.slice(-10)}` : (text || '—');
  };
  const relative = value => {
    const date = value ? new Date(value) : null;
    if (!date || Number.isNaN(date.getTime())) return '—';
    const minutes = Math.max(0, Math.round((Date.now() - date.getTime()) / 60000));
    if (minutes < 1) return 'şimdi';
    if (minutes < 60) return `${minutes} dk`;
    if (minutes < 1440) return `${Math.round(minutes / 60)} sa`;
    return `${Math.round(minutes / 1440)} gün`;
  };
  const safeJSON = value => {
    try { return JSON.stringify(value ?? {}, null, 2); } catch { return '{}'; }
  };

  const state = { cards: new Map(), access: false, currentTarget: '' };

  function canonicalGrade(value) {
    const grade = String(value || '-').trim().toUpperCase();
    return grade || '-';
  }

  function gradeBand(value) {
    const grade = canonicalGrade(value);
    if (['F', 'E', 'D', 'D+'].includes(grade)) return 'high';
    if (['C', 'C-', 'C+'].includes(grade)) return 'elevated';
    if (['A', 'A-', 'A+', 'B', 'B-', 'B+'].includes(grade)) return 'monitor';
    return 'unknown';
  }

  function gradeTone(value, signed = true) {
    if (!signed) return 'warn';
    const band = gradeBand(value);
    if (band === 'high') return 'bad';
    if (band === 'elevated') return 'warn';
    if (band === 'monitor') return 'good';
    return 'warn';
  }

  function canonicalSigned(item) {
    return item?.signed === true && String(item?.signature || '').trim() !== '';
  }

  function api(path, options = {}) {
    return KoscheiAuth.apiCall(path, options).then(async response => ({
      response,
      data: await response.json().catch(() => ({}))
    }));
  }

  function notice(message, bad = false) {
    const node = $('notice');
    if (!node) return;
    node.textContent = message;
    node.className = `notice show${bad ? ' bad' : ''}`;
  }

  function clearNotice() {
    const node = $('notice');
    if (node) node.className = 'notice';
  }

  function renderStatus(stream = {}) {
    const manual = stream.enabled === false || ['waiting_for_stream', 'stale'].includes(String(stream.pipeline_status || ''));
    $('statusDot').className = `dot ${manual ? '' : 'live'}`;
    $('statusText').textContent = manual ? 'Manuel soruşturma hazır' : 'Canonical Radar canlı';
    $('statusNote').textContent = manual
      ? 'Otomatik akış sınırlı olabilir; imzalı canonical kararlar ve manuel soruşturma kullanılabilir.'
      : 'Canonical verdict store ve imzalı karar zinciri çalışıyor.';
    $('processed').textContent = num(stream.processing_completed, 0);
    $('insufficient').textContent = num(stream.processing_insufficient, 0);
    $('lastDecision').textContent = relative(stream.last_processed_at);
  }

  async function loadAccess() {
    const { response, data } = await api('/api/auth/premium-access');
    const access = data.access || {};
    state.access = response.ok && access.active === true;
    const plan = String(access.plan || 'none').toUpperCase();
    const remaining = Number.isFinite(Number(access.outputs_remaining)) ? ` · ${num(access.outputs_remaining)} çıktı` : '';
    $('accessPill').textContent = state.access ? `${plan} PLAN${remaining}` : `${String(access.required_plan || 'starter').toUpperCase()} PLAN GEREKLİ`;
    $('accessPill').className = `pill ${state.access ? 'green' : 'amber'}`;
  }

  function renderCards(items) {
    state.cards.clear();
    const visible = (items || []).filter(canonicalSigned);
    const dangerItems = visible.filter(item => ['high', 'elevated'].includes(gradeBand(item.grade)));
    const monitorItems = visible.filter(item => !['high', 'elevated'].includes(gradeBand(item.grade)));

    $('visible').textContent = num(visible.length, 0);
    $('floored').textContent = num(visible.filter(item => canonicalSigned(item)).length, 0);
    $('redCount').textContent = dangerItems.length;
    $('greenCount').textContent = monitorItems.length;

    const cardHTML = item => {
      const key = String(item.id || item.signature || item.target).replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 70);
      state.cards.set(key, item);
      const grade = canonicalGrade(item.grade);
      const tone = gradeTone(grade, item.signed === true);
      const band = gradeBand(grade);
      const summary = item.summary || {};
      return `<article class="radar-card" data-key="${esc(key)}">
        <div class="cardtop"><div><div class="project">${esc(short(item.target))}</div><div class="token">${esc(item.target)}</div></div><span class="badge ${tone === 'bad' ? 'red' : 'green'}">${esc(band.toUpperCase())}</span></div>
        <div class="mini"><span>Canonical grade</span><b>${esc(grade)}</b></div>
        <div class="mini"><span>Verdict</span><b>${esc(item.verdict || '—')}</b></div>
        <div class="mini"><span>İmzalı gözlem</span><b>${esc(summary.occurrence_count || item.scan_count || item.occurrence_count || 1)}</b></div>
        <div class="mini"><span>Son görülen</span><b>${esc(relative(summary.last_seen_at || item.last_seen_at || item.created_at))}</b></div>
      </article>`;
    };

    $('danger').innerHTML = dangerItems.length ? dangerItems.map(cardHTML).join('') : '<div class="empty">İmzalı high/elevated canonical karar yok.</div>';
    $('monitor').innerHTML = monitorItems.length ? monitorItems.map(cardHTML).join('') : '<div class="empty">İmzalı monitor canonical kararı yok.</div>';
    document.querySelectorAll('[data-key]').forEach(node => node.addEventListener('click', () => {
      const item = state.cards.get(node.dataset.key);
      if (item) openDetail(item.target, item);
    }));
    return visible;
  }

  async function loadFeed() {
    const { response, data } = await api('/api/v1/radar/feed');
    if (!response.ok) {
      notice(response.status === 401 ? 'Giriş yapmanız gerekiyor.' : 'Canonical Radar feed şu anda kullanılamıyor.', true);
      return [];
    }
    renderStatus(data.stream || {});
    return renderCards(data.items || []);
  }

  function listRows(items, emptyText) {
    if (!Array.isArray(items) || !items.length) return `<div class="empty">${esc(emptyText)}</div>`;
    return `<div class="evidence-list">${items.map(item => {
      const title = item.rule_id || item.title || item.label || item.status || 'evidence';
      const text = item.summary || item.reason || item.description || safeJSON(item);
      return `<div class="evidence-row verified"><b>${esc(title)}</b><span>${esc(text)}</span><small>CANONICAL</small></div>`;
    }).join('')}</div>`;
  }

  function recursiveLineagePanel(lineage) {
    if (!lineage || typeof lineage !== 'object') return '';
    const seeds = Array.isArray(lineage.seeds) ? lineage.seeds : [];
    const tokens = Array.isArray(lineage.related_tokens) ? lineage.related_tokens : [];
    return `<section class="panel full"><span class="eyebrow">RECURSIVE ACTOR LINEAGE</span><h3>Bounded geçmiş token soy ağacı</h3>
      <div class="mini"><span>Seed wallet</span><b>${esc(seeds.length)}</b></div>
      <div class="mini"><span>İlişkili token</span><b>${esc(tokens.length)}</b></div>
      <div class="mini"><span>Kapsam</span><b>${esc(lineage.complete === false ? 'SINIRLI / EKSİK' : 'BOUNDED COMPLETE')}</b></div>
      <details><summary>Lineage JSON</summary><pre>${esc(safeJSON(lineage))}</pre></details></section>`;
  }

  function renderDetail(data, fallbackItem = {}) {
    const final = data.final_verdict || fallbackItem || {};
    const grade = canonicalGrade(final.grade || fallbackItem.grade);
    const signed = final.signed === true || canonicalSigned(fallbackItem);
    const tone = gradeTone(grade, signed);
    const triggered = Array.isArray(final.triggered_rules) ? final.triggered_rules : (Array.isArray(fallbackItem.triggered_rules) ? fallbackItem.triggered_rules : []);
    const watchFlags = Array.isArray(final.watch_flags) ? final.watch_flags : (Array.isArray(fallbackItem.watch_flags) ? fallbackItem.watch_flags : []);
    const decisionPath = Array.isArray(final.decision_path) ? final.decision_path : (Array.isArray(fallbackItem.decision_path) ? fallbackItem.decision_path : []);
    const source = data.source_context || {};
    const distribution = data.holder_distribution || {};
    const actor = data.actor_investigation || {};
    const target = data.target || fallbackItem.target || state.currentTarget;

    $('reportTitle').textContent = source.token_symbol || source.token_name || short(target);
    $('reportBody').className = 'detail-body';
    $('reportBody').innerHTML = `
      <section class="verdict-head ${tone}">
        <div class="scorebox"><strong>${esc(grade)}</strong><span>UNIFIED GRADE</span></div>
        <div><span class="eyebrow">CANONICAL KOSCHEI VERDICT</span><h2>${esc(final.verdict || fallbackItem.verdict || 'Kanıt değerlendirmesi sürüyor')}</h2><div class="target-full">${esc(target)}</div><p class="muted">${esc(final.recommendation || data.warning?.interpretation || 'Kanıt, karşı kanıt ve eksik deliller birlikte değerlendirilir.')}</p><div class="actions"><span class="pill ${signed ? 'green' : 'amber'}">${signed ? 'SIGNED' : 'EVIDENCE PENDING'}</span><span class="pill">${esc(grade)}</span><span class="pill violet">${esc(final.ruleset_version || final.rule_version || fallbackItem.rule_version || 'ruleset')}</span></div></div>
      </section>
      <section class="statgrid">
        <article class="stat"><label>Canonical authority</label><strong>UNIFIED STORE</strong><small>security_unified_radar_verdicts</small></article>
        <article class="stat"><label>Top 1</label><strong>${distribution.top_1_percentage == null ? '—' : `%${num(distribution.top_1_percentage, 4)}`}</strong><small>holder concentration</small></article>
        <article class="stat"><label>Top 10</label><strong>${distribution.top_10_percentage == null ? '—' : `%${num(distribution.top_10_percentage, 4)}`}</strong><small>holder concentration</small></article>
        <article class="stat"><label>Creator</label><strong>${esc(short(source.creator_wallet || ''))}</strong><small>${esc(source.creator_scope || 'source relation')}</small></article>
      </section>
      <section class="two-col"><article class="panel"><span class="eyebrow">TRIGGERED RULES</span><h3>Deterministik tetikler</h3>${listRows(triggered, 'Tetiklenen canonical rule yok.')}</article><article class="panel"><span class="eyebrow">WATCH FLAGS</span><h3>İzleme sinyalleri</h3>${listRows(watchFlags, 'Aktif watch flag yok.')}</article></section>
      <section class="panel full"><span class="eyebrow">DECISION PATH</span><h3>Karar yolu</h3>${decisionPath.length ? `<ol>${decisionPath.map(item => `<li>${esc(item)}</li>`).join('')}</ol>` : '<div class="empty">Decision path sağlanmadı.</div>'}</section>
      ${recursiveLineagePanel(actor.recursive_lineage)}
      <section class="panel full"><span class="eyebrow">FULL INVESTIGATION EVIDENCE</span><h3>Kanıt ve tanı çıktıları</h3><details open><summary>Actor investigation</summary><pre>${esc(safeJSON(actor))}</pre></details><details><summary>Behavior signals</summary><pre>${esc(safeJSON(data.behavior_signals || {}))}</pre></details><details><summary>LP control</summary><pre>${esc(safeJSON(data.lp_control || {}))}</pre></details><details><summary>Threat anticipation</summary><pre>${esc(safeJSON(data.threat_anticipation || {}))}</pre></details><details><summary>Evidence log</summary><pre>${esc(safeJSON(data.evidence || []))}</pre></details></section>
      <section class="panel full"><span class="eyebrow">SIGNATURE</span><h3>Canonical karar kimliği</h3><div class="signature">${esc(final.signature || fallbackItem.signature || '—')}</div></section>
      <p class="disclaimer">Koschei operasyonel kanıt ve teknik risk sınıflandırır; gerçek kişi kimliği, niyet veya suç isnadı üretmez.</p>`;
    $('reportBody').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function normalizeCustomerInvestigation(envelope, target) {
    const report = envelope?.investigation_report;
    if (!report || typeof report !== 'object' || Array.isArray(report)) return null;
    return { ...report, target: report.target || target, final_verdict: report.final_verdict || envelope.final_verdict || {} };
  }

  async function openDetail(target, fallbackItem = {}) {
    const clean = String(target || '').trim();
    if (!clean) return;
    state.currentTarget = clean;
    $('reportTitle').textContent = 'Canonical Radar raporu hazırlanıyor';
    $('reportBody').className = 'empty';
    $('reportBody').textContent = 'Kanıt dosyası ve imzalı karar okunuyor…';
    try {
      const { response, data } = await api(`/api/v1/radar/detail?target=${encodeURIComponent(clean)}&network=solana-mainnet`);
      if (!response.ok) throw new Error(data.message || data.error || 'Detay raporu alınamadı.');
      renderDetail(data, fallbackItem);
    } catch (error) {
      notice(error.message || 'Detay raporu alınamadı.', true);
      renderDetail({ target: clean, final_verdict: fallbackItem }, fallbackItem);
    }
  }

  async function runScan() {
    const target = $('target').value.trim();
    if (!target) {
      notice('Kontrol edilecek Solana mintini girin.', true);
      return;
    }
    clearNotice();
    $('run').disabled = true;
    $('run').textContent = 'KANIT TOPLANIYOR…';
    try {
      const { response, data } = await api('/api/v1/radar/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, network: 'solana-mainnet', mode: 'manual_dashboard_check' })
      });
      if (!response.ok) throw new Error(data.message || data.error || 'Tarama tamamlanamadı.');
      const report = normalizeCustomerInvestigation(data, target);
      if (report) {
        renderDetail(report, data.final_verdict || {});
        notice('Canonical soruşturma dosyası hazırlandı.');
      } else {
        const items = await loadFeed();
        const item = items.find(row => String(row.target || '').toLowerCase() === target.toLowerCase()) || data.final_verdict || {};
        await openDetail(target, item);
      }
    } catch (error) {
      notice(error.message || 'Radar yanıtı kullanılamıyor.', true);
    } finally {
      $('run').disabled = false;
      $('run').textContent = 'TAM ARVIS RADARI ÇALIŞTIR';
    }
  }

  async function boot() {
    await KoscheiAuth.init();
    if (!KoscheiAuth.requireAuth('/login')) return;
    $('run').addEventListener('click', runScan);
    const initialTarget = new URLSearchParams(location.search).get('target') || '';
    if (initialTarget) $('target').value = initialTarget;
    await Promise.all([loadAccess(), loadFeed()]);
    if (initialTarget && state.access) await openDetail(initialTarget);
    window.setInterval(loadFeed, 30000);
  }

  boot();
})();
