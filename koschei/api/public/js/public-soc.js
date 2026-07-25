(() => {
  'use strict';

  const page = document.body.dataset.koscheiSocPage || 'cases';
  const statusNode = document.getElementById('soc-status');
  const updatedNode = document.getElementById('soc-updated');
  const contentNode = document.getElementById(page === 'live' ? 'soc-events' : 'case-grid');
  const boundariesNode = document.getElementById('soc-boundaries');
  const number = new Intl.NumberFormat('tr-TR');
  const date = new Intl.DateTimeFormat('tr-TR', { dateStyle: 'medium', timeStyle: 'medium' });

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
    identity.append(el('h3', '', item.title || item.case_ref));
    identity.append(el('p', '', item.summary || 'Değişmez ARVIS kanıt vakası.'));
    if (Number(item.revision_count || 1) > 1) {
      identity.append(el('span', 'soc-tag', `${number.format(item.revision_count)} teknik sürüm · en güncel gösteriliyor`));
    }
    const verdict = el('span', 'soc-tag', item.verdict_grade || item.verdict_status || 'WITHHOLD');
    top.append(identity, verdict);

    const ref = el('div', 'soc-case-ref', `${item.case_ref} · ${item.target_display || 'hedef gizlendi'}`);
    const proofs = el('div', 'soc-proof');
    proofs.append(
      proof('Kanıt satırı', item.evidence_rows),
      proof('Doğrulandı', item.verified_rows, 'verified'),
      proof('Gözlendi', item.observed_rows, 'observed'),
      proof('Eksik', item.unknown_rows, 'unknown')
    );
    const hash = el('div', 'soc-hash', `Değişmez bundle hash\n${item.bundle_hash || 'kullanılamıyor'}\nYayın ${safeDate(item.published_at)}`);
    const actions = el('div', 'soc-card-actions');
    const open = el('a', 'soc-btn primary', 'Anlaşılır özeti aç');
    open.href = caseURL(item);
    const raw = el('a', 'soc-btn soc-mono', 'Ham teknik dosya');
    raw.href = item.public_url || `/dossier/${encodeURIComponent(item.case_ref)}`;
    const verifier = el('span', 'soc-btn soc-mono', 'Bağımsız doğrulama');
    verifier.title = item.independent_verification_path || '';
    actions.append(open, raw, verifier);
    card.append(top, ref, proofs, hash, actions);
    return card;
  }

  function renderCases(payload) {
    const cases = currentCases(payload.cases);
    const featured = cases.filter(item => item.featured).length;
    const verified = cases.reduce((sum, item) => sum + Number(item.verified_rows || 0), 0);
    const observed = cases.reduce((sum, item) => sum + Number(item.observed_rows || 0), 0);
    setText('metric-cases', number.format(cases.length));
    setText('metric-featured', number.format(featured));
    setText('metric-verified', number.format(verified));
    setText('metric-observed', number.format(observed));
    setText('metric-refresh', '60 sn');
    if (!cases.length) {
      empty('Henüz açıkça yayınlanmış doğrulanabilir vaka yok. Özel taramalar otomatik olarak burada görünmez.');
      return;
    }
    contentNode.replaceChildren(...cases.map(caseCard));
  }

  function eventRow(item) {
    const row = el('article', 'soc-event');
    row.append(el('time', '', safeDate(item.occurred_at)));
    const body = el('div');
    const title = el('a', '', item.title || item.case_ref);
    title.href = caseURL(item);
    title.style.color = 'inherit';
    title.style.textDecoration = 'none';
    const strong = el('strong');
    strong.append(title);
    body.append(strong, el('p', '', `${item.target_kind || 'hedef'} · ${item.target || 'gizlendi'} · ${item.description || ''}`));
    const proofNode = el('div', 'soc-event-proof', `${number.format(Number(item.evidence_rows || 0))} kanıt\n${item.verifiable ? 'HASH DOĞRULANABİLİR' : 'DOĞRULAMA BEKLİYOR'}`);
    row.append(body, proofNode);
    return row;
  }

  function renderLive(payload) {
    const summary = payload.summary || {};
    const events = currentCases(Array.isArray(payload.events) ? payload.events.map(item => ({
      ...item,
      target_id: item.target,
      produced_at: item.occurred_at
    })) : []);
    setText('metric-cases', number.format(events.length));
    setText('metric-featured', number.format(Number(summary.featured_cases || 0)));
    setText('metric-verified', number.format(Number(summary.verified_evidence_rows || 0)));
    setText('metric-observed', number.format(Number(summary.observed_evidence_rows || 0)));
    setText('metric-refresh', `${Number(payload.refresh_seconds || 15)} sn`);
    if (!events.length) {
      empty('Yeni doğrulanmış yayın yok. Koschei hareket varmış gibi sahte olay üretmez.');
    } else {
      contentNode.replaceChildren(...events.map(eventRow));
    }
    const boundaries = Array.isArray(payload.boundaries) ? payload.boundaries : [];
    if (boundariesNode) boundariesNode.replaceChildren(...boundaries.map(value => el('div', '', value)));
  }

  async function load() {
    if (statusNode) statusNode.textContent = 'ARVIS açık kanıt akışı güncelleniyor';
    try {
      const endpoint = page === 'live' ? '/api/public/soc/feed' : '/api/public/cases?limit=100';
      const response = await fetch(endpoint, { cache: 'no-store', headers: { Accept: 'application/json' } });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || payload.ok !== true) throw new Error(payload.error || `HTTP ${response.status}`);
      if (page === 'live') renderLive(payload); else renderCases(payload);
      if (statusNode) statusNode.textContent = 'ARVIS açık kanıt akışı çalışıyor';
      if (updatedNode) updatedNode.textContent = `Son güncelleme: ${safeDate(payload.generated_at)}`;
    } catch (error) {
      empty('Canlı kanıt akışı şu anda doğrulanamadı. Eski veya uydurma veri gösterilmiyor.', 'soc-error');
      if (statusNode) statusNode.textContent = 'Açık kanıt akışına ulaşılamıyor';
      if (updatedNode) updatedNode.textContent = String(error?.message || 'bilinmeyen hata');
    } finally {
      window.setTimeout(load, page === 'live' ? 15000 : 60000);
    }
  }

  load();
})();
