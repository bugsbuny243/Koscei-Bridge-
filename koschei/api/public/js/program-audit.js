(() => {
  'use strict';

  const form = document.getElementById('audit-form');
  const programID = document.getElementById('program-id');
  const artifactType = document.getElementById('artifact-type');
  const sourceCommit = document.getElementById('source-commit');
  const content = document.getElementById('content');
  const status = document.getElementById('status');
  const runButton = document.getElementById('run');
  const result = document.getElementById('result');
  const findingsNode = document.getElementById('findings');
  const hint = document.getElementById('format-hint');
  const REQUEST_TIMEOUT_MS = 45000;

  const decisionLabels = {
    block: 'BLOKLA', warn: 'UYAR', review: 'İNCELE', no_static_trigger: 'STATİK TETİK YOK'
  };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = String(text);
    return node;
  }

  function setStatus(message, bad = false) {
    status.textContent = message;
    status.classList.toggle('bad', bad);
  }

  async function request(path, body) {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const response = await fetch(path, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify(body), signal: controller.signal
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || payload.ok !== true) {
        const error = new Error(payload.details || payload.message || payload.error || `HTTP ${response.status}`);
        error.status = response.status;
        throw error;
      }
      return payload;
    } finally {
      window.clearTimeout(timer);
    }
  }

  function validateArtifact() {
    const raw = content.value.trim();
    if (!programID.value.trim()) throw new Error('Program ID gerekli.');
    if (!raw) throw new Error('Artifact içeriği gerekli.');
    try {
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('JSON nesnesi gerekli.');
    } catch (error) {
      throw new Error(`Artifact geçerli JSON değil: ${error.message}`);
    }
    return raw;
  }

  function renderFinding(finding) {
    const card = el('article', 'finding');
    const header = el('header');
    const title = el('div');
    title.append(el('code', '', finding.rule_id || 'KPS'), el('h3', '', finding.title || 'Güvenlik inceleme yüzeyi'));
    header.append(title, el('b', `severity-${String(finding.severity || 'low').toLowerCase()}`, String(finding.severity || 'unknown').toUpperCase()));
    card.append(header);
    const location = finding.location || {};
    if (location.path || location.line) {
      card.append(el('p', '', `Konum: ${location.path || 'artifact'}${location.line ? `:${location.line}` : ''}`));
    }
    const limits = Array.isArray(finding.limitations) ? finding.limitations : [];
    if (limits.length) {
      const list = el('ul');
      limits.forEach(value => list.append(el('li', '', value)));
      card.append(list);
    }
    card.append(el('div', 'hash', `Finding ref: ${finding.finding_ref || '—'} · Güven: ${finding.confidence || '—'}`));
    return card;
  }

  function renderAnalysis(payload) {
    const analysis = payload.analysis || {};
    const summary = analysis.summary || {};
    const report = analysis.report || {};
    const decision = String(summary.decision || 'review');
    const decisionNode = document.getElementById('decision');
    decisionNode.className = `decision ${decision}`;
    document.getElementById('decision-label').textContent = decisionLabels[decision] || decision.toUpperCase();
    document.getElementById('action').textContent = summary.recommended_action || 'Bulguları doğrula.';
    document.getElementById('m-total').textContent = Number(summary.finding_count || 0).toLocaleString('tr-TR');
    document.getElementById('m-critical').textContent = Number(summary.critical_count || 0).toLocaleString('tr-TR');
    document.getElementById('m-high').textContent = Number(summary.high_count || 0).toLocaleString('tr-TR');
    document.getElementById('m-medium').textContent = Number(summary.medium_count || 0).toLocaleString('tr-TR');
    document.getElementById('m-low').textContent = Number(summary.low_count || 0).toLocaleString('tr-TR');
    document.getElementById('report-hash').textContent = summary.report_hash || report.report_hash || '—';
    const findings = Array.isArray(report.findings) ? report.findings : [];
    findingsNode.replaceChildren(...(findings.length ? findings.map(renderFinding) : [el('div', 'finding', 'Bu detector sürümünde statik kural tetiklenmedi. Bu sonuç güvenlik garantisi değildir.') ]));
    result.classList.add('show');
    result.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  artifactType.addEventListener('change', () => {
    hint.textContent = artifactType.value === 'source_bundle'
      ? 'Örnek: {"programs/lib.rs":"pub fn transfer(...) { ... }"}'
      : 'Geçerli JSON nesnesi yapıştır.';
  });

  document.getElementById('sample').addEventListener('click', () => {
    artifactType.value = 'source_bundle';
    programID.value = programID.value || 'ExampleProgram111111111111111111111111111111';
    content.value = JSON.stringify({
      'programs/example/src/lib.rs': "use solana_program::program::invoke_unchecked;\npub fn transfer(ctx: Context<Transfer>) -> Result<()> {\n    unsafe { invoke_unchecked(&instruction, &accounts)?; }\n    Ok(())\n}"
    }, null, 2);
    hint.textContent = 'Örnek yalnız detector akışını göstermek içindir; mainnet programı değildir.';
  });

  form.addEventListener('submit', async event => {
    event.preventDefault();
    runButton.disabled = true;
    result.classList.remove('show');
    try {
      const raw = validateArtifact();
      setStatus('Private artifact kaydediliyor…');
      const stored = await request('/api/v1/defense/artifacts', {
        program_id: programID.value.trim(), network: 'solana-mainnet', artifact_type: artifactType.value,
        source_commit: sourceCommit.value.trim(), content_encoding: 'json', content: raw,
        trust_level: 'unverified', verified: false, metadata: { submitted_via: 'program-audit' }
      });
      const ref = stored.artifact?.artifact_ref;
      if (!ref) throw new Error('Artifact referansı üretilmedi.');
      setStatus(`Artifact ${ref} kaydedildi. Deterministik analiz çalışıyor…`);
      const analyzed = await request('/api/v1/defense/lab', { action: 'analyze', artifact_ref: ref });
      renderAnalysis(analyzed);
      setStatus(`Analiz tamamlandı · ${analyzed.analysis?.summary?.run_ref || ref}`);
    } catch (error) {
      if (error?.status === 401) setStatus('Oturum gerekli. Giriş yaptıktan sonra yeniden dene.', true);
      else setStatus(String(error?.message || 'Analiz başarısız oldu.'), true);
    } finally {
      runButton.disabled = false;
    }
  });
})();
