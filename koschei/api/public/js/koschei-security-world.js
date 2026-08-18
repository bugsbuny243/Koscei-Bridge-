(() => {
  const canvas = document.querySelector('[data-koschei-security-world]');
  if (!canvas) return;

  const ctx = canvas.getContext('2d', { alpha: true });
  if (!ctx) return;

  const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const nodes = [
    { id: 'ETH', x: .14, y: .24, r: 5 },
    { id: 'SOL', x: .14, y: .74, r: 5 },
    { id: 'SAFE', x: .39, y: .25, r: 6 },
    { id: 'PAYLOAD', x: .40, y: .52, r: 5 },
    { id: 'FORK', x: .62, y: .45, r: 6 },
    { id: 'PROOF', x: .80, y: .25, r: 7 },
    { id: 'SHIELD', x: .80, y: .72, r: 7 },
    { id: 'SIGN', x: .94, y: .49, r: 6 }
  ];
  const links = [
    ['ETH','SAFE'], ['SAFE','PAYLOAD'], ['SOL','PAYLOAD'], ['PAYLOAD','FORK'],
    ['FORK','PROOF'], ['FORK','SHIELD'], ['PROOF','SIGN'], ['SHIELD','SIGN']
  ];

  let width = 0, height = 0, dpr = 1, start = performance.now();

  function resize() {
    const box = canvas.getBoundingClientRect();
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = Math.max(320, box.width);
    height = Math.max(300, box.height);
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function point(node) { return { x: node.x * width, y: node.y * height }; }
  function byId(id) { return nodes.find(n => n.id === id); }

  function drawGrid(t) {
    ctx.save();
    ctx.strokeStyle = 'rgba(88,245,190,.055)';
    ctx.lineWidth = 1;
    const gap = 24;
    const drift = reduceMotion ? 0 : (t * .008) % gap;
    for (let x = -gap + drift; x < width + gap; x += gap) {
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke();
    }
    for (let y = -gap + drift; y < height + gap; y += gap) {
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke();
    }
    ctx.restore();
  }

  function drawLink(a, b, phase) {
    const pa = point(a), pb = point(b);
    ctx.strokeStyle = 'rgba(92,225,255,.22)';
    ctx.lineWidth = 1.2;
    ctx.beginPath(); ctx.moveTo(pa.x, pa.y); ctx.lineTo(pb.x, pb.y); ctx.stroke();

    const p = reduceMotion ? .5 : ((phase % 1) + 1) % 1;
    const x = pa.x + (pb.x - pa.x) * p;
    const y = pa.y + (pb.y - pa.y) * p;
    const g = ctx.createRadialGradient(x, y, 0, x, y, 11);
    g.addColorStop(0, 'rgba(111,247,202,.95)');
    g.addColorStop(1, 'rgba(111,247,202,0)');
    ctx.fillStyle = g; ctx.beginPath(); ctx.arc(x, y, 11, 0, Math.PI * 2); ctx.fill();
  }

  function drawNode(node, t) {
    const p = point(node);
    const pulse = reduceMotion ? 0 : Math.sin(t * .0025 + node.x * 9) * 2;
    const glow = ctx.createRadialGradient(p.x, p.y, 1, p.x, p.y, 24 + pulse);
    glow.addColorStop(0, 'rgba(73,246,183,.55)');
    glow.addColorStop(1, 'rgba(73,246,183,0)');
    ctx.fillStyle = glow; ctx.beginPath(); ctx.arc(p.x, p.y, 24 + pulse, 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = '#7dffd0'; ctx.beginPath(); ctx.arc(p.x, p.y, node.r, 0, Math.PI * 2); ctx.fill();
    ctx.font = '700 10px ui-monospace, SFMono-Regular, Menlo, monospace';
    ctx.fillStyle = 'rgba(213,255,241,.88)';
    ctx.fillText(node.id, p.x + 10, p.y - 9);
  }

  function drawSentinel(t) {
    const target = point(byId('FORK'));
    const angle = reduceMotion ? .7 : t * .0007;
    const radius = 42;
    const x = target.x + Math.cos(angle) * radius;
    const y = target.y + Math.sin(angle) * radius;
    ctx.strokeStyle = 'rgba(255,214,102,.38)';
    ctx.setLineDash([3, 5]);
    ctx.beginPath(); ctx.arc(target.x, target.y, radius, 0, Math.PI * 2); ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = '#ffd66d'; ctx.beginPath(); ctx.arc(x, y, 4.5, 0, Math.PI * 2); ctx.fill();
    ctx.font = '800 9px ui-monospace, SFMono-Regular, Menlo, monospace';
    ctx.fillStyle = 'rgba(255,225,145,.9)'; ctx.fillText('SENTINEL', x + 8, y + 3);
  }

  function frame(now) {
    const t = now - start;
    ctx.clearRect(0, 0, width, height);
    drawGrid(t);
    links.forEach((pair, i) => drawLink(byId(pair[0]), byId(pair[1]), t * .00018 + i * .13));
    nodes.forEach(n => drawNode(n, t));
    drawSentinel(t);
    if (!reduceMotion) requestAnimationFrame(frame);
  }

  resize();
  window.addEventListener('resize', resize, { passive: true });
  if (reduceMotion) frame(performance.now()); else requestAnimationFrame(frame);
})();
