(() => {
  const script = document.currentScript;
  if (!script) return;
  const key = (script.dataset.tradepiKey || '').trim();
  if (!key) {
    console.error('TradePI Agent: data-tradepi-key is required');
    return;
  }
  const apiOrigin = new URL(script.src, document.baseURI).origin;
  const title = (script.dataset.tradepiTitle || 'Sales assistant').trim();
  const storageKey = 'tradepi-agent-user:' + key;
  let userID = localStorage.getItem(storageKey);
  if (!userID) {
    userID = (globalThis.crypto && crypto.randomUUID) ? crypto.randomUUID() : 'web-' + Date.now() + '-' + Math.random().toString(36).slice(2);
    localStorage.setItem(storageKey, userID);
  }

  const style = document.createElement('style');
  style.textContent = `
    .tp-agent-launch{position:fixed;right:20px;bottom:20px;z-index:2147483000;border:0;border-radius:999px;padding:14px 18px;background:#111827;color:#fff;font:600 14px system-ui;box-shadow:0 10px 30px #0004;cursor:pointer}
    .tp-agent-panel{position:fixed;right:20px;bottom:76px;z-index:2147483000;width:min(380px,calc(100vw - 32px));height:min(560px,calc(100vh - 110px));display:none;flex-direction:column;background:#0b0d12;color:#f8fafc;border:1px solid #283244;border-radius:18px;box-shadow:0 24px 80px #0008;overflow:hidden;font-family:system-ui}
    .tp-agent-panel[data-open=true]{display:flex}.tp-agent-head{padding:16px 18px;border-bottom:1px solid #232b39;font-weight:700}.tp-agent-msgs{flex:1;overflow:auto;padding:14px;display:flex;flex-direction:column;gap:10px}.tp-agent-msg{max-width:85%;padding:10px 12px;border-radius:13px;white-space:pre-wrap;line-height:1.4;font-size:14px}.tp-agent-user{align-self:flex-end;background:#1f2937}.tp-agent-bot{align-self:flex-start;background:#151b26;border:1px solid #252d3a}.tp-agent-form{display:flex;gap:8px;padding:12px;border-top:1px solid #232b39}.tp-agent-input{flex:1;min-width:0;border:1px solid #303a4a;border-radius:11px;background:#101620;color:#fff;padding:11px}.tp-agent-send{border:0;border-radius:11px;background:#e5e7eb;color:#111827;padding:10px 14px;font-weight:700;cursor:pointer}.tp-agent-send:disabled{opacity:.5;cursor:default}.tp-agent-note{font-size:11px;color:#8b96a7;padding:0 14px 10px}
  `;
  document.head.appendChild(style);

  const launch = document.createElement('button');
  launch.className = 'tp-agent-launch';
  launch.type = 'button';
  launch.textContent = 'Chat';

  const panel = document.createElement('section');
  panel.className = 'tp-agent-panel';
  panel.dataset.open = 'false';
  panel.innerHTML = `<div class="tp-agent-head"></div><div class="tp-agent-msgs"></div><form class="tp-agent-form"><input class="tp-agent-input" maxlength="8000" autocomplete="off" placeholder="Type your message…"><button class="tp-agent-send" type="submit">Send</button></form><div class="tp-agent-note">Powered by TradePI AI Agents</div>`;
  panel.querySelector('.tp-agent-head').textContent = title;
  const messages = panel.querySelector('.tp-agent-msgs');
  const form = panel.querySelector('.tp-agent-form');
  const input = panel.querySelector('.tp-agent-input');
  const send = panel.querySelector('.tp-agent-send');

  function addMessage(text, who) {
    const node = document.createElement('div');
    node.className = 'tp-agent-msg ' + (who === 'user' ? 'tp-agent-user' : 'tp-agent-bot');
    node.textContent = text;
    messages.appendChild(node);
    messages.scrollTop = messages.scrollHeight;
  }

  launch.addEventListener('click', () => {
    const open = panel.dataset.open === 'true';
    panel.dataset.open = String(!open);
    launch.textContent = open ? 'Chat' : 'Close';
    if (!open) input.focus();
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const text = input.value.trim();
    if (!text || send.disabled) return;
    input.value = '';
    addMessage(text, 'user');
    send.disabled = true;
    try {
      const response = await fetch(apiOrigin + '/api/agents/chat?key=' + encodeURIComponent(key), {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({user_id: userID, text})
      });
      if (!response.ok) throw new Error('request failed');
      const data = await response.json();
      addMessage(data.reply || 'I could not produce a verified answer.', 'bot');
    } catch (_) {
      addMessage('The sales assistant is temporarily unavailable. Please try again.', 'bot');
    } finally {
      send.disabled = false;
      input.focus();
    }
  });

  document.body.append(panel, launch);
})();
