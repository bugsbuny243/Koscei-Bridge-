(function () {
  const auth = window.KoscheiAuth;
  if (!auth || window.__koscheiAuthSessionFixInstalled) return;
  window.__koscheiAuthSessionFixInstalled = true;

  const SIGNED_OUT_KEY = 'koschei_explicitly_signed_out';
  const JWT_KEYS = ['koschei_jwt', 'koschei_token'];
  const originalInit = auth.init.bind(auth);
  const originalSignIn = auth.signIn.bind(auth);
  const originalSignUp = auth.signUp.bind(auth);

  function installBoundedAuthFetch() {
    if (window.__koscheiBoundedAPIFetchInstalled) return;
    window.__koscheiBoundedAPIFetchInstalled = true;
    const nativeFetch = window.fetch.bind(window);
    window.fetch = function (input, init = {}) {
      let url;
      try { url = new URL(typeof input === 'string' ? input : input?.url || '', window.location.origin); } catch { return nativeFetch(input, init); }
      const bounded = url.origin === window.location.origin && (url.pathname === '/health' || url.pathname.startsWith('/api/'));
      if (!bounded) return nativeFetch(input, init);
      const controller = new AbortController();
      const externalSignal = init.signal;
      let timedOut = false;
      const onExternalAbort = () => controller.abort(externalSignal?.reason);
      if (externalSignal) {
        if (externalSignal.aborted) onExternalAbort();
        else externalSignal.addEventListener('abort', onExternalAbort, { once: true });
      }
      const timeoutMs = 15000;
      const timer = window.setTimeout(() => { timedOut = true; controller.abort('koschei_api_timeout'); }, timeoutMs);
      return nativeFetch(input, { ...init, signal: controller.signal }).catch(error => {
        if (timedOut) throw new Error('DEGRADED DEPENDENCY — Koschei oturum servisi 15 saniyede yanıt vermedi.');
        throw error;
      }).finally(() => {
        window.clearTimeout(timer);
        if (externalSignal) externalSignal.removeEventListener('abort', onExternalAbort);
      });
    };
  }

  installBoundedAuthFetch();

  function clearLocalSession() {
    try {
      for (const key of JWT_KEYS) localStorage.removeItem(key);
    } catch {}
  }

  function markSignedOut() {
    try { localStorage.setItem(SIGNED_OUT_KEY, '1'); } catch {}
  }

  function clearSignedOut() {
    try { localStorage.removeItem(SIGNED_OUT_KEY); } catch {}
  }

  function explicitlySignedOut() {
    try { return localStorage.getItem(SIGNED_OUT_KEY) === '1'; } catch { return false; }
  }

  async function endNeonSession() {
    try {
      const configResponse = await fetch('/api/config', { credentials: 'same-origin' });
      const config = await configResponse.json().catch(() => ({}));
      const baseURL = String(config.neonAuthUrl || '').trim().replace(/\/+$/, '');
      if (!configResponse.ok || !baseURL) return;
      await fetch(baseURL + '/sign-out', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
    } catch {}
  }

  auth.init = async function () {
    if (explicitlySignedOut()) {
      clearLocalSession();
      return false;
    }
    return originalInit();
  };

  auth.signIn = async function (email, password) {
    clearSignedOut();
    return originalSignIn(email, password);
  };

  auth.signUp = async function (email, password) {
    clearSignedOut();
    return originalSignUp(email, password);
  };

  auth.signOut = async function () {
    markSignedOut();
    clearLocalSession();
    await endNeonSession();
    window.location.replace('/login.html?signed_out=1');
  };
})();
