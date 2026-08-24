(function () {
  'use strict';

  const allowedPlans = new Set(['starter', 'professional', 'enterprise']);
  let catalogState = null;

  async function readJSON(response) {
    const text = await response.text().catch(() => '');
    if (!text) return {};
    try { return JSON.parse(text); } catch { return { error: text }; }
  }

  function planReady(payload, plan) {
    const paddle = payload && payload.paddle && typeof payload.paddle === 'object' ? payload.paddle : {};
    return paddle[plan + '_ready'] === true;
  }

  function setStatus(message, warning) {
    const target = document.getElementById('checkoutStatus');
    if (!target) return;
    target.textContent = message;
    target.className = 'pricing-policy-status ' + (warning ? 'warn' : 'neutral');
  }

  function applyCatalogState(response, payload) {
    const paddle = payload && payload.paddle && typeof payload.paddle === 'object' ? payload.paddle : {};
    const configuredPlanCount = Number(paddle.configured_plan_count || 0);
    const readyPlans = [];

    document.querySelectorAll('[data-koschei-checkout]').forEach((button) => {
      const plan = String(button.getAttribute('data-koschei-checkout') || '').trim().toLowerCase();
      const ready = allowedPlans.has(plan) && planReady(payload, plan);
      button.dataset.checkoutReady = ready ? '1' : '0';
      button.setAttribute('aria-disabled', ready ? 'false' : 'true');
      if (ready) {
        readyPlans.push(plan);
        button.removeAttribute('title');
      } else {
        button.setAttribute('title', 'Paddle checkout for this plan is not active yet.');
      }
    });

    if (response.ok && readyPlans.length === allowedPlans.size) {
      setStatus('Paid plans are recurring monthly subscriptions: Starter $299, Professional $999, Enterprise $4,999. Applicable taxes may be calculated at checkout. Cancel before renewal to stop future billing.', false);
      return;
    }

    if (configuredPlanCount === 0) {
      setStatus('Paddle catalog is not active yet. Starter, Professional and Enterprise subscription products/prices must be created and their price IDs configured before checkout can open.', true);
      return;
    }

    setStatus('Paddle checkout setup is incomplete: ' + readyPlans.length + '/3 plans are checkout-ready. Unready purchase buttons remain blocked until the catalog and webhook configuration are complete.', true);
  }

  async function loadCatalogState() {
    let response;
    let payload;
    try {
      response = await fetch('/paddle/public-config', {
        method: 'GET',
        credentials: 'same-origin',
        headers: { 'Accept': 'application/json' },
      });
      payload = await readJSON(response);
    } catch {
      response = { ok: false };
      payload = {};
    }
    catalogState = { response, payload };
    applyCatalogState(response, payload);
    return catalogState;
  }

  async function open(plan) {
    plan = String(plan || '').trim().toLowerCase();
    if (!allowedPlans.has(plan)) throw new Error('Unknown Koschei plan.');

    const state = catalogState || await loadCatalogState();
    if (!planReady(state.payload, plan)) {
      throw new Error('Paddle checkout for ' + plan + ' is not active yet.');
    }

    const response = await fetch('/api/paddle/checkout', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ plan }),
    });
    const payload = await readJSON(response);
    if (response.status === 401) {
      const next = encodeURIComponent('/pricing');
      window.location.assign('/login.html?next=' + next);
      return;
    }
    if (!response.ok) {
      if (payload.error === 'paddle_checkout_failed') {
        const providerStatus = Number(payload.provider_status || 0);
        if (providerStatus > 0) {
          throw new Error('Paddle rejected the checkout request (provider HTTP ' + providerStatus + ').');
        }
      }
      throw new Error(String(payload.message || payload.error || 'Checkout is temporarily unavailable.'));
    }
    const checkoutURL = String(payload.checkout_url || '').trim();
    let parsed;
    try { parsed = new URL(checkoutURL); } catch { throw new Error('Checkout URL is invalid.'); }
    if (parsed.protocol !== 'https:') throw new Error('Checkout URL is not secure.');
    window.location.assign(parsed.href);
  }

  function bindButtons() {
    document.querySelectorAll('[data-koschei-checkout]').forEach((button) => {
      button.dataset.checkoutReady = '0';
      button.setAttribute('aria-disabled', 'true');
      button.addEventListener('click', async (event) => {
        event.preventDefault();
        if (button.dataset.checkoutBusy === '1') return;
        const plan = button.getAttribute('data-koschei-checkout');
        const original = button.textContent;
        button.dataset.checkoutBusy = '1';
        button.setAttribute('aria-busy', 'true');
        button.textContent = 'Checking secure checkout…';
        try {
          await open(plan);
        } catch (error) {
          button.textContent = original;
          button.removeAttribute('aria-busy');
          button.dataset.checkoutBusy = '0';
          setStatus(error && error.message ? error.message : 'Checkout is temporarily unavailable.', true);
        }
      });
    });
    void loadCatalogState();
  }

  window.KoscheiCheckout = Object.freeze({ enabled: true, provider: 'paddle', open, refresh: loadCatalogState });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bindButtons);
  else bindButtons();
})();