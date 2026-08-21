(function () {
  'use strict';

  const allowedPlans = new Set(['starter', 'professional', 'enterprise']);

  async function readJSON(response) {
    const text = await response.text().catch(() => '');
    if (!text) return {};
    try { return JSON.parse(text); } catch { return { error: text }; }
  }

  async function open(plan) {
    plan = String(plan || '').trim().toLowerCase();
    if (!allowedPlans.has(plan)) throw new Error('Unknown Koschei plan.');

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
      button.addEventListener('click', async (event) => {
        event.preventDefault();
        if (button.dataset.checkoutBusy === '1') return;
        const plan = button.getAttribute('data-koschei-checkout');
        const original = button.textContent;
        button.dataset.checkoutBusy = '1';
        button.setAttribute('aria-busy', 'true');
        button.textContent = 'Opening secure checkout…';
        try {
          await open(plan);
        } catch (error) {
          button.textContent = original;
          button.removeAttribute('aria-busy');
          button.dataset.checkoutBusy = '0';
          const target = document.getElementById('checkoutStatus');
          if (target) {
            target.textContent = error && error.message ? error.message : 'Checkout is temporarily unavailable.';
            target.className = 'pricing-policy-status warn';
          }
        }
      });
    });
  }

  window.KoscheiCheckout = Object.freeze({ enabled: true, provider: 'paddle', open });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bindButtons);
  else bindButtons();
})();