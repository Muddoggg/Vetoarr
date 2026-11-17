'use strict';
(() => {
  const feedback = document.getElementById('discord-feedback');
  const webhook = document.getElementById('webhook');
  const enabled = document.getElementById('discord-enabled');
  const marker = document.getElementById('discord-configured');
  const save = document.querySelector('[data-discord-ajax="save"]');
  const test = document.querySelector('[data-discord-ajax="test"]');
  const remove = document.querySelector('[data-discord-ajax="remove"]');
  if (!feedback || !webhook || !enabled || !marker || !save || !test || !remove) return;
  const removeButton = remove.querySelector('button');
  const csrf = save.querySelector('[name="csrf"]').value;
  let configured = marker.textContent.includes('saved') && !marker.textContent.includes('not saved');

  async function submit(form, extra, lockFields = false) {
    const button = form.querySelector('button[type="submit"]');
    if (button) button.disabled = true;
    feedback.textContent = 'Working...';
    feedback.classList.remove('error');
    let previousDisabled;
    try {
      const data = new FormData(form);
      if (extra) Object.entries(extra).forEach(([key, value]) => data.set(key, value));
      if (lockFields) {
        previousDisabled = [webhook.disabled, enabled.disabled, removeButton.disabled];
        webhook.disabled = enabled.disabled = removeButton.disabled = true;
      }
      const response = await fetch(form.action, {
        method: 'POST', credentials: 'same-origin', redirect: 'error',
        headers: { Accept: 'application/json' }, body: data
      });
      if (!response.headers.get('content-type')?.includes('application/json')) {
        throw new Error('Your session may have expired. Reload the page and sign in again.');
      }
      const result = await response.json();
      feedback.textContent = result.message || (response.ok ? 'Saved.' : 'Request failed.');
      feedback.classList.toggle('error', !response.ok || !result.ok);
      return response.ok && result.ok;
    } catch (_) {
      feedback.textContent = 'Could not reach Vetoarr. Check your connection and try again.';
      feedback.classList.add('error');
      return false;
    } finally {
      if (previousDisabled) {
        [webhook.disabled, enabled.disabled, removeButton.disabled] = previousDisabled;
      }
      if (button) button.disabled = false;
    }
  }
  save.addEventListener('submit', async (event) => {
    event.preventDefault();
    const newWebhook = webhook.value.trim();
    if (await submit(save, undefined, true)) {
      if (newWebhook) {
        configured = true;
        enabled.checked = true;
        marker.textContent = '(saved)';
        removeButton.disabled = false;
        webhook.value = '';
        webhook.placeholder = 'Leave blank to keep saved webhook';
      }
    }
  });
  test.addEventListener('submit', (event) => {
    event.preventDefault();
    submit(test, { webhook: webhook.value.trim(), csrf });
  });
  remove.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (await submit(remove)) {
      configured = false;
      enabled.checked = true;
      marker.textContent = '(not saved)';
      webhook.value = '';
      webhook.placeholder = 'Paste Discord webhook URL';
      removeButton.disabled = true;
    }
  });
})();
