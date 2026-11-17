'use strict';
(() => {
  const form = document.getElementById('plex-login-form');
  const feedback = document.getElementById('plex-login-feedback');
  if (!form || !feedback) return;
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = form.querySelector('button');
    button.disabled = true;
    feedback.textContent = 'Connecting to Plex...';
    try {
      const response = await fetch(form.action, {
        method: 'POST',
        credentials: 'same-origin',
        redirect: 'error',
        headers: { Accept: 'application/json' },
        body: new FormData(form)
      });
      if (!response.ok || !response.headers.get('content-type')?.includes('application/json')) {
        throw new Error('Plex sign-in could not be started.');
      }
      const data = await response.json();
      const url = new URL(data.url);
      if (url.protocol !== 'https:' || url.hostname !== 'app.plex.tv' || url.pathname !== '/auth') {
        throw new Error('Unexpected authentication URL.');
      }
      window.location.assign(data.url);
    } catch (_) {
      feedback.textContent = 'Unable to start Plex sign-in. Try again.';
      button.disabled = false;
    }
  });
})();
