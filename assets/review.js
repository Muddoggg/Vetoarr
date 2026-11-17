(() => {
  'use strict';
  const form = document.getElementById('confirm-selection-form');
  if (!form) return;
  const key = 'vetoarr:selected:' + form.dataset.selectionUser;
  const dialog = document.getElementById('review-dialog');
  if (dialog && typeof dialog.showModal === 'function') {
    dialog.removeAttribute('open');
    dialog.showModal();
    dialog.addEventListener('cancel', event => {
      event.preventDefault();
      window.location.assign('/');
    });
  }
  const list = document.getElementById('confirm-items');
  const count = document.getElementById('confirm-count');
  const submit = document.getElementById('confirm-submit');
  function update() {
    const remaining = list.querySelectorAll('[data-confirm-item]').length;
    count.textContent = String(remaining);
    submit.disabled = remaining === 0;
  }
  list.addEventListener('click', event => {
    const button = event.target.closest('button[data-remove-id]');
    if (!button) return;
    const row = button.closest('[data-confirm-item]');
    if (!row) return;
    row.remove();
    try {
      const data = JSON.parse(sessionStorage.getItem(key) || '[]');
      if (Array.isArray(data))
        sessionStorage.setItem(key, JSON.stringify(data.filter(x => x.id !== button.dataset.removeId)));
    } catch (_) {}
    update();
  });
  form.addEventListener('submit', event => {
    if (!list.querySelector('[data-confirm-item]')) event.preventDefault();
    else submit.disabled = true;
  });
  update();
})();