(() => {
  'use strict';
  const root = document.querySelector('[data-selection-user]');
  if (!root) return;
  const key = 'vetoarr:selected:' + root.dataset.selectionUser;
  const limit = 20;
  const count = document.getElementById('selected-count');
  const tray = document.getElementById('selected-items');
  const send = document.getElementById('review-selections');
  const form = document.getElementById('selection-review-form');
  const status = document.getElementById('selection-status');
  let selected = new Map();
  try {
    const data = JSON.parse(sessionStorage.getItem(key) || '[]');
    if (Array.isArray(data)) data.slice(0, limit).forEach(x => {
      if (x && /^[0-9]{1,18}$/.test(x.id) && typeof x.title === 'string')
        selected.set(x.id, {id:x.id,title:x.title.slice(0,180),type:x.type});
    });
  } catch (_) { selected = new Map(); }
  if (new URLSearchParams(location.search).get('submitted') === '1') selected.clear();
  const save = () => { try { sessionStorage.setItem(key, JSON.stringify([...selected.values()])); } catch (_) {} };
  function render() {
    count.textContent = String(selected.size);
    send.disabled = selected.size === 0;
    tray.replaceChildren();
    selected.forEach(item => {
      const line = document.createElement('div');
      line.className = 'line';
      const name = document.createElement('span');
      name.textContent = item.title;
      const remove = document.createElement('button');
      remove.type = 'button';
      remove.textContent = 'Remove';
      remove.setAttribute('aria-label', 'Remove ' + item.title);
      remove.addEventListener('click', () => {
        selected.delete(item.id);
        save(); render();
      });
      line.append(name, remove);
      tray.append(line);
    });
    document.querySelectorAll('input[data-media-id]').forEach(input => {
      input.checked = selected.has(input.dataset.mediaId);
    });
    save();
  }
  document.addEventListener('change', event => {
    const input = event.target.closest('input[data-media-id]');
    if (!input) return;
    const id = input.dataset.mediaId;
    if (input.checked && !selected.has(id)) {
      if (selected.size >= limit) {
        input.checked = false;
        status.textContent = 'Choose up to ' + limit + ' titles per submission.';
        return;
      }
      selected.set(id, {id, title:input.dataset.mediaTitle, type:input.dataset.mediaType});
    } else if (!input.checked) selected.delete(id);
    status.textContent = '';
    render();
  });
  form.addEventListener('submit', event => {
    form.querySelectorAll('input[name="plex_ids"]').forEach(x => x.remove());
    selected.forEach(item => {
      const hidden = document.createElement('input');
      hidden.type = 'hidden';
      hidden.name = 'plex_ids';
      hidden.value = item.id;
      form.append(hidden);
    });
    if (!selected.size) event.preventDefault();
  });
  const list = document.getElementById('browse-items');
  if (list) {
    const section = list.dataset.library;
    let offset = Number(list.dataset.nextOffset);
    let more = list.dataset.hasMore === 'true';
    let loading = false;
    const loadButton = document.getElementById('load-more');
    const sentinel = document.getElementById('load-sentinel');
    function appendItem(item) {
      if (!item || !/^[0-9]{1,18}$/.test(item.id)) return;
      if (list.querySelector('input[data-media-id="' + item.id + '"]')) return;
      const label = document.createElement('label');
      label.className = 'line';
      const cb = document.createElement('input');
      cb.type = 'checkbox'; cb.dataset.mediaId = item.id;
      cb.dataset.mediaTitle = item.title;
      cb.dataset.mediaType = item.type;
      cb.checked = selected.has(item.id);
      const body = document.createElement('span');
      const strong = document.createElement('strong');
      strong.textContent = item.title;
      const small = document.createElement('small');
      small.textContent = (item.year || '') + ' · ' + item.type;
      body.append(strong, small);
      label.append(cb, body);
      list.append(label);
    }
    async function loadMore() {
      if (!more || loading) return;
      loading = true; loadButton.disabled = true;
      status.textContent = 'Loading more titles…';
      try {
        const response = await fetch('/api/library/' + encodeURIComponent(section) + '/items?offset=' + offset,
                                     {headers:{Accept:'application/json'},credentials:'same-origin'});
        if (!response.ok) throw new Error('Library request failed');
        const data = await response.json();
        if (!Array.isArray(data.items) || !Number.isInteger(data.next_offset)) throw new Error('Bad response');
        data.items.forEach(appendItem);
        offset = data.next_offset;
        more = data.has_more === true;
        loadButton.hidden = !more;
        status.textContent = '';
      } catch (_) {
        status.textContent = 'Could not load more titles. Try again.';
      } finally { loading = false; loadButton.disabled = false; }
    }
    loadButton.addEventListener('click', loadMore);
    if (!more) loadButton.hidden = true;
    if ('IntersectionObserver' in window) {
      const observer = new IntersectionObserver(entries => {
        if (entries.some(e => e.isIntersecting)) loadMore();
      }, {rootMargin:'120px'});
      observer.observe(sentinel);
    }
  }
  render();
})();