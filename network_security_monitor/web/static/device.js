'use strict';
(() => {
  const form = document.getElementById('device-review');
  if (!form) return;
  const button = document.getElementById('save-review');
  const feedback = document.getElementById('review-feedback');
  button.disabled = false;
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (button.disabled) return;
    button.disabled = true;
    feedback.textContent = 'Saving review…';
    try {
      const response = await fetch(form.dataset.endpoint, {
        method: 'PATCH',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.content || ''},
        body: JSON.stringify(Object.fromEntries(new FormData(form))),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.message || (response.status === 403 ? 'Your role cannot update device reviews.' : 'Could not save the review. Please retry.'));
      document.getElementById('current-review-status').textContent = payload.status;
      feedback.textContent = 'Review saved.';
    } catch (error) {
      feedback.textContent = error.message || 'Could not save the review. Please retry.';
    } finally {
      button.disabled = false;
    }
  });
})();
