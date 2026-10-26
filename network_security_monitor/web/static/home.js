'use strict';
(() => {
  const button = document.getElementById('copy-demo');
  const feedback = document.getElementById('copy-feedback');
  if (!navigator.clipboard?.writeText) return;
  button.hidden = false;
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(document.getElementById('demo-command').textContent);
      feedback.textContent = 'Command copied. Run it in a terminal on your monitoring host.';
    } catch (_) {
      feedback.textContent = 'Could not copy. Select the command above and copy it manually.';
    }
  });
})();
