(() => {
  const params = new URLSearchParams(window.location.search);
  const message = params.get('message');
  const status = params.get('status');
  const messageNode = document.getElementById('error-message');
  const statusNode = document.getElementById('error-status');

  if (messageNode && message) messageNode.textContent = message;
  if (statusNode && /^\d{3}$/.test(status || '')) {
    statusNode.textContent = `Fehlercode ${status}`;
    statusNode.hidden = false;
  }
})();
