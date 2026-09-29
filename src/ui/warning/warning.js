/**
 * Warning Page Logic
 * Parses URL params, displays threat evidence, handles bypass.
 * @module warning
 */

document.addEventListener('DOMContentLoaded', () => {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get('url') || 'Unknown URL';
  const score = params.get('score') || '80';
  const reason = params.get('reason') || 'High risk phishing threat detected.';

  function escapeHTML(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  const numScore = parseInt(score, 10) || 0;
  const classificationEl = document.getElementById('classification');
  if (classificationEl) {
    classificationEl.textContent = numScore >= 80 ? 'Critical' : numScore >= 60 ? 'High Risk' : numScore >= 40 ? 'Suspicious' : 'Low';
  }

  document.getElementById('score-val').textContent = score;
  document.getElementById('target-url').textContent = targetUrl;
  
  // URLSearchParams automatically decodes query params; escapeHTML prevents XSS without throwing URIError
  document.getElementById('reasons-list').innerHTML = escapeHTML(reason);

  document.getElementById('btn-back')?.addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close();
    }
  });

  document.getElementById('btn-proceed')?.addEventListener('click', () => {
    if (confirm('This site may steal your personal information. Continue anyway?')) {
      try {
        const hostname = new URL(targetUrl).hostname;
        if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
          chrome.runtime.sendMessage({ action: 'ALLOW_SESSION_DOMAIN', domain: hostname }, () => {
            window.location.href = targetUrl;
          });
        } else {
          window.location.href = targetUrl;
        }
      } catch {
        window.location.href = targetUrl;
      }
    }
  });
});
