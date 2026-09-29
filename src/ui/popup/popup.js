/**
 * Popup Interface Logic
 * Fetches current active tab security status and updates popup elements.
 * @module popup
 */

document.addEventListener('DOMContentLoaded', async () => {
  const scoreNum = document.getElementById('score-number');
  const headerStatus = document.getElementById('header-status');
  const headerStatusText = document.getElementById('header-status-text');
  const ringProgress = document.getElementById('ring-progress');
  const currentUrl = document.getElementById('current-url');
  const findingsList = document.getElementById('findings-list');
  const btnRescan = document.getElementById('btn-rescan');
  const btnDashboard = document.getElementById('btn-dashboard');

  // Ring circumference for r=44
  const CIRC = 2 * Math.PI * 44;

  let currentTabId = null;

  if (typeof chrome !== 'undefined' && chrome.tabs) {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs[0]) {
        currentTabId = tabs[0].id;
        if (tabs[0].url) {
          try {
            const urlObj = new URL(tabs[0].url);
            currentUrl.textContent = urlObj.hostname;
          } catch {
            currentUrl.textContent = tabs[0].url;
          }
        }
        fetchSecurityStatus(currentTabId);
      }
    } catch {}
  }

  btnRescan?.addEventListener('click', () => {
    if (currentTabId && typeof chrome !== 'undefined' && chrome.tabs) {
      chrome.tabs.sendMessage(currentTabId, { action: 'TRIGGER_DOM_SCAN' }, () => {
        if (chrome.runtime.lastError) { /* ignore */ }
      });
      headerStatusText.textContent = 'Scanning';
      setTimeout(() => fetchSecurityStatus(currentTabId), 800);
    }
  });

  btnDashboard?.addEventListener('click', () => {
    if (typeof chrome !== 'undefined' && chrome.tabs) {
      chrome.tabs.create({ url: chrome.runtime.getURL('src/ui/dashboard/dashboard.html') });
    }
  });

  function fetchSecurityStatus(tabId) {
    if (typeof chrome === 'undefined' || !chrome.runtime) return;
    chrome.runtime.sendMessage({ action: 'GET_TAB_SECURITY_STATUS', tabId }, (response) => {
      if (chrome.runtime.lastError) { renderSafe(); return; }
      if (response && response.result) {
        renderStatus(response.result);
      } else {
        renderSafe();
      }
    });
  }

  function escapeHTML(str) {
    if (!str) return '';
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
  }

  function setRing(score) {
    const offset = CIRC - (score / 100) * CIRC;
    ringProgress.style.strokeDashoffset = offset;

    let gradId = 'url(#safeGrad)';
    if (score >= 80) gradId = 'url(#dangerGrad)';
    else if (score >= 40) gradId = 'url(#warnGrad)';
    
    ringProgress.style.stroke = gradId;
    
    // Add glow effect if high risk
    if (score >= 60) {
      ringProgress.style.filter = 'url(#glow)';
    } else {
      ringProgress.style.filter = 'none';
    }
  }

  function setStatus(label, type) {
    headerStatusText.textContent = label;
    headerStatus.className = `status-badge ${type}`;
  }

  function setSignal(id, flagged) {
    const statusText = document.getElementById(id + '-status');
    const bar = document.getElementById(id + '-bar');
    
    const type = flagged ? 'danger' : 'safe';
    
    if (statusText) {
      statusText.textContent = flagged ? 'FLAGGED' : 'OK';
      statusText.className = `signal-status ${type}`;
    }
    
    if (bar) {
      bar.className = `signal-bar-fill ${type}`;
      bar.style.width = flagged ? '100%' : '100%';
    }
  }

  function renderSafe() {
    scoreNum.textContent = '0';
    setRing(0);
    setStatus('Safe', 'safe');
    ['url','form','dom','behavior'].forEach(id => setSignal(id, false));
    findingsList.innerHTML = '<div class="finding-empty">No suspicious activity detected.</div>';
  }

  function renderStatus(result) {
    const score = result.riskScore || 0;
    
    // Animate score counter
    let currentScore = 0;
    const duration = 1000;
    const startTime = performance.now();
    
    const animateScore = (currentTime) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      
      // Easing function (easeOutQuart)
      const ease = 1 - Math.pow(1 - progress, 4);
      currentScore = Math.floor(score * ease);
      
      scoreNum.textContent = String(currentScore);
      
      if (progress < 1) {
        requestAnimationFrame(animateScore);
      } else {
        scoreNum.textContent = String(score);
      }
    };
    
    requestAnimationFrame(animateScore);
    setRing(score);

    const type = score >= 60 ? 'danger' : score >= 40 ? 'warn' : 'safe';
    const label = result.classification || (score >= 80 ? 'Critical' : score >= 60 ? 'High Risk' : score >= 40 ? 'Suspicious' : 'Safe');
    setStatus(label, type);

    const triggered = result.detectorsTriggered || [];
    setSignal('url',  triggered.some(d => ['URLDetector','ReputationEngine','BrandImpersonationDetector'].includes(d)));
    setSignal('form', triggered.includes('FormDetector'));
    setSignal('dom',  triggered.includes('DOMDetector'));
    setSignal('behavior', triggered.includes('BehaviorDetector'));

    if (score > 0 && result.reasons && result.reasons.length > 0 && result.classification !== 'SAFE') {
      const strokeColor = score >= 60 ? 'var(--danger)' : 'var(--warn)';
      findingsList.innerHTML = result.reasons.map(r =>
        `<div class="finding-item">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${strokeColor}" stroke-width="2" style="flex-shrink: 0; margin-top: 2px;">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="8" x2="12" y2="12"></line>
            <line x1="12" y1="16" x2="12.01" y2="16"></line>
          </svg>
          <span>${escapeHTML(r)}</span>
        </div>`
      ).join('');
    } else {
      findingsList.innerHTML = '<div class="finding-empty">No suspicious activity detected.</div>';
    }
  }
});
