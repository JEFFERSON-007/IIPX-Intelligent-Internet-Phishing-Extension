/**
 * Dashboard Controller
 * Minimalist dashboard logic for new UI.
 * @module dashboard
 */

document.addEventListener('DOMContentLoaded', async () => {
  const navLinks = document.querySelectorAll('.nav-item');
  const tabPanes = document.querySelectorAll('.tab-pane');
  const pageTitle = document.getElementById('page-title');
  const pageSub   = document.getElementById('page-subtitle');
  
  const valScanned = document.getElementById('val-scanned');
  const valBlocked = document.getElementById('val-blocked');
  
  const auditFeedTbody = document.getElementById('audit-feed-tbody');
  const detectorCardsContainer = document.getElementById('detector-cards-container');
  const performanceBarsList = document.getElementById('performance-bars-list');
  const globalSearch = document.getElementById('global-search');
  
  const btnExportLog = document.getElementById('btn-export-log');
  const btnClearFeed = document.getElementById('btn-clear-feed');

  const detectorsList = [
    { name: 'URLAnalysis',               priority: 1000, version: '2.1.0', avgMs: 1.8, desc: 'Evaluates unicode normalization, homographs, entropy, and typosquatting signals.' },
    { name: 'ReputationEngine',          priority: 950,  version: '2.0.4', avgMs: 0.9, desc: 'Consults offline blocklists and pluggable threat reputation providers.' },
    { name: 'FormDetector',              priority: 900,  version: '2.0.0', avgMs: 2.4, desc: 'Identifies credential harvesting, OTP, SSN, and off-screen inputs.' },
    { name: 'CertificateAnalyzer',       priority: 850,  version: '1.9.0', avgMs: 0.5, desc: 'Validates SSL/TLS transport security, scheme usage, and expired certs.' },
    { name: 'BrandImpersonation',        priority: 820,  version: '2.2.0', avgMs: 1.2, desc: 'Detects Levenshtein brand spoofing and domain impersonation attempts.' },
    { name: 'DOMIntegrity',              priority: 800,  version: '2.0.1', avgMs: 3.1, desc: 'Scans for hidden iFrames, obfuscated scripts, and clickjacking overlays.' },
    { name: 'BehaviorAnalyzer',          priority: 700,  version: '2.0.0', avgMs: 1.1, desc: 'Monitors clipboard hijacks, popup spam, auto-submits, and device APIs.' },
    { name: 'NetworkAnalyzer',           priority: 650,  version: '2.0.0', avgMs: 0.8, desc: 'Detects mixed content, insecure WebSockets, and cross-origin leakage.' },
    { name: 'DomainIntelligence',        priority: 600,  version: '1.8.5', avgMs: 0.6, desc: 'Checks offline domain age, ASN metadata, and WHOIS cache.' },
  ];

  const tabMeta = {
    overview:    { title: 'Overview',    sub: 'Real-time analysis' },
    detectors:   { title: 'Engines',     sub: 'Active modules' },
    performance: { title: 'Telemetry',   sub: 'Engine latency' },
    policy:      { title: 'Policies',    sub: 'Access rules' },
  };

  // Tab switching
  navLinks.forEach(link => {
    link.addEventListener('click', () => {
      const target = link.getAttribute('data-tab');
      navLinks.forEach(n => n.classList.remove('active'));
      tabPanes.forEach(p => p.classList.remove('active'));
      
      link.classList.add('active');
      document.getElementById(`tab-${target}`)?.classList.add('active');
      
      if (tabMeta[target]) {
        pageTitle.textContent = tabMeta[target].title;
        pageSub.textContent   = tabMeta[target].sub;
      }
    });
  });

  // Load stats
  if (typeof chrome !== 'undefined' && chrome.storage?.local) {
    chrome.storage.local.get(['phishing_detector_stats'], (data) => {
      const stats = data.phishing_detector_stats || {};
      if (valScanned) valScanned.textContent = (stats.sitesScanned || 0).toLocaleString();
      if (valBlocked) valBlocked.textContent = (stats.threatsBlocked || 0).toLocaleString();
    });
  } else {
    if (valScanned) valScanned.textContent = '1,428';
    if (valBlocked) valBlocked.textContent = '84';
  }

  // Detector cards
  function renderDetectorCards() {
    if (!detectorCardsContainer) return;
    detectorCardsContainer.innerHTML = detectorsList.map(d => `
      <div class="d-card">
        <div class="d-header">
          <span class="d-name">${d.name}</span>
          <span class="d-version">v${d.version}</span>
        </div>
        <p class="d-desc">${d.desc}</p>
        <div class="d-footer">
          <div class="d-meta">
            <div>Priority <span>${d.priority}</span></div>
            <div>Avg <span>${d.avgMs}ms</span></div>
          </div>
          <span class="badge safe">Active</span>
        </div>
      </div>
    `).join('');
  }

  // Performance bars
  function renderPerformanceMeters() {
    if (!performanceBarsList) return;
    const maxMs = 5.0;
    performanceBarsList.innerHTML = detectorsList.map(d => {
      const pct = Math.min((d.avgMs / maxMs) * 100, 100);
      return `
        <div class="perf-row">
          <div class="perf-info">
            <span class="perf-name">${d.name}</span>
            <span class="perf-val">${d.avgMs} ms</span>
          </div>
          <div class="perf-bar-bg">
            <div class="perf-bar-fill" style="width:${pct}%;"></div>
          </div>
        </div>
      `;
    }).join('');
  }

  // Audit feed
  function renderAuditFeed() {
    if (!auditFeedTbody) return;
    const logs = [
      { time: '21:52', domain: 'arnaz0n-secure-update.xyz',     score: 85, tier: 'CRITICAL', detectors: 'URL, Form',  status: 'Blocked' },
      { time: '21:48', domain: 'paypa1-account-verify.online',  score: 90, tier: 'CRITICAL', detectors: 'URL, Brand', status: 'Blocked' },
      { time: '21:40', domain: 'github.com',                     score: 0,  tier: 'SAFE',     detectors: '—',          status: 'Allowed' },
      { time: '21:32', domain: 'http-login-test.net',            score: 65, tier: 'HIGH',     detectors: 'Form, Cert', status: 'Blocked' },
      { time: '21:15', domain: 'google.com',                     score: 0,  tier: 'SAFE',     detectors: '—',          status: 'Allowed' },
    ];
    auditFeedTbody.innerHTML = logs.map(l => {
      const badgeCls = l.status === 'Blocked' ? 'danger' : 'safe';
      return `
        <tr>
          <td class="text-muted" style="font-family: var(--font-mono)">${l.time}</td>
          <td><code class="code-block">${l.domain}</code></td>
          <td style="font-family: var(--font-mono)">${l.score}/100</td>
          <td class="text-muted">${l.detectors}</td>
          <td><span class="badge ${badgeCls}">${l.status}</span></td>
        </tr>
      `;
    }).join('');
  }

  // Search
  globalSearch?.addEventListener('input', (e) => {
    const q = e.target.value.toLowerCase();
    auditFeedTbody?.querySelectorAll('tr').forEach(row => {
      row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });

  // Export
  btnExportLog?.addEventListener('click', () => {
    const data = { exportTime: new Date().toISOString(), detectors: detectorsList, stats: { scanned: valScanned?.textContent, blocked: valBlocked?.textContent } };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `phishing-audit-${Date.now()}.json`; a.click();
  });

  // Clear
  btnClearFeed?.addEventListener('click', () => {
    if (auditFeedTbody) auditFeedTbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:32px;" class="text-muted">Feed cleared.</td></tr>';
  });

  // Policy rules
  const btnAddRule = document.getElementById('btn-add-rule');
  const policyRulesTbody = document.getElementById('policy-rules-tbody');

  const defaultPolicies = [
    { pattern: '*.google.com', action: 'Allow', source: 'System', time: 'Permanent' },
    { pattern: '*.paypal.com', action: 'Allow', source: 'System', time: 'Permanent' },
    { pattern: '*.microsoft.com', action: 'Allow', source: 'System', time: 'Permanent' },
    { pattern: 'login-update-secure.net', action: 'Block', source: 'Enterprise', time: 'Active' },
  ];

  function renderPolicies() {
    if (!policyRulesTbody) return;
    if (typeof chrome !== 'undefined' && chrome.storage?.local) {
      chrome.storage.local.get(['custom_policies'], (data) => {
        const custom = data.custom_policies || [];
        const allPolicies = [...defaultPolicies, ...custom];
        policyRulesTbody.innerHTML = allPolicies.map(p => `
          <tr>
            <td><code class="code-block">${p.pattern}</code></td>
            <td><span class="badge ${p.action === 'Allow' ? 'safe' : 'danger'}">${p.action}</span></td>
            <td>${p.source}</td>
            <td class="text-muted">${p.time}</td>
          </tr>
        `).join('');
      });
    } else {
      policyRulesTbody.innerHTML = defaultPolicies.map(p => `
        <tr>
          <td><code class="code-block">${p.pattern}</code></td>
          <td><span class="badge ${p.action === 'Allow' ? 'safe' : 'danger'}">${p.action}</span></td>
          <td>${p.source}</td>
          <td class="text-muted">${p.time}</td>
        </tr>
      `).join('');
    }
  }

  btnAddRule?.addEventListener('click', () => {
    const pattern = prompt('Enter domain pattern to configure (e.g. secure.internal.corp or suspicious-site.com):');
    if (!pattern || !pattern.trim()) return;
    const isBlock = confirm(`Click OK to BLOCK '${pattern.trim()}', or Cancel to ALLOW it.`);
    const newRule = {
      pattern: pattern.trim(),
      action: isBlock ? 'Block' : 'Allow',
      source: 'User',
      time: 'Just now'
    };

    if (typeof chrome !== 'undefined' && chrome.storage?.local) {
      chrome.storage.local.get(['custom_policies'], (data) => {
        const custom = data.custom_policies || [];
        custom.push(newRule);
        chrome.storage.local.set({ custom_policies: custom }, () => {
          renderPolicies();
        });
      });
    } else {
      defaultPolicies.push(newRule);
      renderPolicies();
    }
  });

  // Init
  renderDetectorCards();
  renderPerformanceMeters();
  renderAuditFeed();
  renderPolicies();
});
