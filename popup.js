// popup.js — connects UI behavior to theme storage and analyzer logic.

function $(id) {
  return document.getElementById(id);
}

let currentSettings = { themeColor: '#ffd1e8' };

const THEME_CLASSES = {
  '#ffd1e8': 'theme-pink',
  '#d1fff0': 'theme-mint',
  '#e8d1ff': 'theme-lavender',
  '#d1eaff': 'theme-sky',
  '#ffeed1': 'theme-peach',
  '#fff4d1': 'theme-lemon',
};

let currentPageUrl = '';
let currentTabId = null;
let showFullUrl = false;

function loadCurrentPage(callback) {
  if (chrome && chrome.tabs && chrome.tabs.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (chrome.runtime.lastError) {
        callback('');
        return;
      }
      const tab = tabs && tabs[0];
      const url = (tab && tab.url) || '';
      currentTabId = (tab && tab.id != null) ? tab.id : null;
      // Browser-internal pages cannot be scanned
      const internal = url.startsWith('chrome://') || url.startsWith('chrome-extension://') ||
                       url.startsWith('about:') || url.startsWith('edge://') ||
                       url.startsWith('moz-extension://');
      callback(internal ? '' : url);
    });
  } else {
    callback('');
  }
}

function formatUrlDisplay(url) {
  if (!url) {
    return 'Waiting for the current page';
  }

  if (showFullUrl || url.length <= 72) {
    return url;
  }

  const head = url.slice(0, 38);
  const tail = url.slice(-28);
  return `${head}...${tail}`;
}

function updateUrlDisplay(url) {
  const fullUrlEl = $('fullUrl');
  const toggleButton = $('toggleUrlButton');
  const displayText = formatUrlDisplay(url);

  if (fullUrlEl) {
    fullUrlEl.textContent = displayText;
    fullUrlEl.classList.toggle('expanded', showFullUrl);
  }

  if (toggleButton) {
    const hasUrl = Boolean(url);
    toggleButton.textContent = hasUrl
      ? showFullUrl ? 'Hide full URL' : 'Show full URL'
      : 'No URL available';
    toggleButton.disabled = !hasUrl;
    toggleButton.setAttribute('aria-expanded', String(showFullUrl));
  }
}

function applySettings(settings) {
  currentSettings = settings;

  // Swap theme body class (CSS handles all palette values — no inline styles needed)
  Object.values(THEME_CLASSES).forEach((cls) => document.body.classList.remove(cls));
  if (!settings.nightMode) {
    document.body.classList.add(THEME_CLASSES[settings.themeColor] || 'theme-pink');
  }

  document.body.classList.toggle('dark-mode', Boolean(settings.nightMode));

  document.querySelectorAll('.swatch').forEach((swatch) => {
    const active = swatch.dataset.color === settings.themeColor;
    swatch.classList.toggle('selected', active);
    swatch.setAttribute('aria-pressed', String(active));
  });

  const autoScanInput = $('autoScanToggle');
  const analysisInput = $('analysisToggle');
  const nightModeInput = $('nightModeToggle');

  if (autoScanInput) autoScanInput.checked = Boolean(settings.autoScan);
  if (analysisInput) analysisInput.checked = Boolean(settings.analysisEnabled);
  if (nightModeInput) nightModeInput.checked = Boolean(settings.nightMode);

  updateScanButtonState();
}

function updateScanButtonState() {
  const scanButton = $('scanButton');
  if (!scanButton) return;

  if (!currentSettings.analysisEnabled) {
    scanButton.disabled = true;
    scanButton.textContent = 'Scanning paused';
    scanButton.classList.add('disabled');
  } else {
    scanButton.disabled = false;
    scanButton.textContent = 'Scan current page';
    scanButton.classList.remove('disabled');
  }
}

function renderScanHistory(history) {
  const list = $('historyList');
  if (!list) return;
  list.innerHTML = '';
  if (!history.length) {
    const empty = document.createElement('li');
    empty.className = 'history-empty';
    empty.textContent = 'No recent scans yet.';
    list.appendChild(empty);
    return;
  }
  history.forEach((item) => {
    const li = document.createElement('li');
    li.className = 'history-item';

    const domainSpan = document.createElement('span');
    domainSpan.className = 'history-domain';
    domainSpan.textContent = item.domain;

    const meta = document.createElement('span');
    meta.className = 'history-meta';

    const levelSpan = document.createElement('span');
    levelSpan.className = `history-level history-${item.level.toLowerCase()}`;
    levelSpan.textContent = item.level;
    meta.appendChild(levelSpan);

    if (item.score != null) {
      const scoreSpan = document.createElement('span');
      scoreSpan.className = 'history-score';
      scoreSpan.textContent = `${item.score}`;
      meta.appendChild(scoreSpan);
    }

    li.appendChild(domainSpan);
    li.appendChild(meta);
    list.appendChild(li);
  });
}

function updateReportLink(url) {
  const reportLink = $('reportLink');
  if (!reportLink) return;
  reportLink.href = url
    ? `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(url)}`
    : 'https://safebrowsing.google.com/safebrowsing/report_phish/';
}

function renderPageHeader(url) {
  const result = analyzeUrl(url);
  currentPageUrl = result.url || '';
  $('domain').textContent = result.domain === 'unknown' ? '-' : result.domain;
  $('category').textContent = url ? `Category: ${result.category || 'Unknown'}` : '';
  showFullUrl = false;
  updateUrlDisplay(result.url);
  updateReportLink(result.url);
  $('trustExplanation').textContent = 'Trust details appear after scanning.';
  $('scoreReason').textContent = '';
  $('reputationStatus').textContent = '';
  const topFactorsEl = $('topFactors');
  if (topFactorsEl) topFactorsEl.innerHTML = '';
  const whySection = $('whySection');
  if (whySection) whySection.hidden = true;
}

function applyLiveThreatResult(sbResult) {
  if (!sbResult || !sbResult.checked) return;

  if (sbResult.isThreat) {
    const label = sbResult.threatTypes.length
      ? sbResult.threatTypes[0].replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, (c) => c.toUpperCase())
      : 'Threat';
    $('reputationStatus').textContent = `Safe Browsing: THREAT DETECTED — ${label}`;
    $('risk').textContent = 'High';
    $('risk').className = 'risk-badge risk-high';
    $('score').textContent = '100 / 100';
    const meterFill = $('riskMeterFill');
    if (meterFill) meterFill.setAttribute('data-pct', '100');
    const concernsList = $('concernsList');
    if (concernsList) {
      const item = document.createElement('li');
      item.className = 'negative';
      item.textContent = `Google Safe Browsing: ${label}`;
      concernsList.prepend(item);
    }
  } else {
    $('reputationStatus').textContent = 'Safe Browsing: No known threats found';
    const positiveList = $('positiveList');
    if (positiveList) {
      const item = document.createElement('li');
      item.textContent = 'Google Safe Browsing: Clean';
      positiveList.prepend(item);
    }
  }
}

function applyDomainAge(age) {
  if (!age || !age.checked) return;
  const { ageInDays } = age;
  const positiveList = $('positiveList');
  const concernsList = $('concernsList');

  if (ageInDays < 30) {
    if (concernsList) {
      const item = document.createElement('li');
      item.className = 'negative';
      item.textContent = `Domain registered ${ageInDays} day${ageInDays !== 1 ? 's' : ''} ago — very new`;
      concernsList.prepend(item);
    }
    if ($('risk')?.textContent !== 'High') {
      $('risk').textContent = 'High';
      $('risk').className = 'risk-badge risk-high';
      const meterFill = $('riskMeterFill');
      if (meterFill) meterFill.setAttribute('data-pct', '80');
    }
  } else if (ageInDays < 180) {
    if (concernsList) {
      const item = document.createElement('li');
      item.className = 'negative';
      item.textContent = `Domain is ${Math.floor(ageInDays / 30)} month${Math.floor(ageInDays / 30) !== 1 ? 's' : ''} old — recently created`;
      concernsList.appendChild(item);
    }
  } else {
    const years = (ageInDays / 365).toFixed(1);
    if (positiveList) {
      const item = document.createElement('li');
      item.textContent = `Established domain (${years} years old)`;
      positiveList.appendChild(item);
    }
  }
}

function applyContentSignals(signals) {
  const high = signals.filter((s) => s.severity === 'high');
  if (!high.length) return;
  const concernsList = $('concernsList');
  high.forEach((signal) => {
    if (!concernsList) return;
    const item = document.createElement('li');
    item.className = 'negative';
    item.textContent = signal.label;
    concernsList.prepend(item);
  });
  if ($('risk')?.textContent !== 'High') {
    $('risk').textContent = 'High';
    $('risk').className = 'risk-badge risk-high';
    const meterFill = $('riskMeterFill');
    if (meterFill) meterFill.setAttribute('data-pct', '80');
  }
}

function renderResult(url) {
  const result = analyzeUrl(url);
  currentPageUrl = result.url || '';
  $('domain').textContent = result.domain === 'unknown' ? '-' : result.domain;
  $('category').textContent = `Category: ${result.category || 'Unknown'}`;
  updateUrlDisplay(result.url);
  updateReportLink(result.url);
  $('score').textContent = `${result.score} / 100`;
  $('risk').textContent = result.level;
  $('risk').className = `risk-badge risk-${result.level.toLowerCase()}`;
  const firstSentence = (result.summary || '').split('.').filter(Boolean)[0] || result.summary;
  $('summary').textContent = firstSentence ? `${firstSentence.trim()}.` : '';
  $('trustExplanation').textContent = result.trustExplanation;
  $('scoreReason').textContent = result.scoreReason || 'Most important indicators are shown above.';
  $('reputationStatus').textContent = `Domain reputation: ${result.reputation?.status || 'unknown'}`;
  $('tipText').textContent = result.tip;
  const meterFill = $('riskMeterFill');
  if (meterFill) {
    const pct = Math.round(Math.min(100, Math.max(0, result.score)) / 5) * 5;
    meterFill.setAttribute('data-pct', String(pct));
  }

  // Render top factors (why this score)
  const topFactorsEl = $('topFactors');
  const whySection = $('whySection');
  if (topFactorsEl) {
    topFactorsEl.innerHTML = '';
    const factors = result.topFactors || [];
    const items = factors.length ? factors : ['No major indicators'];
    items.forEach((f) => {
      const item = document.createElement('li');
      item.textContent = f;
      topFactorsEl.appendChild(item);
    });
    if (whySection) whySection.hidden = false;
  }

  renderFindings(result);

  if (result.domain && result.domain !== 'unknown') {
    saveScanToHistory({ domain: result.domain, level: result.level, score: result.score, ts: Date.now() }, () => {
      loadScanHistory(renderScanHistory);
    });
  }

  // request content script signals and domain age already collected by background
  if (currentTabId != null && chrome.runtime && chrome.runtime.sendMessage) {
    chrome.runtime.sendMessage({ type: 'GET_CONTENT_SIGNALS', tabId: currentTabId }, (signals) => {
      if (chrome.runtime.lastError || !signals) return;
      applyContentSignals(signals);
    });
    chrome.runtime.sendMessage({ type: 'GET_DOMAIN_AGE', tabId: currentTabId, domain: result.domain }, (age) => {
      if (chrome.runtime.lastError || !age) return;
      applyDomainAge(age);
    });
  }

  // kick off live Safe Browsing check
  if (url && chrome.runtime && chrome.runtime.sendMessage) {
    $('reputationStatus').textContent = 'Checking Google Safe Browsing…';
    chrome.runtime.sendMessage(
      { type: 'CHECK_SAFE_BROWSING', url, tabId: currentTabId, localLevel: result.level },
      (response) => {
        if (chrome.runtime.lastError) return;
        applyLiveThreatResult(response);
      }
    );
  }

  // subtly reveal updated results
  const container = document.querySelector('.container');
  if (container) {
    container.classList.add('results-visible');
    setTimeout(() => container.classList.remove('results-visible'), 1200);
  }
}

function renderFindings(result) {
  const positiveList = $('positiveList');
  const concernsList = $('concernsList');
  if (!positiveList || !concernsList) return;

  positiveList.innerHTML = '';
  concernsList.innerHTML = '';

  if (result.positiveSignals && result.positiveSignals.length) {
    result.positiveSignals.forEach((signal) => {
      const item = document.createElement('li');
      item.textContent = signal;
      positiveList.appendChild(item);
    });
  } else {
    const item = document.createElement('li');
    item.textContent = 'No strong positive signals were detected yet.';
    positiveList.appendChild(item);
  }

  if (result.concerns && result.concerns.length) {
    result.concerns.forEach((concern) => {
      const item = document.createElement('li');
      item.textContent = concern;
      item.classList.add('negative');
      concernsList.appendChild(item);
    });
  } else {
    const item = document.createElement('li');
    item.textContent = "CatPhish didn't spot any common phishing indicators on this page.";
    concernsList.appendChild(item);
  }
}

function toggleSettingsMenu() {
  const menu = $('settingsMenu');
  menu.classList.toggle('open');
  menu.classList.toggle('hidden', !menu.classList.contains('open'));
}

function closeSettingsMenu() {
  const menu = $('settingsMenu');
  if (menu.classList.contains('open')) {
    menu.classList.remove('open');
    menu.classList.add('hidden');
  }
}

function initializeControls() {
  const settingsButton = $('settingsButton');
  const scanButton = $('scanButton');
  const swatches = document.querySelectorAll('.swatch');

  if (settingsButton) {
    settingsButton.addEventListener('click', (event) => {
      event.stopPropagation();
      toggleSettingsMenu();
    });
  }

  swatches.forEach((swatch) => {
    swatch.addEventListener('click', () => {
      const selected = swatch.dataset.color;
      // If night mode is active, turn it off so the chosen color shows immediately
      if (currentSettings.nightMode) {
        currentSettings.nightMode = false;
      }
      currentSettings.themeColor = selected;
      saveSettings(currentSettings);
      applySettings(currentSettings);
    });
  });

  const autoScanToggle = $('autoScanToggle');
  const analysisToggle = $('analysisToggle');
  const toggleUrlButton = $('toggleUrlButton');

  if (autoScanToggle) {
    autoScanToggle.addEventListener('change', () => {
      currentSettings.autoScan = autoScanToggle.checked;
      saveSettings(currentSettings);

      if (currentSettings.autoScan && currentSettings.analysisEnabled) {
        loadCurrentPage(renderResult);
      }
    });
  }

  if (analysisToggle) {
    analysisToggle.addEventListener('change', () => {
      currentSettings.analysisEnabled = analysisToggle.checked;
      saveSettings(currentSettings);
      applySettings(currentSettings);

      if (currentSettings.analysisEnabled && currentSettings.autoScan) {
        loadCurrentPage(renderResult);
      }
    });
  }

  if (toggleUrlButton) {
    toggleUrlButton.addEventListener('click', () => {
      showFullUrl = !showFullUrl;
      updateUrlDisplay(currentPageUrl);
    });
  }

  const nightModeToggle = $('nightModeToggle');
  if (nightModeToggle) {
    nightModeToggle.addEventListener('change', () => {
      currentSettings.nightMode = nightModeToggle.checked;
      saveSettings(currentSettings);
      applySettings(currentSettings);
    });
  }

  if (scanButton) {
    scanButton.addEventListener('click', () => {
      if (!currentSettings.analysisEnabled) return;
      loadCurrentPage(renderResult);
    });
  }

  document.addEventListener('click', (event) => {
    const menu = $('settingsMenu');
    const button = $('settingsButton');
    if (menu && button && !menu.contains(event.target) && !button.contains(event.target)) {
      closeSettingsMenu();
    }
  });
}

function initPopup() {
  loadSettings((settings) => {
    applySettings(settings);
    initializeControls();
    loadCurrentPage((url) => {
      renderPageHeader(url);
      loadScanHistory(renderScanHistory);
      if (currentSettings.autoScan && currentSettings.analysisEnabled) {
        renderResult(url);
      } else {
        if (currentSettings.analysisEnabled) {
          $('summary').textContent = 'Auto-scan is off. Tap scan to analyze this page.';
        } else {
          $('summary').textContent = 'Scanning is paused in settings.';
        }
      }
    });
  });
}

document.addEventListener('DOMContentLoaded', initPopup);
