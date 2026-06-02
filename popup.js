// popup.js — connects UI behavior to theme storage and analyzer logic.

function $(id) {
  return document.getElementById(id);
}

let currentSettings = { themeColor: '#ffd1e8' };

const THEME_PALETTES = {
  '#ffd1e8': { text: '#342651', muted: '#7a4060', accent: '#e76f9e', bgStart: '#ffeaf2', bgMid: '#fff5fb' }, // pink
  '#d1fff0': { text: '#1a3d32', muted: '#3d6655', accent: '#0f9060', bgStart: '#eafff8', bgMid: '#f5fffb' }, // mint
  '#e8d1ff': { text: '#2d1f4a', muted: '#6a5090', accent: '#8b5cf6', bgStart: '#f0e8ff', bgMid: '#f8f5ff' }, // lavender
  '#d1eaff': { text: '#1a2e4a', muted: '#3d5870', accent: '#2878c8', bgStart: '#eaf4ff', bgMid: '#f5f9ff' }, // sky
  '#ffeed1': { text: '#3d2510', muted: '#8a5e3a', accent: '#cc6020', bgStart: '#fff5e8', bgMid: '#fffaf5' }, // peach
  '#fff4d1': { text: '#352e10', muted: '#686025', accent: '#9e7800', bgStart: '#fffaea', bgMid: '#fffdf5' }, // lemon
};
let currentPageUrl = '';
let showFullUrl = false;

function hexToRgb(hex) {
  if (!hex) return [0, 0, 0];
  let h = hex.replace('#', '').trim();
  if (h.length === 3) h = h.split('').map((c) => c + c).join('');
  const bigint = parseInt(h, 16);
  return [(bigint >> 16) & 255, (bigint >> 8) & 255, bigint & 255];
}

function rgbToHex(r, g, b) {
  const toHex = (n) => Math.max(0, Math.min(255, Math.round(n))).toString(16).padStart(2, '0');
  return `#${toHex(r)}${toHex(g)}${toHex(b)}`;
}

function darkenHex(hex, amount = 0.4) {
  const [r, g, b] = hexToRgb(hex);
  const factor = 1 - amount;
  return rgbToHex(r * factor, g * factor, b * factor);
}

function loadCurrentPage(callback) {
  if (chrome && chrome.tabs) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs && tabs[0];
      callback(tab && tab.url ? tab.url : '');
    });
  } else {
    callback(window.location.href || '');
  }
}

function formatUrlDisplay(url) {
  if (!url) {
    return 'Waiting for the current page';
  }

  if (showFullUrl || url.length <= 72) {
    return url;
  }

  const maxLength = 72;
  const head = url.slice(0, 38);
  const tail = url.slice(-28);
  return `${head}…${tail}`;
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
  // Apply theme color; when night mode is active, use a darker variant so color changes still show
  const appliedColor = settings.nightMode ? darkenHex(settings.themeColor, 0.5) : settings.themeColor;
  document.documentElement.style.setProperty('--card', appliedColor);

  if (!settings.nightMode) {
    const palette = THEME_PALETTES[settings.themeColor] || THEME_PALETTES['#ffd1e8'];
    document.documentElement.style.setProperty('--text', palette.text);
    document.documentElement.style.setProperty('--muted', palette.muted);
    document.documentElement.style.setProperty('--accent', palette.accent);
    document.body.style.background = `radial-gradient(circle at top, ${palette.bgStart} 0%, ${palette.bgMid} 40%, #fffaff 100%)`;
  } else {
    // Remove inline overrides so dark mode CSS and :root defaults take over
    document.documentElement.style.removeProperty('--text');
    document.documentElement.style.removeProperty('--muted');
    document.documentElement.style.removeProperty('--accent');
    document.body.style.background = '';
  }

  document.body.classList.toggle('dark-mode', Boolean(settings.nightMode));

  const swatches = document.querySelectorAll('.swatch');
  swatches.forEach((swatch) => {
    swatch.style.backgroundColor = swatch.dataset.color;
    swatch.classList.toggle('selected', swatch.dataset.color === settings.themeColor);
  });

  const autoScanInput = $('autoScanToggle');
  const analysisInput = $('analysisToggle');
  const nightModeInput = $('nightModeToggle');

  if (autoScanInput) {
    autoScanInput.checked = Boolean(settings.autoScan);
  }
  if (analysisInput) {
    analysisInput.checked = Boolean(settings.analysisEnabled);
  }
  if (nightModeInput) {
    nightModeInput.checked = Boolean(settings.nightMode);
  }

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

function renderPageHeader(url) {
  const result = analyzeUrl(url);
  currentPageUrl = result.url || '';
  $('domain').textContent = result.domain;
  $('category').textContent = `Category: ${result.category || 'Unknown'}`;
  showFullUrl = false;
  updateUrlDisplay(result.url);
  $('trustExplanation').textContent = 'Trust details update after scanning.';
  $('scoreReason').textContent = 'Score note: waiting for scan details.';
  $('reputationStatus').textContent = `Domain reputation: ${result.reputation?.status || 'unknown'}`;
}

function renderResult(url) {
  const result = analyzeUrl(url);
  currentPageUrl = result.url || '';
  $('domain').textContent = result.domain;
  $('category').textContent = `Category: ${result.category || 'Unknown'}`;
  updateUrlDisplay(result.url);
  $('score').textContent = `${result.score}/100`;
  $('risk').textContent = result.level;
  $('risk').className = `risk-badge risk-${result.level.toLowerCase()}`;
  $('summary').textContent = result.summary;
  // Keep summary short (1-2 sentences) — trim to first sentence for clarity
  const firstSentence = (result.summary || '').split('.').filter(Boolean)[0] || '';
  if (firstSentence) $('summary').textContent = `${firstSentence.trim()}.`;
  $('trustExplanation').textContent = result.trustExplanation;
  $('scoreReason').textContent = result.scoreReason || 'Most important indicators are shown above.';
  $('reputationStatus').textContent = `Domain reputation: ${result.reputation?.status || 'unknown'}`;
  $('tipText').textContent = result.tip;
  const meterFill = $('riskMeterFill');
  if (meterFill) {
    meterFill.style.width = `${Math.min(100, Math.max(0, result.score))}%`;
  }

  // Render top factors (why this score)
  const topFactorsEl = $('topFactors');
  if (topFactorsEl) {
    topFactorsEl.innerHTML = '';
    const factors = result.topFactors || [];
    if (factors.length) {
      factors.forEach((f) => {
        const item = document.createElement('li');
        item.textContent = f;
        topFactorsEl.appendChild(item);
      });
    } else {
      const item = document.createElement('li');
      item.textContent = 'No major indicators';
      topFactorsEl.appendChild(item);
    }
  }

  renderFindings(result);

  // subtly reveal updated results
  const container = document.querySelector('.container');
  if (container) {
    container.classList.add('results-visible');
    window.setTimeout(() => container.classList.remove('results-visible'), 1200);
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
    item.textContent = 'CatPhish didn’t spot any common phishing indicators on this page.';
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
