// popup.js — connects UI behavior to theme storage and analyzer logic.

function $(id) {
  return document.getElementById(id);
}

let currentSettings = { themeColor: '#ffd1e8' };

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

function applySettings(settings) {
  currentSettings = settings;
  document.documentElement.style.setProperty('--card', settings.themeColor);
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
  $('domain').textContent = result.domain;
  $('category').textContent = `Category: ${result.category || 'Unknown'}`;
  $('fullUrl').textContent = result.url || 'Waiting for the current page';
  $('trustExplanation').textContent = 'Trust details update after scanning.';
  $('scoreReason').textContent = 'Score note: waiting for scan details.';
  $('reputationStatus').textContent = `Domain reputation: ${result.reputation?.status || 'unknown'}`;
}

function renderResult(url) {
  const result = analyzeUrl(url);
  $('domain').textContent = result.domain;
  $('category').textContent = `Category: ${result.category || 'Unknown'}`;
  $('fullUrl').textContent = result.url;
  $('score').textContent = `${result.score}/100`;
  $('risk').textContent = result.level;
  $('risk').className = `risk-badge risk-${result.level.toLowerCase()}`;
  $('summary').textContent = result.summary;
  $('trustExplanation').textContent = result.trustExplanation;
  $('scoreReason').textContent = result.scoreReason || 'Score note: based on URL signals and site context.';
  $('reputationStatus').textContent = `Domain reputation: ${result.reputation?.status || 'unknown'}`;
  $('tipText').textContent = result.tip;

  renderFindings(result);
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
      currentSettings.themeColor = swatch.dataset.color;
      applySettings(currentSettings);
      saveSettings(currentSettings);
    });
  });

  const autoScanToggle = $('autoScanToggle');
  const analysisToggle = $('analysisToggle');

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
