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

  const swatches = document.querySelectorAll('.swatch');
  swatches.forEach((swatch) => {
    swatch.classList.toggle('selected', swatch.dataset.color === settings.themeColor);
  });
}

function renderResult(url) {
  const result = analyzeUrl(url);
  $('domain').textContent = result.domain;
  $('fullUrl').textContent = result.url;
  $('score').textContent = `${result.score}/100`;
  $('risk').textContent = result.level;
  $('risk').className = `risk-badge risk-${result.level.toLowerCase()}`;
  $('summary').textContent = result.summary;
  $('tipText').textContent = result.tip;

  const findingsList = $('findingsList');
  findingsList.innerHTML = '';
  result.reasons.forEach((reason) => {
    const item = document.createElement('li');
    item.textContent = reason;
    findingsList.appendChild(item);
  });
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

  if (scanButton) {
    scanButton.addEventListener('click', () => {
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
    loadCurrentPage(renderResult);
  });
}

document.addEventListener('DOMContentLoaded', initPopup);
