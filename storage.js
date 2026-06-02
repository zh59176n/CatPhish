// storage.js — theme settings persistence using chrome.storage.local.

const STORAGE_DEFAULTS = {
  themeColor: '#ffd1e8',
  autoScan: true,
  analysisEnabled: true,
  nightMode: false
};

function loadSettings(callback) {
  if (chrome && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(STORAGE_DEFAULTS, (items) => {
      callback({ ...STORAGE_DEFAULTS, ...items });
    });
  } else {
    callback({ ...STORAGE_DEFAULTS });
  }
}

function saveSettings(settings) {
  if (chrome && chrome.storage && chrome.storage.local) {
    chrome.storage.local.set(settings);
  }
}
