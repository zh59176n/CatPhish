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

const HISTORY_MAX = 5;

function loadScanHistory(callback) {
  if (chrome && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get({ scanHistory: [] }, (items) => {
      callback(Array.isArray(items.scanHistory) ? items.scanHistory : []);
    });
  } else {
    callback([]);
  }
}

function saveScanToHistory(entry, callback) {
  loadScanHistory((history) => {
    const deduped = history.filter((h) => h.domain !== entry.domain);
    const updated = [entry, ...deduped].slice(0, HISTORY_MAX);
    if (chrome && chrome.storage && chrome.storage.local) {
      chrome.storage.local.set({ scanHistory: updated }, callback);
    } else if (callback) {
      callback();
    }
  });
}
