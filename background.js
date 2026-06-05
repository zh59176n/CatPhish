// background.js — service worker for Google Safe Browsing API calls and badge updates.

importScripts('config.js');
importScripts('analyzer.js');
const SAFE_BROWSING_ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
const THREAT_TYPES = ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'];
const DEFAULT_CACHE_TTL = 5 * 60 * 1000;

const urlCache = new Map();

function parseCacheDuration(str) {
  const seconds = parseFloat(str);
  return isNaN(seconds) ? DEFAULT_CACHE_TTL : seconds * 1000;
}

async function checkSafeBrowsing(url, apiKey) {
  if (!apiKey) return { checked: false, reason: 'no_key' };

  const cached = urlCache.get(url);
  if (cached && Date.now() - cached.ts < cached.ttl) return cached.result;

  try {
    const resp = await fetch(`${SAFE_BROWSING_ENDPOINT}?key=${encodeURIComponent(apiKey)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'catphish', clientVersion: '0.1' },
        threatInfo: {
          threatTypes: THREAT_TYPES,
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }]
        }
      })
    });

    if (!resp.ok) return { checked: false, reason: 'api_error', status: resp.status };

    const data = await resp.json();
    const isThreat = Array.isArray(data.matches) && data.matches.length > 0;
    const threatTypes = isThreat ? data.matches.map((m) => m.threatType) : [];
    // respect per-match cacheDuration from the API; use the shortest to be safe
    const ttl = isThreat
      ? Math.min(...data.matches.map((m) => parseCacheDuration(m.cacheDuration)))
      : DEFAULT_CACHE_TTL;
    const result = { checked: true, isThreat, threatTypes };
    urlCache.set(url, { result, ts: Date.now(), ttl });
    return result;
  } catch (_) {
    return { checked: false, reason: 'network_error' };
  }
}

function updateBadge(tabId, isThreat, localLevel) {
  if (isThreat) {
    chrome.action.setBadgeText({ text: '!', tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#c53030', tabId });
  } else if (localLevel === 'High') {
    chrome.action.setBadgeText({ text: '!', tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#dd6b20', tabId });
  } else if (localLevel === 'Medium') {
    chrome.action.setBadgeText({ text: '~', tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#d69e2e', tabId });
  } else {
    chrome.action.setBadgeText({ text: '', tabId });
  }
}

const contentSignals = new Map(); // tabId → signals[]

const INTERNAL_PREFIXES = ['chrome://', 'chrome-extension://', 'about:', 'edge://', 'moz-extension://'];

function scanTab(tabId, url) {
  if (!url || INTERNAL_PREFIXES.some((p) => url.startsWith(p))) {
    chrome.action.setBadgeText({ text: '', tabId });
    return;
  }
  const local = analyzeUrl(url);
  updateBadge(tabId, false, local.level);
  checkSafeBrowsing(url, SAFE_BROWSING_API_KEY).then((sb) => {
    updateBadge(tabId, sb.isThreat || false, local.level);
  });
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete' || !tab.url) return;
  scanTab(tabId, tab.url);
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId, (tab) => {
    if (chrome.runtime.lastError || !tab.url) return;
    scanTab(tabId, tab.url);
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'CONTENT_SIGNALS') {
    const tabId = sender.tab?.id;
    if (tabId != null) {
      contentSignals.set(tabId, message.signals);
      const hasHighSignal = message.signals.some((s) => s.severity === 'high');
      if (hasHighSignal) {
        chrome.tabs.get(tabId, (tab) => {
          if (chrome.runtime.lastError || !tab.url) return;
          const local = analyzeUrl(tab.url);
          updateBadge(tabId, false, 'High');
          checkSafeBrowsing(tab.url, SAFE_BROWSING_API_KEY).then((sb) => {
            updateBadge(tabId, sb.isThreat || false, 'High');
          });
        });
      }
    }
    return;
  }

  if (message.type === 'GET_CONTENT_SIGNALS') {
    sendResponse(contentSignals.get(message.tabId) || []);
    return true;
  }

  if (message.type === 'CHECK_SAFE_BROWSING') {
    const { url, tabId, localLevel } = message;
    checkSafeBrowsing(url, SAFE_BROWSING_API_KEY).then((result) => {
      if (tabId != null) updateBadge(tabId, result.isThreat, localLevel);
      sendResponse(result);
    });
    return true;
  }
});
