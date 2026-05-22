const MAX_HIST  = 50;   // keep last 50 results
const DEBOUNCE  = 800;  // ms to wait before checking a newly loaded URL

let debounceTimer = null;
let lastCheckedUrl = '';

// ── Defaults ──────────────────────────────────────────────────────────────────
async function getSettings() {
  return new Promise(resolve => {
    chrome.storage.local.get({
      enabled: true,
      model: 'svm',
      history: [],
      backendUrl: 'http://10.13.27.108:5000'
    }, resolve);
  });
}

async function saveHistory(entry) {
  const { history } = await getSettings();
  const updated = [entry, ...history].slice(0, MAX_HIST);
  chrome.storage.local.set({ history: updated });
}

// ── Badge helpers ─────────────────────────────────────────────────────────────
function setBadge(tabId, verdict) {
  const isSafe = verdict === 'legitimate';
  chrome.action.setBadgeBackgroundColor({
    tabId,
    color: isSafe ? '#10b981' : '#ef4444'
  });
  chrome.action.setBadgeText({ tabId, text: isSafe ? '✓' : '!' });
  chrome.action.setTitle({
    tabId,
    title: isSafe ? 'PhishGuard: Safe' : '⚠ PhishGuard: PHISHING DETECTED'
  });
}

function clearBadge(tabId) {
  chrome.action.setBadgeText({ tabId, text: '' });
  chrome.action.setTitle({ tabId, title: 'PhishGuard — Checking…' });
}

function setBadgeChecking(tabId) {
  chrome.action.setBadgeBackgroundColor({ tabId, color: '#6366f1' });
  chrome.action.setBadgeText({ tabId, text: '…' });
  chrome.action.setTitle({ tabId, title: 'PhishGuard — Scanning…' });
}

// ── Notification helper ───────────────────────────────────────────────────────
function notify(url, data) {
  if (data.is_safe) return;          // only alert on phishing
  const short = url.length > 50 ? url.slice(0, 47) + '…' : url;
  chrome.notifications.create({
    type:     'basic',
    iconUrl:  'icons/icon128.png',
    title:    '⚠ Phishing URL Detected!',
    message:  `${short}\nConfidence: ${data.confidence.toFixed(1)}%`,
    priority: 2
  });
}

// ── Core: send URL to backend ─────────────────────────────────────────────────
async function analyzeUrl(tabId, url) {
  const { enabled, model, backendUrl } = await getSettings();
  if (!enabled) return;

  // Skip browser internal pages
  if (!url.startsWith('http://') && !url.startsWith('https://')) return;
  if (url === lastCheckedUrl) return;
  lastCheckedUrl = url;

  setBadgeChecking(tabId);

  try {
    const res  = await fetch(`${backendUrl}/predict`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url, model })
    });

    if (!res.ok) {
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#f59e0b' });
      chrome.action.setBadgeText({ tabId, text: '?' });
      chrome.action.setTitle({ tabId, title: 'PhishGuard: Backend error' });
      return;
    }

    const data = await res.json();
    setBadge(tabId, data.verdict);
    notify(url, data);

    // Save to history
    await saveHistory({
      url,
      verdict:    data.verdict,
      is_safe:    data.is_safe,
      confidence: data.confidence,
      model_used: data.model_used,
      latency_ms: data.latency_ms,
      timestamp:  new Date().toISOString()
    });

    // Notify popup to refresh
    chrome.runtime.sendMessage({ type: 'result', data: { url, ...data } }).catch(() => {});

  } catch (err) {
    // Backend unreachable
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#94a3b8' });
    chrome.action.setBadgeText({ tabId, text: '–' });
    chrome.action.setTitle({ tabId, title: 'PhishGuard: Backend offline' });
    console.warn('[PhishGuard] Backend unreachable:', err.message);
  }
}

// ── Tab listeners ─────────────────────────────────────────────────────────────
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  if (!tab.url) return;

  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    analyzeUrl(tabId, tab.url);
  }, DEBOUNCE);
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await chrome.tabs.get(tabId);
  if (!tab.url) return;
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    analyzeUrl(tabId, tab.url);
  }, DEBOUNCE);
});

// ── Message handler (from popup) ──────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'check_now') {
    chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
      if (tab) {
        lastCheckedUrl = '';           // force re-check
        analyzeUrl(tab.id, tab.url);
        sendResponse({ ok: true });
      }
    });
    return true; // keep channel open for async
  }

  if (msg.type === 'clear_history') {
    chrome.storage.local.set({ history: [] });
    sendResponse({ ok: true });
    return true;
  }
});
