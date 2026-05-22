// ── PhishGuard Popup ──────────────────────────────────────────────────────────
const API_URL = 'http://10.13.27.108:5000';

// ── Helpers ───────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

function shortUrl(url, max = 48) {
  return url.length > max ? url.slice(0, max - 1) + '…' : url;
}

function timeAgo(isoString) {
  const diff = Math.floor((Date.now() - new Date(isoString)) / 1000);
  if (diff < 60)   return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  return `${Math.floor(diff/3600)}h ago`;
}

// ── Status banner ─────────────────────────────────────────────────────────────
function setStatus(state, verdict, url, data) {
  const banner  = $('statusBanner');
  const icon    = $('statusIcon');
  const vEl     = $('statusVerdict');
  const uEl     = $('statusUrl');
  const stats   = $('statsRow');
  const barWrap = $('confBarWrap');

  banner.className = `status-banner ${state}`;

  if (state === 'safe') {
    icon.textContent  = '✓';
    vEl.textContent   = 'Safe / Legitimate';
  } else if (state === 'danger') {
    icon.textContent  = '⚠';
    vEl.textContent   = '⚠ Phishing Detected!';
  } else if (state === 'checking') {
    icon.innerHTML    = '<div class="spinner"></div>';
    vEl.textContent   = 'Scanning…';
  } else if (state === 'offline') {
    icon.textContent  = '–';
    vEl.textContent   = 'Backend Offline';
  } else {
    icon.textContent  = '🛡';
    vEl.textContent   = 'Monitoring…';
  }

  uEl.textContent = url ? shortUrl(url) : 'Navigate to any page to auto-scan';

  if (data) {
    stats.style.display   = 'flex';
    barWrap.style.display = 'block';
    $('statConf').textContent    = `${data.confidence.toFixed(1)}%`;
    $('statModel').textContent   = data.model_used;
    $('statLatency').textContent = `${data.latency_ms.toFixed(0)}ms`;
    $('confBar').style.width     = `${data.confidence}%`;
    $('confBar').style.background = state === 'safe' ? '#10b981' : '#ef4444';
    $('confPct').textContent     = `${data.confidence.toFixed(1)}%`;
  } else {
    stats.style.display   = 'none';
    barWrap.style.display = 'none';
  }
}

// ── History renderer ──────────────────────────────────────────────────────────
function renderHistory(history) {
  const list = $('historyList');
  if (!history || history.length === 0) {
    list.innerHTML = '<div class="no-history">No scans yet — navigate to a page!</div>';
    return;
  }
  list.innerHTML = history.map(h => `
    <div class="hist-item ${h.is_safe ? 'safe' : 'danger'}" title="${h.url}">
      <span class="hist-dot">${h.is_safe ? '✓' : '⚠'}</span>
      <span class="hist-url">${shortUrl(h.url, 38)}</span>
      <span class="hist-conf">${h.confidence.toFixed(0)}%</span>
    </div>
  `).join('');
}

// ── Init ──────────────────────────────────────────────────────────────────────
async function init() {
  const settings = await new Promise(res =>
    chrome.storage.local.get({
      enabled: true,
      model: 'svm',
      history: [],
      lastResult: null,
      backendUrl: 'http://10.13.27.108:5000'
    }, res)
  );

  // Connection settings
  const ipInput = $('backendUrlInput');
  const saveBtn = $('saveBackendBtn');
  ipInput.value = settings.backendUrl;

  saveBtn.addEventListener('click', () => {
    let url = ipInput.value.trim();
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'http://' + url;
    }
    chrome.storage.local.set({ backendUrl: url }, () => {
      saveBtn.textContent = 'Saved!';
      saveBtn.style.background = '#10b981';
      setTimeout(() => {
        saveBtn.textContent = 'Save';
        saveBtn.style.background = '#6366f1';
      }, 1500);
    });
  });

  // Toggle
  const toggle = $('enableToggle');
  toggle.checked = settings.enabled;
  $('toggleLabel').textContent = settings.enabled ? 'ON' : 'OFF';
  toggle.addEventListener('change', () => {
    const val = toggle.checked;
    chrome.storage.local.set({ enabled: val });
    $('toggleLabel').textContent = val ? 'ON' : 'OFF';
    if (!val) setStatus('idle', null, null, null);
  });

  // Model tabs
  document.querySelectorAll('.model-tab').forEach(tab => {
    if (tab.dataset.model === settings.model) tab.classList.add('active');
    else tab.classList.remove('active');

    tab.addEventListener('click', () => {
      document.querySelectorAll('.model-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      chrome.storage.local.set({ model: tab.dataset.model });
    });
  });

  // Render last result if available
  if (settings.lastResult) {
    const r = settings.lastResult;
    setStatus(r.is_safe ? 'safe' : 'danger', r.verdict, r.url, r);
  }

  // Render history
  renderHistory(settings.history);

  // Get current tab URL
  chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
    if (tab && tab.url && tab.url.startsWith('http')) {
      $('statusUrl').textContent = shortUrl(tab.url);
    }
  });

  // Scan Now button
  $('scanNowBtn').addEventListener('click', () => {
    setStatus('checking', null, $('statusUrl').textContent, null);
    chrome.runtime.sendMessage({ type: 'check_now' });
  });

  // Open Dashboard
  $('openDashBtn').addEventListener('click', () => {
    chrome.tabs.create({ url: `${settings.backendUrl}/dashboard` });
  });

  // Clear history
  $('clearHistBtn').addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'clear_history' }, () => {
      renderHistory([]);
    });
  });
}

// ── Listen for live results pushed from background ────────────────────────────
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'result') {
    const d = msg.data;
    chrome.storage.local.set({ lastResult: d });
    setStatus(d.is_safe ? 'safe' : 'danger', d.verdict, d.url, d);
    chrome.storage.local.get({ history: [] }, ({ history }) => renderHistory(history));
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────
init();
