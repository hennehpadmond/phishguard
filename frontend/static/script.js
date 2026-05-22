// Automatically use the host IP if loaded from the server, otherwise fallback to local IP
const API = window.location.origin;

let selectedModel  = "svm";
let debounceTimer  = null;
let isChecking     = false;
const DEBOUNCE_MS  = 600;   // auto-check fires 600 ms after typing stops

// ── DOMContentLoaded ──────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {

  // Model tabs
  const tabs = document.querySelectorAll(".model-tab");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      selectedModel = tab.dataset.model;

      // Re-check with new model if a result is already showing
      const urlInput = document.getElementById("urlInput").value.trim();
      if (urlInput) triggerDebounce(urlInput);
    });
  });

  // URL input — live debounced detection
  const urlInput = document.getElementById("urlInput");
  if (urlInput) {
    urlInput.addEventListener("input", () => {
      const val = urlInput.value.trim();
      setLiveIndicator("typing");
      clearTimeout(debounceTimer);
      if (!val) { resetResult(); return; }
      debounceTimer = setTimeout(() => triggerDebounce(val), DEBOUNCE_MS);
    });

    // Keep Enter key support as instant trigger
    urlInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        clearTimeout(debounceTimer);
        const val = urlInput.value.trim();
        if (val) checkURL(val);
      }
    });
  }

  // Check API health on load
  checkBackendHealth();
});

// ── Live indicator state ──────────────────────────────────────────────────────
function setLiveIndicator(state) {
  const dot  = document.getElementById("liveDot");
  const text = document.getElementById("liveText");
  if (!dot || !text) return;

  const states = {
    idle:    { color: "#6b7280", label: "Ready" },
    typing:  { color: "#f59e0b", label: "Waiting…" },
    checking:{ color: "#6366f1", label: "Scanning…" },
    safe:    { color: "#10b981", label: "Safe" },
    phishing:{ color: "#ef4444", label: "Phishing!" },
    error:   { color: "#f59e0b", label: "Error" },
    offline: { color: "#94a3b8", label: "Backend offline" },
  };

  const s = states[state] || states.idle;
  dot.style.background  = s.color;
  dot.style.boxShadow   = `0 0 6px ${s.color}`;
  text.textContent      = s.label;
  text.style.color      = s.color;
}

// ── Trigger debounced check ───────────────────────────────────────────────────
function triggerDebounce(url) {
  setLiveIndicator("checking");
  checkURL(url);
}

// ── Backend health ────────────────────────────────────────────────────────────
async function checkBackendHealth() {
  try {
    const r = await fetch(`${API_URL}/health`, { signal: AbortSignal.timeout(3000) });
    if (r.ok) {
      setLiveIndicator("idle");
    } else {
      setLiveIndicator("offline");
    }
  } catch {
    setLiveIndicator("offline");
  }
}

// ── Reset result panel ────────────────────────────────────────────────────────
function resetResult() {
  const resultPanel = document.getElementById("resultPanel");
  if (resultPanel) resultPanel.style.display = "none";
  const errorMsg = document.getElementById("errorMsg");
  if (errorMsg) errorMsg.style.display = "none";
  setLiveIndicator("idle");
}

// ── Main check function ───────────────────────────────────────────────────────
async function checkURL(urlOverride) {
  const urlInput    = document.getElementById("urlInput");
  const errorMsg    = document.getElementById("errorMsg");
  const resultPanel = document.getElementById("resultPanel");
  const loadingSpinner = document.getElementById("loadingSpinner");

  const url = (urlOverride !== undefined ? urlOverride : urlInput.value.trim());

  errorMsg.style.display    = "none";
  resultPanel.style.display = "none";

  if (!url) {
    errorMsg.textContent   = "Please enter a URL.";
    errorMsg.style.display = "block";
    setLiveIndicator("error");
    return;
  }

  if (isChecking) return;
  isChecking = true;

  loadingSpinner.style.display = "flex";
  setLiveIndicator("checking");

  try {
    const response = await fetch(`${API_URL}/predict`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url, model: selectedModel }),
      signal:  AbortSignal.timeout(10000)
    });

    const data = await response.json();
    loadingSpinner.style.display = "none";

    if (!response.ok) {
      errorMsg.textContent   = data.error || "An error occurred.";
      errorMsg.style.display = "block";
      setLiveIndicator("error");
      isChecking = false;
      return;
    }

    displayResult(data);
    setLiveIndicator(data.is_safe ? "safe" : "phishing");

  } catch (err) {
    loadingSpinner.style.display = "none";
    if (err.name === "TimeoutError") {
      errorMsg.textContent = "Request timed out. Is the backend running?";
    } else {
      errorMsg.textContent = "Failed to connect to the server. Is the backend running?";
    }
    errorMsg.style.display = "block";
    setLiveIndicator("offline");
  }

  isChecking = false;
}

// ── Display result ────────────────────────────────────────────────────────────
function displayResult(data) {
  const resultPanel    = document.getElementById("resultPanel");
  const resultIcon     = document.getElementById("resultIcon");
  const resultLabel    = document.getElementById("resultLabel");
  const statConfidence = document.getElementById("statConfidence");
  const statModel      = document.getElementById("statModel");
  const statLatency    = document.getElementById("statLatency");
  const confidenceBar  = document.getElementById("confidenceBar");
  const confidencePct  = document.getElementById("confidencePct");
  const resultUrl      = document.getElementById("resultUrl");

  resultPanel.classList.remove("safe", "danger");
  confidenceBar.classList.remove("safe-bg", "danger-bg");

  if (data.is_safe) {
    resultPanel.classList.add("safe");
    resultIcon.textContent  = "✓";
    resultLabel.textContent = "Safe / Legitimate";
    confidenceBar.style.backgroundColor = "#10b981";
  } else {
    resultPanel.classList.add("danger");
    resultIcon.textContent  = "⚠";
    resultLabel.textContent = "Phishing Detected";
    confidenceBar.style.backgroundColor = "#ef4444";
  }

  statConfidence.textContent  = `${data.confidence.toFixed(2)}%`;
  statModel.textContent       = data.model_used;
  statLatency.textContent     = `${data.latency_ms.toFixed(1)} ms`;
  confidenceBar.style.width   = `${data.confidence}%`;
  confidencePct.textContent   = `${data.confidence.toFixed(1)}%`;
  resultUrl.textContent       = data.url;
  resultPanel.style.display   = "block";
}

// ── Batch check ───────────────────────────────────────────────────────────────
async function checkBatch() {
  const batchInput   = document.getElementById("batchInput").value;
  const batchResults = document.getElementById("batchResults");

  const urls = batchInput.split("\n").map(l => l.trim()).filter(l => l.length > 0);

  if (urls.length === 0) {
    batchResults.innerHTML = `<div class="error-msg" style="display:block">Please enter at least one URL.</div>`;
    return;
  }
  if (urls.length > 100) {
    batchResults.innerHTML = `<div class="error-msg" style="display:block">Maximum 100 URLs allowed per batch.</div>`;
    return;
  }

  batchResults.innerHTML = `<div class="spinner-wrap" style="display:flex"><div class="spinner"></div><span>Processing ${urls.length} URLs…</span></div>`;

  try {
    const response = await fetch(`${API_URL}/predict/batch`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ urls, model: selectedModel })
    });

    const data = await response.json();

    if (!response.ok) {
      batchResults.innerHTML = `<div class="error-msg" style="display:block">${data.error || "An error occurred."}</div>`;
      return;
    }

    let html = `<div class="batch-results-list" style="margin-top:1rem;display:flex;flex-direction:column;gap:.5rem;">`;

    data.results.forEach(res => {
      const color = res.is_safe ? "#10b981" : "#ef4444";
      const icon  = res.is_safe ? "✓" : "⚠";
      html += `
        <div style="border:1px solid #e2e8f0;border-left:4px solid ${color};padding:10px;border-radius:4px;background:white;display:flex;align-items:center;justify-content:space-between;">
          <div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:70%;">
            <strong style="color:${color}">${icon} ${res.verdict.toUpperCase()}</strong><br>
            <span style="font-size:.9em;color:#64748b;">${res.url}</span>
          </div>
          <div style="text-align:right;font-size:.9em;color:#475569;">
            Conf: <strong>${res.confidence.toFixed(1)}%</strong><br>
            Lat: ${res.latency_ms.toFixed(1)}ms
          </div>
        </div>`;
    });

    data.errors.forEach(err => {
      html += `
        <div style="border:1px solid #e2e8f0;border-left:4px solid #f59e0b;padding:10px;border-radius:4px;background:white;">
          <strong style="color:#f59e0b;">Error</strong><br>
          <span style="font-size:.9em;color:#64748b;">${err.url}</span>
          <p style="margin:4px 0 0;font-size:.85em;color:#ef4444;">${err.error}</p>
        </div>`;
    });

    html += `</div>`;
    batchResults.innerHTML = html;

  } catch {
    batchResults.innerHTML = `<div class="error-msg" style="display:block">Failed to connect to the server.</div>`;
  }
}
