# PhishGuard — Browser Extension Setup Guide

## ✅ What Was Built

### 1. Browser Extension (`extension/` folder)
Automatically detects phishing URLs as you navigate — **no typing, no clicking**.

| Feature | Details |
|---|---|
| Auto-scan | Every page you visit is checked against the backend |
| Badge alert | Green ✓ = safe, Red ! = phishing, Purple … = scanning |
| Desktop notifications | Alerts you instantly when a phishing page is detected |
| Popup | Click the extension icon to see verdict, confidence, model, and history |
| Model selector | Switch between SVC, Logistic Regression, and Decision Tree inside the popup |
| Enable/disable toggle | Turn detection on/off without removing the extension |

### 2. Enhanced Web UI (`frontend/`)
- **Auto-detects as you type** (600ms debounce — no need to click Scan)
- Live status dot shows: Ready → Scanning → Safe / Phishing!
- Backend health is checked on load; warns if backend is offline

---

## 🚀 Setup Instructions

### Step 1 — Start the Backend
```powershell
cd C:\Users\DELL\Desktop\Phishing_Detection\backend
python app.py
```
Keep this terminal open. The API runs at `http://localhost:5000`.

### Step 2 — Open the Web App
Open `frontend/index.html` in your browser. Start typing any URL — it auto-detects!

### Step 3 — Install the Browser Extension

#### Chrome / Edge / Brave:
1. Open your browser and go to: `chrome://extensions` (Chrome/Brave) or `edge://extensions` (Edge)
2. Enable **Developer Mode** (toggle in top-right)
3. Click **"Load unpacked"**
4. Select the folder: `C:\Users\DELL\Desktop\Phishing_Detection\extension`
5. The 🛡 PhishGuard icon will appear in your toolbar

#### First Use:
- Navigate to any website
- The extension auto-scans the URL and shows a badge:
  - 🟢 `✓` — Safe
  - 🔴 `!` — Phishing detected (+ desktop notification)
  - 🟣 `…` — Scanning
  - ⚫ `–` — Backend offline (start `app.py` first)

---

## 📁 File Structure

```
Phishing_Detection/
├── backend/
│   └── app.py              ← Flask API (+ SSE /stream endpoint)
├── frontend/
│   ├── index.html          ← Web UI (auto-detect as you type)
│   └── static/
│       ├── script.js       ← Live debounced detection logic
│       └── style.css
└── extension/              ← Browser Extension (NEW)
    ├── manifest.json       ← Extension config (Manifest V3)
    ├── background.js       ← Service worker: auto-scans tabs
    ├── popup.html          ← Extension popup UI
    ├── popup.js            ← Popup logic
    └── icons/
        ├── icon16.png
        ├── icon48.png
        └── icon128.png
```

---

## ⚠️ Important Notes

- The backend **must be running** (`python app.py`) for detection to work
- The extension uses `http://localhost:5000` — same as the web UI
- Chrome may block `http://` (non-HTTPS) in some settings; if the badge shows `–`, check that `app.py` is running
- The extension **does not** collect or send data anywhere except your local backend
