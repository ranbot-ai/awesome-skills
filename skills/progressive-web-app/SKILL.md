---
name: progressive-web-app
description: Build Progressive Web Apps (PWAs) with offline support, installability, and caching strategies. Trigger whenever the user mentions PWA, service workers, web app manifests, Workbox, 'add to home screen
category: Document Processing
source: antigravity
tags: [javascript, api, claude, ai, document, image, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/progressive-web-app
---


# Progressive Web Apps (PWAs)

## Overview

A Progressive Web App is a web application that uses modern browser capabilities to deliver a fast, reliable, and installable experience — even on unreliable networks. The three required pillars are:

1. **HTTPS** — Required in production for service workers to register (localhost is exempt for development).
2. **Web App Manifest** (`manifest.json`) — Makes the app installable and defines its appearance on device home screens.
3. **Service Worker** (`sw.js`) — A background script that intercepts network requests, manages caches, and enables offline functionality.

## When to Use This Skill

- Use when the user wants their web app to work offline or on unreliable networks.
- Use when building a mobile-first web project where users should be able to install the app to their home screen.
- Use when the user asks about caching strategies, service workers, or improving web app performance and resilience.
- Use when the user mentions Workbox, web app manifests, background sync, or push notifications for the web.
- Use when the user asks "can my website be installed like an app?" or "how do I make my site work offline?" — even if they don't use the word PWA.

## Deliverables Checklist

Every PWA implementation must include these files at minimum:

- [ ] `index.html` — Links manifest, registers service worker
- [ ] `manifest.json` — Full app metadata and icon set
- [ ] `sw.js` — Service worker with install, activate, and fetch handlers
- [ ] `app.js` — Main app logic with SW registration and install prompt handling
- [ ] `offline.html` — Fallback page shown when navigation fails offline (required — missing file will cause install to fail)

---

## Step 1: Web App Manifest (`manifest.json`)

Defines how the app appears when installed. Must be linked from `<head>` via `<link rel="manifest">`.

```json
{
  "name": "My Awesome PWA",
  "short_name": "MyPWA",
  "description": "A fast, offline-capable Progressive Web App.",
  "start_url": "/",
  "scope": "/",
  "display": "standalone",
  "orientation": "portrait-primary",
  "background_color": "#ffffff",
  "theme_color": "#0055ff",
  "icons": [
    {
      "src": "/assets/icons/icon-192x192.png",
      "sizes": "192x192",
      "type": "image/png",
      "purpose": "any maskable"
    },
    {
      "src": "/assets/icons/icon-512x512.png",
      "sizes": "512x512",
      "type": "image/png",
      "purpose": "any maskable"
    }
  ],
  "screenshots": [
    {
      "src": "/assets/screenshots/desktop.png",
      "sizes": "1280x720",
      "type": "image/png",
      "form_factor": "wide"
    }
  ]
}
```

**Key fields:**
- `display`: `standalone` hides browser UI; `minimal-ui` shows minimal controls; `browser` is standard tab.
- `purpose: "maskable"` on icons enables adaptive icons on Android (safe zone matters — keep content in center 80%).
- `screenshots` is optional but required for Chrome's enhanced install dialog on desktop.

---

## Step 2: HTML Shell (`index.html`)

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>My Awesome PWA</title>

  <!-- PWA manifest -->
  <link rel="manifest" href="/manifest.json">

  <!-- Theme color for browser chrome -->
  <meta name="theme-color" content="#0055ff">

  <!-- iOS-specific (Safari doesn't fully use manifest) -->
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="default">
  <meta name="apple-mobile-web-app-title" content="MyPWA">
  <link rel="apple-touch-icon" href="/assets/icons/icon-192x192.png">

  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <div id="app">
    <header><h1>My PWA</h1></header>
    <main id="content">Loading...</main>
    <!-- Optional: install button, hidden by default -->
    <button id="install-btn" hidden>Install App</button>
  </div>
  <script src="/app.js"></script>
</body>
</html>
```

---

## Step 3: Service Worker Registration & Install Prompt (`app.js`)

```javascript
// ─── Service Worker Registration ───────────────────────────────────────────
if ('serviceWorker' in navigator) {
  window.addEventListener('load', async () => {
    try {
      const registration = await navigator.serviceWorker.register('/sw.js');
      console.log('[App] SW registered, scope:', registration.scope);
    } catch (err) {
      console.error('[App] SW registration failed:', err);
    }
  });
}

// ─── Install Prompt (Add to Home Screen) ───────────────────────────────────
let deferredPrompt;
const installBtn = document.getElementById('install-btn'); // may be null if omitted

// Capture the browser's install prompt — it fires before the browser's own UI
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault(); // Stop automatic mini-infobar on mobile
  deferredPrompt = e;
  if (installBtn) installBtn.hidden = false; // Show your custom install button
});

if (installBt
