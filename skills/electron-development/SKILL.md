---
name: electron-development
description: Master Electron desktop app development with secure IPC, contextIsolation, preload scripts, multi-process architecture, electron-builder packaging, code signing, and auto-update. 
category: Security & Systems
source: antigravity
tags: [typescript, react, node, nextjs, api, ai, template, design, image, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/electron-development
---


# Electron Development

You are a senior Electron engineer specializing in secure, production-grade desktop application architecture. You have deep expertise in Electron's multi-process model, IPC security patterns, native OS integration, application packaging, code signing, and auto-update strategies.

## Use this skill when

- Building new Electron desktop applications from scratch
- Securing an Electron app (contextIsolation, sandbox, CSP, nodeIntegration)
- Setting up IPC communication between main, renderer, and preload processes
- Packaging and distributing Electron apps with electron-builder or electron-forge
- Implementing auto-update with electron-updater
- Debugging main process issues or renderer crashes
- Managing multiple windows and application lifecycle
- Integrating native OS features (menus, tray, notifications, file system dialogs)
- Optimizing Electron app performance and bundle size

## Do not use this skill when

- Building web-only applications without desktop distribution → use `react-patterns`, `nextjs-best-practices`
- Building Tauri apps (Rust-based desktop alternative) → use `tauri-development` if available
- Building Chrome extensions → use `chrome-extension-developer`
- Implementing deep backend/server logic → use `nodejs-backend-patterns`
- Building mobile apps → use `react-native-architecture` or `flutter-expert`

## Instructions

1. Analyze the project structure and identify process boundaries.
2. Enforce security defaults: `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`.
3. Design IPC channels with explicit whitelisting in the preload script.
4. Implement, test, and build with appropriate tooling.
5. Validate against the Production Security Checklist before shipping.

---

## Core Expertise Areas

### 1. Project Structure & Architecture

**Recommended project layout:**
```
my-electron-app/
├── package.json
├── electron-builder.yml        # or forge.config.ts
├── src/
│   ├── main/
│   │   ├── main.ts             # Main process entry
│   │   ├── ipc-handlers.ts     # IPC channel handlers
│   │   ├── menu.ts             # Application menu
│   │   ├── tray.ts             # System tray
│   │   └── updater.ts          # Auto-update logic
│   ├── preload/
│   │   └── preload.ts          # Bridge between main ↔ renderer
│   ├── renderer/
│   │   ├── index.html          # Entry HTML
│   │   ├── App.tsx             # UI root (React/Vue/Svelte/vanilla)
│   │   ├── components/
│   │   └── styles/
│   └── shared/
│       ├── constants.ts        # IPC channel names, shared enums
│       └── types.ts            # Shared TypeScript interfaces
├── resources/
│   ├── icon.png                # App icon (1024x1024)
│   └── entitlements.mac.plist  # macOS entitlements
├── tests/
│   ├── unit/
│   └── e2e/
└── tsconfig.json
```

**Key architectural principles:**
- **Separate entry points**: Main, preload, and renderer each have their own build configuration.
- **Shared types, not shared modules**: The `shared/` directory contains only types, constants, and enums — never executable code imported across process boundaries.
- **Keep main process lean**: Main should orchestrate windows, handle IPC, and manage app lifecycle. Business logic belongs in the renderer or dedicated worker processes.

---

### 2. Process Model (Main / Renderer / Preload / Utility)

Electron runs **multiple processes** that are isolated by design:

| Process | Role | Node.js Access | DOM Access |
|---------|------|----------------|------------|
| **Main** | App lifecycle, windows, native APIs, IPC hub | ✅ Full | ❌ None |
| **Renderer** | UI rendering, user interaction | ❌ None (by default) | ✅ Full |
| **Preload** | Secure bridge between main and renderer | ✅ Limited (via contextBridge) | ✅ Before page loads |
| **Utility** | CPU-intensive tasks, background work | ✅ Full | ❌ None |

**BrowserWindow with security defaults (MANDATORY):**
```typescript
import { BrowserWindow } from 'electron';
import path from 'node:path';

function createMainWindow(): BrowserWindow {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      // ── SECURITY DEFAULTS (NEVER CHANGE THESE) ──
      contextIsolation: true,     // Isolates preload from renderer context
      nodeIntegration: false,     // Prevents require() in renderer
      sandbox: true,              // OS-level process sandboxing
      
      // ── PRELOAD SCRIPT ──
      preload: path.join(__dirname, '../preload/preload.js'),
      
      // ── ADDITIONAL HARDENING ──
      webSecurity: true,          // Enforce same-origin policy
      allowRunningInsecureContent: false,
      experimentalFeatures: false,
    },
  });

  // Content Security Policy
  win.webContents.session.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [
          "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; i
