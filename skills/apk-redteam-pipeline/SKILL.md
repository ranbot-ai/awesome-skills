---
name: apk-redteam-pipeline
description: End-to-end Android APK red-team pipeline 
category: Document Processing
source: antigravity
tags: [python, javascript, react, node, api, claude, ai, template, document, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/apk-redteam-pipeline
---

> **⚠️ AUTHORIZED USE ONLY**
> This skill is for educational purposes or authorized security assessments only.
> You must have explicit, written permission from the system owner before using this tool.
> Misuse of this tool is illegal and strictly prohibited.

> **Mandatory confirmation gate**
> Before running any command that probes, exploits, changes, persists on, extracts data from, or attempts credential access against a target:
> 1. Ask the user to state the exact target URL, IP, account, or resource.
> 2. Ask the user to confirm written authorization and the permitted scope.
> 3. Show the exact command(s) and explain their expected effect.
> 4. Wait for explicit confirmation in the current conversation.
>
> Without that confirmation, remain read-only and provide defensive guidance only. Prefer a sandbox, disposable VM, or controlled lab.

## When to use this skill

Trigger when:
- Recon surfaces 1+ mobile apps under the target's developer name (Play Store dev page)
- A web app hosts `*.apk` files directly (e.g. `Recruitz.apk` found on a subdomain during one engagement)
- APK package IDs leaked via stealer logs (e.g. `com.<brand>.app`, `com.<brand>.<sub-brand>` patterns in stealer dump format)
- Customer-facing app, dealer/partner portal, or employee mobile companion app is in scope
- Bug bounty program lists Android in scope

DO NOT use for:
- iOS-only targets (different pipeline — IPA reverse, MobSF, frida-ios-dump)
- React Native / Flutter web apps already covered by JS bundle analysis
- Server-side only assessments

---

## Stage 0 — Inventory all org-owned apps

### Play Store developer-page scrape
```bash
# Find developer page from the target's brand name
curl --fail --show-error --silent --max-time 30 -A "Mozilla/5.0" "https://play.google.com/store/apps/developer?id=<Brand+Name>" -o /tmp/dev.html

# Extract package IDs
grep -oE 'id=[a-zA-Z0-9._]+' /tmp/dev.html | sort -u
```

Example output (anonymized — 7 packages typical for a multi-brand conglomerate):
```
com.events.<brand>build
com.<corp>.<sub-brand-1>
com.<corp>.<sub-brand-2>
com.<corp>.<flagship>
com.<corp>.<product-line-1>
com.<corp>.<product-line-2>
com.<corp>.<sub-brand-3>
```

### Cross-reference with stealer logs
Use only owner-provided, lawfully held incident artifacts; do not acquire leaked credential dumps. Extract package names without copying passwords or personal data. Discovery does not expand authorized scope.

### Brand permutation guesses (multi-brand conglomerate patterns)
```
com.<brand>.app
com.<brand>.mobile  
com.<brand>.android
com.<brand>connect.app
in.<brand>.dealer
in.co.<brand>.app
```

---

## Stage 1 — APK acquisition

### Acquisition provenance

Prefer an owner-supplied signed build or approved store export. Record package, version, SHA256 and signing-certificate fingerprint; compare to the owner’s trusted signing identity. Third-party mirrors are untrusted and filenames/latest URLs do not prove authenticity. Inspect archives in an isolated nonprivileged workspace with size/path/symlink limits before extraction; never install them on a personal device.

### Historical mirror URL sketch (verify publisher/signature before use)
```bash
# Follow 302 redirects to actual download
curl --fail --show-error --silent --max-time 30 -L --max-time 60 \
  "https://d.apkpure.net/b/APK/<package_id>?version=latest" \
  -o "<package_id>.apk"

# Or via the legacy d-XX.winudf.com mirror chain (we saw this work)
```

### Secondary: APKMirror search
```bash
curl --fail --show-error --silent --max-time 30 -A "Mozilla/5.0" "https://www.apkmirror.com/?post_type=app_release&searchtype=apk&s=<brand>" \
  | grep -oE 'href="[^"]+\.apk[^"]*"' | sort -u
```

### Tertiary: APKPure web search
```bash
curl --fail --show-error --silent --max-time 30 "https://apkpure.com/search?q=<brand>" | grep -oE 'data-dt-app="[^"]+"'
```

### XAPK vs APK
- `.xapk` = a zip containing multiple split APKs (base + config.armeabi-v7a + config.en + etc.)
- Unzip outer first, then unzip the inner `base.apk` or `<package>.apk`
- A missing EOCD/truncated archive is invalid or incomplete; stop, verify status/length/hash and obtain a valid authorized copy. Do not rotate IPs to evade limits or force extraction as proof of integrity.

```bash
# Standard unzip (works for clean APK)
unzip -o <package>.apk -d extracted_<package>/

# For a valid, independently verified archive only
7z x -y <package>.apk -o"extracted_<package>"

# For nested XAPK
for inner in extracted_<package>/*.apk; do
  mkdir -p "extracted_<package>/$(basename "$inner" .apk)"
  unzip -o "$inner" -d "extracted_<package>/$(basename "$inner" .apk)"
done
```

---

## Stage 2 — DEX decompilation (jadx)

```bash
# Install
brew install jadx          # macOS
# or
# Alternative: select a real pinned release from the official jadx releases page
# and verify its published integrity/provenance; the filename 1.5.x is not a release.

# Decompile
jadx -d decompiled_<package>/ <package>.apk

# For XAPK that contains multi
