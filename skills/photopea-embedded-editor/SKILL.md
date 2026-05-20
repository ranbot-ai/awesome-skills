---
name: photopea-embedded-editor
description: Embed Photopea in web apps using photopea.js. Covers embedding, file I/O, scripting, exporting, layers, text, filters, and the full Photoshop-compatible API. 
category: Document Processing
source: antigravity
tags: [javascript, react, api, ai, agent, workflow, template, design, document, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/photopea-embedded-editor
---


# Photopea Embedded Editor Skill
## Using photopea.js (yikuansun/PhotopeaAPI) in Websites & Apps

---

## When to Use This Skill

Use this skill for **every task** that involves:
- Embedding Photopea as an image editor inside a webpage or web app
- Controlling an embedded Photopea instance from your JavaScript code
- Automating image editing workflows from a host page (open files, run scripts, export results)
- Building an image editing feature into your product using Photopea as the engine
- Writing scripts to manipulate documents, layers, text, selections, filters, colors, and paths

**Do NOT** use raw `postMessage` wiring — always use `photopea.js` as the wrapper.

---

## Library: photopea.js

`photopea.js` is a Promises-based JavaScript wrapper around the Photopea Live Messaging API.
Repository: https://github.com/yikuansun/PhotopeaAPI
npm package: https://www.npmjs.com/package/photopea

### Installation

**CDN (no build step)**
```html
<script src="https://cdn.jsdelivr.net/npm/photopea@1.1.1/dist/photopea.min.js"></script>
```

**Self-hosted**
```html
<script src="./photopea.min.js"></script>
```

**npm (Webpack / Vite / Rollup)**
```bash
npm install photopea
```
```js
import Photopea from "photopea";
```

---

## Core API: The `Photopea` Class

| Method | Description |
|--------|-------------|
| `Photopea.createEmbed(container)` | Creates + injects the iframe, resolves when ready |
| `new Photopea(window.parent)` | Plugin mode: wrap the parent window |
| `pea.runScript(script)` | Run JS string inside Photopea; returns output array |
| `pea.loadAsset(arrayBuffer)` | Load binary file (image, font, brush, etc.) |
| `pea.openFromURL(url, asSmart)` | Open remote URL as new doc or smart object layer |
| `pea.exportImage(type)` | Export current doc; returns `Blob` (`"png"` or `"jpg"`) |

All methods return Promises — always `await` or `.then()`.

---

## Step 1 — Embed

The container `<div>` **must** have a fixed width and height before calling `createEmbed`.

```html
<div id="editor" style="width:1000px; height:650px;"></div>
<script src="https://cdn.jsdelivr.net/npm/photopea@1.1.1/dist/photopea.min.js"></script>
<script>
  Photopea.createEmbed(document.getElementById("editor")).then(async (pea) => {
    // pea is ready
  });
</script>
```

**React:**
```jsx
import { useEffect, useRef } from "react";
import Photopea from "photopea";

export default function Editor() {
  const containerRef = useRef(null);
  const peaRef       = useRef(null);

  useEffect(() => {
    if (!containerRef.current || peaRef.current) return;
    Photopea.createEmbed(containerRef.current).then((pea) => {
      peaRef.current = pea;
    });
  }, []);

  return <div ref={containerRef} style={{ width: "100%", height: "650px" }} />;
}
```

---

## Step 2 — Opening Files

```js
// Remote URL → new document
await pea.openFromURL("https://example.com/design.psd", false);

// Remote URL → smart object layer inside current document
await pea.openFromURL("https://example.com/overlay.png", true);

// Local file (user input → ArrayBuffer → loadAsset)
document.getElementById("fileInput").addEventListener("change", async (e) => {
  const buf = await e.target.files[0].arrayBuffer();
  await pea.loadAsset(buf);
});

// Base64 data URI via runScript
await pea.runScript(`app.open("data:image/png;base64,iVBORw0...");`);
```

---

## Step 3 — Running Scripts

`runScript` sends a JS string, returns an array of `app.echoToOE(...)` values + `"done"` last.

```js
const result = await pea.runScript(`app.echoToOE("hello");`);
// result → ["hello", "done"]

// Return structured data
const out = await pea.runScript(`
  app.echoToOE(JSON.stringify({
    width:  app.activeDocument.width,
    height: app.activeDocument.height,
    layers: app.activeDocument.layers.length
  }));
`);
const info = JSON.parse(out[0]);
```

---

## Step 4 — Exporting

```js
// PNG Blob (via exportImage)
const blob = await pea.exportImage("png");
document.getElementById("preview").src = URL.createObjectURL(blob);

// JPEG Blob
const blob = await pea.exportImage("jpg");

// WebP / PSD / quality-controlled JPEG via saveToOE
const result = await pea.runScript(`app.activeDocument.saveToOE("webp:0.85");`);
const webpBlob = new Blob([result[0]], { type: "image/webp" });

const result = await pea.runScript(`app.activeDocument.saveToOE("psd:true");`);
const psdBlob  = new Blob([result[0]], { type: "application/octet-stream" });

// Trigger download
async function download(pea, filename = "export.png") {
  const blob = await pea.exportImage("png");
  const a    = Object.assign(document.createElement("a"), {
    href:     URL.createObjectURL(blob),
    download: filename
  });
  a.click();
}
```

**Export format strings for `saveToOE`:**

| String | Format |
|--------|--------|
| `"png"` | PNG lossless |
| `"jpg"` | JPEG default |
| `"jpg:0.8"` | JPEG quality 0.0–1.0 |
| `"webp:0.7"` | WebP quality 0.0–1.0 |
| `"psd"` | Full PSD |
| `"psd:true"` | Minified PSD |
| `"svg:true"` | SVG |

---

##
