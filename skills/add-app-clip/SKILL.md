---
name: add-app-clip
description: Add an iOS App Clip target to an Expo app. Use when the user mentions App Clip, AASA, apple-app-site-association, appclips, smart app banner, or wants to ship a lightweight iOS Clip invoked from a URL
category: Document Processing
source: antigravity
tags: [typescript, react, node, api, ai, template, document, image, security, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/add-app-clip
---


# Add an App Clip to an Expo App
## When to Use

Use this skill when you need add an iOS App Clip target to an Expo app. Use when the user mentions App Clip, AASA, apple-app-site-association, appclips, smart app banner, or wants to ship a lightweight iOS Clip invoked from a URL alongside their parent app.


Adds an iOS App Clip target to an Expo project. The Clip lives in `targets/clip/`, ships alongside the parent app, and is invoked from a URL on the app's domain via an Apple App Site Association (AASA) file.

The parent app's bundle ID becomes `com.<username>.<app-name>` and the Clip's is automatically derived as `<parent>.clip` (e.g. `com.bacon.may20.clip`).

## 1. Set `bundleIdentifier` and `appleTeamId`

`bun create target` warns if these are missing. Add to `app.json`:

```json
{
  "expo": {
    "ios": {
      "bundleIdentifier": "com.<username>.<app-name>",
      "appleTeamId": "XX57RJ5UTD"
    }
  }
}
```

## 2. Add the App Clip target

```sh
bun create target clip
```

This installs [`@bacons/apple-targets`](https://github.com/EvanBacon/expo-apple-targets), adds it to the `plugins` array in `app.json`, and writes:

- `targets/clip/expo-target.config.js` — the target's config plugin
- `targets/clip/Info.plist` — Clip Info.plist
- `targets/clip/AppDelegate.swift`, `Assets.xcassets`, etc.

Pick a good icon or reuse the existing one defined in the app — check it with `bunx expo config` under the `icon` or `ios.icon` key.

## 3. Wire up associated domains

The parent app and the Clip each need the Associated Domains entitlement pointing at the domain that hosts the AASA file.

In `app.json`, add both `applinks:` (parent) and `appclips:` (Clip invocation) entries:

```json
{
  "expo": {
    "ios": {
      "associatedDomains": [
        "applinks:may20.expo.app",
        "appclips:may20.expo.app"
      ]
    }
  }
}
```

In `targets/clip/expo-target.config.js`, declare the Clip's entitlement:

```js
/** @type {import('@bacons/apple-targets/app.plugin').ConfigFunction} */
module.exports = (config) => ({
  type: "clip",
  icon: "https://github.com/expo.png",
  entitlements: {
    "com.apple.developer.associated-domains": ["appclips:may20.expo.app"],
  },
});
```

> If you skip this, `expo prebuild` will print: `Apple App Clip may require the associated domains entitlement but none were found`.

## 4. Register bundle IDs and create the App Store entry

```sh
bunx setup-safari
```

This logs in to the Apple Developer account, registers `com.bacon.may20`, creates the App Store Connect entry, and prints:

- A starter `apple-app-site-association` JSON
- A `<meta name="apple-itunes-app">` tag with the iTunes app id
- Team ID, iTunes ID, and Bundle ID

## 5. Host the AASA file

App Clips are invoked when iOS fetches `https://<your-domain>/.well-known/apple-app-site-association` and finds a matching `appclips` entry.

```sh
mkdir -p public/.well-known
touch public/.well-known/apple-app-site-association
```

Paste the JSON `setup-safari` printed, but **add an `appclips` block** for the Clip's full app ID (`<TeamID>.<ClipBundleID>`). The output of `setup-safari` only covers the parent app:

```json
{
  "applinks": {
    "details": [
      {
        "appIDs": ["XX57RJ5UTD.com.bacon.may20"],
        "components": [{ "/": "*", "comment": "Matches all routes" }]
      }
    ]
  },
  "appclips": {
    "apps": ["XX57RJ5UTD.com.bacon.may20.clip"]
  },
  "activitycontinuation": {
    "apps": ["XX57RJ5UTD.com.bacon.may20"]
  },
  "webcredentials": {
    "apps": ["XX57RJ5UTD.com.bacon.may20"]
  }
}
```

Notes:

- The file has **no extension** and **no `Content-Type` requirements** beyond being served as-is. Expo Router static export serves files in `public/` verbatim.
- The `appclips` block is what lets a URL on the domain launch the Clip.
- `webcredentials` is used for sharing credentials between the website, parent app, and the App Clip.
- `activitycontinuation` is optional and used for sharing the link between mobile and desktop. Must be used with `Head` from expo-router — see https://docs.expo.dev/router/advanced/apple-handoff/
- Notation and route-disabling details: https://sosumi.ai/documentation/xcode/supporting-associated-domains

## 6. Add the Smart App Banner meta tag

Create `src/app/+html.tsx` (Expo Router's HTML shell) and add the tag from `setup-safari`. Create the versioned template if it doesn't exist:

```sh
bunx expo customize src/app/+html.tsx
```

Add the meta tag to the `<head>`:

```tsx
import { ScrollViewStyleReset } from "expo-router/html";

export default function Root({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <meta charSet="utf-8" />
        <meta httpEquiv="X-UA-Compatible" content="IE=edge" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="apple-itunes-app" content="app-id=6771566491" />
        <ScrollViewStyleReset />
      </head>
      <body>{children}</body>
    </html>
  );
}
```

To
