---
name: applicationinsights-web-ts
description: Instrument browser/web apps with the Application Insights JavaScript SDK (@microsoft/applicationinsights-web). Use for Real User Monitoring (RUM) — page views, clicks, AJAX/fetch dependencies, excep
category: AI & Agents
source: antigravity
tags: [javascript, typescript, react, node, api, mcp, ai, agent, gpt, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/applicationinsights-web-ts
---


# Application Insights JavaScript SDK (Web) for TypeScript
## When to Use

Use this skill when you need instrument browser/web apps with the Application Insights JavaScript SDK (@microsoft/applicationinsights-web). Use for Real User Monitoring (RUM) — page views, clicks, AJAX/fetch dependencies, exceptions, custom events, and browser-side GenAI agent traces correlated to backend...


Real User Monitoring (RUM) for browser apps with `@microsoft/applicationinsights-web`. Auto-collects page views, AJAX/fetch dependencies, unhandled exceptions, and (with the Click Analytics plugin) clicks. Supports custom events, metrics, and **GenAI agent traces** that follow OpenTelemetry GenAI semantic conventions and correlate to backend spans via W3C Trace Context.

> **Distinct from `azure-monitor-opentelemetry-ts`**, which is for Node.js server apps. This skill is for **browser/web** code (and React Native).

## Before Implementation

Search `microsoft-docs` MCP for current API patterns:

- Query: "Application Insights JavaScript SDK setup"
- Query: "Application Insights JavaScript SDK configuration"
- Query: "Application Insights JavaScript framework extensions React Angular"
- Verify package version: `npm view @microsoft/applicationinsights-web version`

## Packages

| Package | Purpose |
| --- | --- |
| `@microsoft/applicationinsights-web` | Core RUM SDK (page views, AJAX, exceptions). |
| `@microsoft/applicationinsights-clickanalytics-js` | Auto-collect click telemetry. |
| `@microsoft/applicationinsights-react-js` | React plugin (router instrumentation, hooks, HOC, ErrorBoundary). |
| `@microsoft/applicationinsights-react-native` | React Native plugin (native crashes, sessions). |
| `@microsoft/applicationinsights-angularplugin-js` | Angular plugin (router events, ErrorHandler). |
| `@microsoft/applicationinsights-debugplugin-js` | Dev-only telemetry inspector. |
| `@microsoft/applicationinsights-perfmarkmeasure-js` | User Timing (`performance.mark/measure`) integration. |

## Installation

```bash
npm i --save @microsoft/applicationinsights-web
# Optional plugins (install only what you use):
npm i --save @microsoft/applicationinsights-clickanalytics-js
npm i --save @microsoft/applicationinsights-react-js @microsoft/applicationinsights-react-native @microsoft/applicationinsights-angularplugin-js
```

Typings ship with the package — no separate `@types/...` install needed.

## Connection String

The browser SDK requires a connection string at init time. **It ships in plaintext to clients** — Microsoft Entra ID auth is not supported for browser telemetry. Use a separate App Insights resource with local auth enabled for browser RUM if you need to isolate it from backend telemetry.

```bash
# Vite / CRA / Next.js — expose to client via the public env prefix
VITE_APPINSIGHTS_CONNECTION_STRING="InstrumentationKey=...;IngestionEndpoint=https://...;LiveEndpoint=https://..."
NEXT_PUBLIC_APPINSIGHTS_CONNECTION_STRING="InstrumentationKey=..."
```

## Quick Start (npm)

```typescript
import { ApplicationInsights } from "@microsoft/applicationinsights-web";

export const appInsights = new ApplicationInsights({
  config: {
    connectionString: import.meta.env.VITE_APPINSIGHTS_CONNECTION_STRING,
    enableAutoRouteTracking: true,        // SPA route changes -> page views
    enableCorsCorrelation: true,          // propagate Request-Id / traceparent to cross-origin AJAX
    enableRequestHeaderTracking: true,
    enableResponseHeaderTracking: true,
    distributedTracingMode: 2,            // DistributedTracingModes.AI_AND_W3C — emit traceparent for backend correlation
    autoTrackPageVisitTime: true,
    disableFetchTracking: false,          // fetch() is auto-instrumented by default
    excludeRequestFromAutoTrackingPatterns: [/livemetrics\.azure\.com/i]
  }
});

appInsights.loadAppInsights();
appInsights.trackPageView();
```

Call `loadAppInsights()` exactly once, as early as possible (before user interactions you want tracked). Then `trackPageView()` for the initial load — when `enableAutoRouteTracking` is on, subsequent route changes are automatic.

## Quick Start (SDK Loader Script)

Recommended when you want auto-updating SDK and zero build pipeline. Paste this as the **first** `<script>` in `<head>`:

```html
<script type="text/javascript" src="https://js.monitor.azure.com/scripts/b/ai.3.gbl.min.js" crossorigin="anonymous"></script>
<script type="text/javascript">
  var appInsights = window.appInsights || function (cfg) {
    /* See: https://learn.microsoft.com/azure/azure-monitor/app/javascript-sdk
       Use the latest snippet from the Microsoft Learn page above — it includes
       backup-CDN failover (cr), SDK-load-failure reporting, and the queue shim
       so calls before SDK ready are not lost. */
  }({ src: "https://js.monitor.azure.com/scripts/b/ai.3.gbl.min.js",
      crossOrigin: "anonymous",
      cfg: { connectionString: "YOUR_CONNECTION_STRING" } });
</script>
```

Loader-only API (queued until SDK loads):
