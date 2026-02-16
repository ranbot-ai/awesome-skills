---
name: go-rod-master
description: Comprehensive guide for browser automation and web scraping with go-rod (Chrome DevTools Protocol) including stealth anti-bot-detection patterns. 
category: Document Processing
source: antigravity
tags: [javascript, react, pdf, api, ai, agent, automation, design, document, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/go-rod-master
---


# Go-Rod Browser Automation Master

## Overview

[Rod](https://github.com/go-rod/rod) is a high-level Go driver built directly on the [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/) for browser automation and web scraping. Unlike wrappers around other tools, Rod communicates with the browser natively via CDP, providing thread-safe operations, chained context design for timeouts/cancellation, auto-wait for elements, correct iframe/shadow DOM handling, and zero zombie browser processes.

The companion library [go-rod/stealth](https://github.com/go-rod/stealth) injects anti-bot-detection evasions based on [puppeteer-extra stealth](https://github.com/nichochar/puppeteer-extra/tree/master/packages/extract-stealth-evasions), hiding headless browser fingerprints from detection systems.

## When to Use This Skill

- Use when the user asks to **scrape**, **automate**, or **test** a website using Go.
- Use when the user needs a **headless browser** for dynamic/SPA content (React, Vue, Angular).
- Use when the user mentions **stealth**, **anti-bot**, **avoiding detection**, **Cloudflare**, or **bot detection bypass**.
- Use when the user wants to work with the **Chrome DevTools Protocol (CDP)** directly from Go.
- Use when the user needs to **intercept** or **hijack** network requests in a browser context.
- Use when the user asks about **concurrent browser scraping** or **page pooling** in Go.
- Use when the user is migrating from **chromedp** or **Playwright Go** and wants a simpler API.

## Safety & Risk

**Risk Level: 🔵 Safe**

- **Read-Only by Default:** Default behavior is navigating and reading page content (scraping/testing).
- **Isolated Contexts:** Browser contexts are sandboxed; cookies and storage do not persist unless explicitly saved.
- **Resource Cleanup:** Designed around Go's `defer` pattern — browsers and pages close automatically.
- **No External Mutations:** Does not modify external state unless the script explicitly submits forms or POSTs data.

## Installation

```bash
# Core rod library
go get github.com/go-rod/rod@latest

# Stealth anti-detection plugin (ALWAYS include for production scraping)
go get github.com/go-rod/stealth@latest
```

Rod auto-downloads a compatible Chromium binary on first run. To pre-download:

```bash
go run github.com/nichochar/go-rod.github.io/cmd/launcher@latest
```

## Core Concepts

### Browser Lifecycle

Rod manages three layers: **Browser → Page → Element**.

```go
// Launch and connect to a browser
browser := rod.New().MustConnect()
defer browser.MustClose()

// Create a page (tab)
page := browser.MustPage("https://example.com")

// Find an element
el := page.MustElement("h1")
fmt.Println(el.MustText())
```

### Must vs Error Patterns

Rod provides two API styles for every operation:

| Style | Method | Use Case |
|:------|:-------|:---------|
| **Must** | `MustElement()`, `MustClick()`, `MustText()` | Scripting, debugging, prototyping. Panics on error. |
| **Error** | `Element()`, `Click()`, `Text()` | Production code. Returns `error` for explicit handling. |

**Production pattern:**

```go
el, err := page.Element("#login-btn")
if err != nil {
    return fmt.Errorf("login button not found: %w", err)
}
if err := el.Click(proto.InputMouseButtonLeft, 1); err != nil {
    return fmt.Errorf("click failed: %w", err)
}
```

**Scripting pattern with Try:**

```go
err := rod.Try(func() {
    page.MustElement("#login-btn").MustClick()
})
if errors.Is(err, context.DeadlineExceeded) {
    log.Println("timeout finding login button")
}
```

### Context & Timeout

Rod uses Go's `context.Context` for cancellation and timeouts. Context propagates recursively to all child operations.

```go
// Set a 5-second timeout for the entire operation chain
page.Timeout(5 * time.Second).
    MustWaitLoad().
    MustElement("title").
    CancelTimeout(). // subsequent calls are not bound by the 5s timeout
    Timeout(30 * time.Second).
    MustText()
```

### Element Selectors

Rod supports multiple selector strategies:

```go
// CSS selector (most common)
page.MustElement("div.content > p.intro")

// CSS selector with text regex matching
page.MustElementR("button", "Submit|Send")

// XPath
page.MustElementX("//div[@class='content']//p")

// Search across iframes and shadow DOM (like DevTools Ctrl+F)
page.MustSearch(".deeply-nested-element")
```

### Auto-Wait

Rod automatically retries element queries until the element appears or the context times out. You do not need manual sleeps:

```go
// This will automatically wait until the element exists
el := page.MustElement("#dynamic-content")

// Wait until the element is stable (position/size not changing)
el.MustWaitStable().MustClick()

// Wait until page has no pending network requests
wait := page.MustWaitRequestIdle()
page.MustElement("#search").MustInput("query")
wait()
```

---

## Stealth & Anti-Bot Detection (go-rod/stealth)

> **IMPORTANT:** For any production scraping or automation against real websit
