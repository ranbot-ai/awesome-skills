---
name: burpsuite-project-parser
description: Searches and explores Burp Suite project files (.burp) from the command line. Use when searching response headers or bodies with regex patterns, extracting security audit findings, dumping proxy histo
category: Security & Systems
source: antigravity
tags: [api, ai, workflow, document, security, vulnerability, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/burpsuite-project-parser
---

## Supporting material availability

This catalog copy contains the inline guidance below, but does not include the following supporting paths. They are external prerequisites, not bundled files:

- `scripts/burp-search.sh` (wrapper; unavailable in this catalog tree)


Ask for the original supporting material or an existing installation before using a step that depends on these paths; this catalog does not identify a verified download source for them. Resolve each path relative to that installation, inspect its contents, and verify any applicable license and execution prerequisites. Do not run a command or claim a referenced procedure was followed until its required file exists. Do not fabricate the missing scripts or treat an unrelated file with the same name as equivalent. Independent steps fully documented here can proceed within the user’s authorized scope; report any dependent step as unavailable.


# Burp Project Parser

Search and extract data from Burp Suite project files using the burpsuite-project-file-parser extension.

## When to Use
- Searching response headers or bodies with regex patterns
- Extracting security audit findings from Burp projects
- Dumping proxy history or site map data
- Analyzing HTTP traffic captured in a Burp project file

## Prerequisites

This skill **delegates parsing to Burp Suite Professional** - it does not parse .burp files directly.

**Required:**
1. **Burp Suite Professional** - Must be installed ([portswigger.net](https://portswigger.net/burp/pro))
2. **burpsuite-project-file-parser extension** - Provides CLI functionality

**Install the extension:**
1. Download from [github.com/BuffaloWill/burpsuite-project-file-parser](https://github.com/BuffaloWill/burpsuite-project-file-parser)
2. In Burp Suite: Extender → Extensions → Add
3. Select the downloaded JAR file

## Quick Reference

Use the wrapper script:
```bash
{baseDir}/scripts/burp-search.sh /path/to/project.burp [FLAGS]
```

The script uses environment variables for platform compatibility:
- `BURP_JAVA`: Path to Java executable
- `BURP_JAR`: Path to burpsuite_pro.jar

See [Platform Configuration](#platform-configuration) for setup instructions.

## Sub-Component Filters (USE THESE)

**ALWAYS use sub-component filters instead of full dumps.** Full `proxyHistory` or `siteMap` can return gigabytes of data. Sub-component filters return only what you need.

### Available Filters

| Filter | Returns | Typical Size |
|--------|---------|--------------|
| `proxyHistory.request.headers` | Request line + headers only | Small (< 1KB/record) |
| `proxyHistory.request.body` | Request body only | Variable |
| `proxyHistory.response.headers` | Status + headers only | Small (< 1KB/record) |
| `proxyHistory.response.body` | Response body only | **LARGE - avoid** |
| `siteMap.request.headers` | Same as above for site map | Small |
| `siteMap.request.body` | | Variable |
| `siteMap.response.headers` | | Small |
| `siteMap.response.body` | | **LARGE - avoid** |

### Default Approach

**Start with headers, not bodies:**

```bash
# Header subset only; redact cookies, Authorization and other secrets before display
{baseDir}/scripts/burp-search.sh project.burp proxyHistory.request.headers | head -c 50000
{baseDir}/scripts/burp-search.sh project.burp proxyHistory.response.headers | head -c 50000

# BAD - full records include bodies, can be gigabytes
{baseDir}/scripts/burp-search.sh project.burp proxyHistory  # NEVER DO THIS
```

**Only fetch bodies for specific URLs after reviewing headers, and ALWAYS truncate:**

```bash
# 1. First, find interesting URLs from headers
{baseDir}/scripts/burp-search.sh project.burp proxyHistory.response.headers | \
  jq -r 'select(.headers | test("text/html")) | .url' | head -n 20

# 2. Then search bodies with targeted regex - MUST truncate body to 1000 chars
{baseDir}/scripts/burp-search.sh project.burp "responseBody='.*specific-pattern.*'" | \
  head -n 10 | jq -c '.body = (.body[:1000] + "...[TRUNCATED]")'
```

**HARD RULE: Body content > 1000 chars must NEVER enter context.** If the user needs full body content, they must view it in Burp Suite's UI.

## Regex Search Operations

### Search Response Headers
```bash
responseHeader='.*regex.*'
```
Searches all response headers. Output: `{"url":"...", "header":"..."}`

Example - find server signatures:
```bash
responseHeader='.*(nginx|Apache|Servlet).*' | head -c 50000
```

### Search Response Bodies
```bash
responseBody='.*regex.*'
```
**MANDATORY: Always truncate body content to 1000 chars max.** Response bodies can be megabytes each.

```bash
# REQUIRED format - always truncate .body field
{baseDir}/scripts/burp-search.sh project.burp "responseBody='.*<form.*action.*'" | \
  head -n 10 | jq -c '.body = (.body[:1000] + "...[TRUNCATED]")'
```

**Never retrieve full body content.** If you need to see more of a specific response, ask the user to open it in Burp Suite's UI.

## Other Operations

### Extract Audit Items
```bash
auditItems
```
Returns all sec
