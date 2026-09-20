---
name: dast-scanning
description: Perform dynamic application security testing with OWASP ZAP, Burp Suite, and Nikto. 
category: Security & Systems
source: antigravity
tags: [python, api, ai, agent, automation, workflow, template, image, security, docker]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/dast-scanning
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

# DAST Scanning

Test running applications for security vulnerabilities through dynamic analysis.

## When to Use This Skill

Use this skill when:
- Testing deployed applications
- Performing automated security scans
- Finding runtime vulnerabilities
- Testing authentication flows
- Validating API security

## Prerequisites

- Running application instance
- Network access to target
- Testing authorization
- Understanding of web security

## Tool Overview

| Tool | Type | Best For |
|------|------|----------|
| OWASP ZAP | OSS | Automated scanning, CI |
| Burp Suite | Commercial | Manual testing, advanced |
| Nikto | OSS | Web server scanning |
| Nuclei | OSS | Template-based scanning |
| Arachni | OSS | Comprehensive scanning |

## OWASP ZAP

### Docker Setup

```bash
# Run ZAP in daemon mode
docker run -d --name zap \
  -p 8080:8080 \
  -v $(pwd)/reports:/zap/reports \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true
```

### Baseline Scan

```bash
# Quick baseline scan
docker run --rm -v $(pwd):/zap/wrk \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t https://target.example.com \
  -r baseline-report.html

# With authentication
docker run --rm -v $(pwd):/zap/wrk \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t https://target.example.com \
  -r report.html \
  --auth-login-url https://target.example.com/login \
  --auth-username user \
  --auth-password pass
```

### Full Scan

```bash
# Comprehensive scan
docker run --rm -v $(pwd):/zap/wrk \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-full-scan.py -t https://target.example.com \
  -r full-report.html \
  -J full-report.json
```

### API Scan

```bash
# OpenAPI specification scan
docker run --rm -v $(pwd):/zap/wrk \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py -t https://target.example.com/openapi.json \
  -f openapi \
  -r api-report.html
```

### ZAP Automation Framework

```yaml
# zap-automation.yaml
env:
  contexts:
    - name: "Default Context"
      urls:
        - "https://target.example.com"
      includePaths:
        - "https://target.example.com/.*"
      excludePaths:
        - "https://target.example.com/logout.*"
      authentication:
        method: "form"
        parameters:
          loginUrl: "https://target.example.com/login"
          loginRequestData: "username={%username%}&password={%password%}"
        verification:
          method: "response"
          loggedInRegex: "\\QWelcome\\E"
      users:
        - name: "testuser"
          credentials:
            username: "test@example.com"
            password: "password123"

jobs:
  - type: spider
    parameters:
      context: "Default Context"
      user: "testuser"
      maxDuration: 10
      
  - type: spiderAjax
    parameters:
      context: "Default Context"
      user: "testuser"
      maxDuration: 10
      
  - type: passiveScan-wait
    parameters:
      maxDuration: 5
      
  - type: activeScan
    parameters:
      context: "Default Context"
      user: "testuser"
      policy: "Default Policy"
      
  - type: report
    parameters:
      template: "traditional-html"
      reportDir: "/zap/reports"
      reportFile: "zap-report"
```

```bash
# Run automation
docker run --rm -v $(pwd):/zap/wrk \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -cmd -autorun /zap/wrk/zap-automation.yaml
```

## CI/CD Integration

### GitHub Actions

```yaml
name: DAST Scan

on:
  workflow_dispatch:
  schedule:
    - cron: '0 2 * * *'

jobs:
  dast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Start Application
        run: |
          docker-compose up -d
          sleep 30  # Wait for app to be ready

      - name: OWASP ZAP Scan
        uses: zaproxy/action-full-scan@v0.8.0
        with:
          target: 'http://localhost:8080'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'

      - name: Upload Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: zap-report
          path: report_html.html
```

### GitLab CI

```yaml
d
