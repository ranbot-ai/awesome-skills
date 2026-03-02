---
name: security-scanning-security-sast
description: Static Application Security Testing (SAST) for code vulnerability analysis across multiple languages and frameworks 
category: Security & Systems
source: antigravity
tags: [python, javascript, typescript, react, api, ai, document, image, security, vulnerability]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/security-scanning-security-sast
---

# SAST Security Plugin

Static Application Security Testing (SAST) for comprehensive code vulnerability detection across multiple languages, frameworks, and security patterns.

## Capabilities

- **Multi-language SAST**: Python, JavaScript/TypeScript, Java, Ruby, PHP, Go, Rust
- **Tool integration**: Bandit, Semgrep, ESLint Security, SonarQube, CodeQL, PMD, SpotBugs, Brakeman, gosec, cargo-clippy
- **Vulnerability patterns**: SQL injection, XSS, hardcoded secrets, path traversal, IDOR, CSRF, insecure deserialization
- **Framework analysis**: Django, Flask, React, Express, Spring Boot, Rails, Laravel
- **Custom rule authoring**: Semgrep pattern development for organization-specific security policies

## Use this skill when

Use for code review security analysis, injection vulnerabilities, hardcoded secrets, framework-specific patterns, custom security policy enforcement, pre-deployment validation, legacy code assessment, and compliance (OWASP, PCI-DSS, SOC2).

**Specialized tools**: Use `security-secrets.md` for advanced credential scanning, `security-owasp.md` for Top 10 mapping, `security-api.md` for REST/GraphQL endpoints.

## Do not use this skill when

- You only need runtime testing or penetration testing
- You cannot access the source code or build outputs
- The environment forbids third-party scanning tools

## Instructions

1. Identify the languages, frameworks, and scope to scan.
2. Select SAST tools and configure rules for the codebase.
3. Run scans in CI or locally with reproducible settings.
4. Triage findings, prioritize by severity, and propose fixes.

## Safety

- Avoid uploading proprietary code to external services without approval.
- Require review before enabling auto-fix or blocking releases.

## SAST Tool Selection

### Python: Bandit

```bash
# Installation & scan
pip install bandit
bandit -r . -f json -o bandit-report.json
bandit -r . -ll -ii -f json  # High/Critical only
```

**Configuration**: `.bandit`
```yaml
exclude_dirs: ['/tests/', '/venv/', '/.tox/', '/build/']
tests: [B201, B301, B302, B303, B304, B305, B307, B308, B312, B323, B324, B501, B502, B506, B602, B608]
skips: [B101]
```

### JavaScript/TypeScript: ESLint Security

```bash
npm install --save-dev eslint @eslint/plugin-security eslint-plugin-no-secrets
eslint . --ext .js,.jsx,.ts,.tsx --format json > eslint-security.json
```

**Configuration**: `.eslintrc-security.json`
```json
{
  "plugins": ["@eslint/plugin-security", "eslint-plugin-no-secrets"],
  "extends": ["plugin:security/recommended"],
  "rules": {
    "security/detect-object-injection": "error",
    "security/detect-non-literal-fs-filename": "error",
    "security/detect-eval-with-expression": "error",
    "security/detect-pseudo-random-prng": "error",
    "no-secrets/no-secrets": "error"
  }
}
```

### Multi-Language: Semgrep

```bash
pip install semgrep
semgrep --config=auto --json --output=semgrep-report.json
semgrep --config=p/security-audit --json
semgrep --config=p/owasp-top-ten --json
semgrep ci --config=auto  # CI mode
```

**Custom Rules**: `.semgrep.yml`
```yaml
rules:
  - id: sql-injection-format-string
    pattern: cursor.execute("... %s ..." % $VAR)
    message: SQL injection via string formatting
    severity: ERROR
    languages: [python]
    metadata:
      cwe: "CWE-89"
      owasp: "A03:2021-Injection"

  - id: dangerous-innerHTML
    pattern: $ELEM.innerHTML = $VAR
    message: XSS via innerHTML assignment
    severity: ERROR
    languages: [javascript, typescript]
    metadata:
      cwe: "CWE-79"

  - id: hardcoded-aws-credentials
    patterns:
      - pattern: $KEY = "AKIA..."
      - metavariable-regex:
          metavariable: $KEY
          regex: "(aws_access_key_id|AWS_ACCESS_KEY_ID)"
    message: Hardcoded AWS credentials detected
    severity: ERROR
    languages: [python, javascript, java]

  - id: path-traversal-open
    patterns:
      - pattern: open($PATH, ...)
      - pattern-not: open(os.path.join(SAFE_DIR, ...), ...)
      - metavariable-pattern:
          metavariable: $PATH
          patterns:
            - pattern: $REQ.get(...)
    message: Path traversal via user input
    severity: ERROR
    languages: [python]

  - id: command-injection
    patterns:
      - pattern-either:
          - pattern: os.system($CMD)
          - pattern: subprocess.call($CMD, shell=True)
      - metavariable-pattern:
          metavariable: $CMD
          patterns:
            - pattern-either:
                - pattern: $X + $Y
                - pattern: f"...{$VAR}..."
    message: Command injection via shell=True
    severity: ERROR
    languages: [python]
```

### Other Language Tools

**Java**: `mvn spotbugs:check`
**Ruby**: `brakeman -o report.json -f json`
**Go**: `gosec -fmt=json -out=gosec.json ./...`
**Rust**: `cargo clippy -- -W clippy::unwrap_used`

## Vulnerability Patterns

### SQL Injection

**VULNERABLE**: String formatting/concatenation with user input in SQL queries

**SECURE**:
```python
# Parameterized queries
cursor.exec
