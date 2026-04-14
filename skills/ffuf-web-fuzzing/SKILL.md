---
name: ffuf-web-fuzzing
description: Expert guidance for ffuf web fuzzing during penetration testing, including authenticated fuzzing with raw requests, auto-calibration, and result analysis 
category: Security & Systems
source: antigravity
tags: [python, pdf, api, claude, ai, agent, workflow, template, design, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ffuf-web-fuzzing
---


# FFUF (Fuzz Faster U Fool) Skill

## When to Use
- You are fuzzing web targets with `ffuf` during authorized security testing or penetration testing.
- The task involves content discovery, subdomain enumeration, parameter fuzzing, or authenticated request fuzzing.
- You need guidance on wordlists, filtering, calibration, and interpreting ffuf results efficiently.

## Overview
FFUF is a fast web fuzzer written in Go, designed for discovering hidden content, directories, files, subdomains, and testing for vulnerabilities during penetration testing. It's significantly faster than traditional tools like dirb or dirbuster.

## Installation
```bash
# Using Go
go install github.com/ffuf/ffuf/v2@latest

# Using Homebrew (macOS)
brew install ffuf

# Binary download
# Download from: https://github.com/ffuf/ffuf/releases/latest
```

## Core Concepts

### The FUZZ Keyword
The `FUZZ` keyword is used as a placeholder that gets replaced with entries from your wordlist. You can place it anywhere:
- URLs: `https://target.com/FUZZ`
- Headers: `-H "Host: FUZZ"`
- POST data: `-d "username=admin&password=FUZZ"`
- Multiple locations with custom keywords: `-w wordlist.txt:CUSTOM` then use `CUSTOM` instead of `FUZZ`

### Multi-wordlist Modes
- **clusterbomb**: Tests all combinations (default) - cartesian product
- **pitchfork**: Iterates through wordlists in parallel (1-to-1 matching)
- **sniper**: Tests one position at a time (for multiple FUZZ positions)

## Common Use Cases

### 1. Directory and File Discovery
```bash
# Basic directory fuzzing
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ

# With file extensions
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -e .php,.html,.txt,.pdf

# Colored and verbose output
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -c -v

# With recursion (finds nested directories)
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -recursion -recursion-depth 2
```

### 2. Subdomain Enumeration
```bash
# Virtual host discovery
ffuf -w /path/to/subdomains.txt -u https://target.com -H "Host: FUZZ.target.com" -fs 4242

# Note: -fs 4242 filters out responses of size 4242 (adjust based on default response size)
```

### 3. Parameter Fuzzing
```bash
# GET parameter names
ffuf -w /path/to/params.txt -u https://target.com/script.php?FUZZ=test_value -fs 4242

# GET parameter values
ffuf -w /path/to/values.txt -u https://target.com/script.php?id=FUZZ -fc 401

# Multiple parameters
ffuf -w params.txt:PARAM -w values.txt:VAL -u https://target.com/?PARAM=VAL -mode clusterbomb
```

### 4. POST Data Fuzzing
```bash
# Basic POST fuzzing
ffuf -w /path/to/passwords.txt -X POST -d "username=admin&password=FUZZ" -u https://target.com/login.php -fc 401

# JSON POST data
ffuf -w entries.txt -u https://target.com/api -X POST -H "Content-Type: application/json" -d '{"name": "FUZZ", "key": "value"}' -fr "error"

# Fuzzing multiple POST fields
ffuf -w users.txt:USER -w passes.txt:PASS -X POST -d "username=USER&password=PASS" -u https://target.com/login -mode pitchfork
```

### 5. Header Fuzzing
```bash
# Custom headers
ffuf -w /path/to/wordlist.txt -u https://target.com -H "X-Custom-Header: FUZZ"

# Multiple headers
ffuf -w /path/to/wordlist.txt -u https://target.com -H "User-Agent: FUZZ" -H "X-Forwarded-For: 127.0.0.1"
```

## Filtering and Matching

### Matchers (Include Results)
- `-mc`: Match status codes (default: 200-299,301,302,307,401,403,405,500)
- `-ml`: Match line count
- `-mr`: Match regex
- `-ms`: Match response size
- `-mt`: Match response time (e.g., `>100` or `<100` milliseconds)
- `-mw`: Match word count

### Filters (Exclude Results)
- `-fc`: Filter status codes (e.g., `-fc 404,403,401`)
- `-fl`: Filter line count
- `-fr`: Filter regex (e.g., `-fr "error"`)
- `-fs`: Filter response size (e.g., `-fs 42,4242`)
- `-ft`: Filter response time
- `-fw`: Filter word count

### Auto-Calibration (USE BY DEFAULT!)
**CRITICAL:** Always use `-ac` unless you have a specific reason not to. This is especially important when having Claude analyze results, as it dramatically reduces noise and false positives.

```bash
# Auto-calibration - ALWAYS USE THIS
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -ac

# Per-host auto-calibration (useful for multiple hosts)
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -ach

# Custom auto-calibration string (for specific patterns)
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -acc "404NotFound"
```

**Why `-ac` is essential:**
- Automatically detects and filters repetitive false positive responses
- Removes noise from dynamic websites with random content
- Makes results analysis much easier for both humans and Claude
- Prevents thousands of identical 404/403 responses from cluttering output
- Adapts to the target's specific behavior

**When Claude analyzes your ffuf results, `-ac` is MANDATORY** - without it, Claude will waste time sifting through thousands of false positives instead of finding the interesting anomalies.
