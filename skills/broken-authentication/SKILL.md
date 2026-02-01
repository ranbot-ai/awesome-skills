---
name: Broken Authentication Testing
description: This skill should be used when the user asks to "test for broken authentication vulnerabilities", "assess session management security", "perform credential stuffing tests", "evaluate password policies
category: Security & Systems
source: antigravity
tags: [python, api, ai, agent, llm, workflow, document, security, vulnerability, aws]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/broken-authentication
---


# Broken Authentication Testing

## Purpose

Identify and exploit authentication and session management vulnerabilities in web applications. Broken authentication consistently ranks in the OWASP Top 10 and can lead to account takeover, identity theft, and unauthorized access to sensitive systems. This skill covers testing methodologies for password policies, session handling, multi-factor authentication, and credential management.

## Prerequisites

### Required Knowledge
- HTTP protocol and session mechanisms
- Authentication types (SFA, 2FA, MFA)
- Cookie and token handling
- Common authentication frameworks

### Required Tools
- Burp Suite Professional or Community
- Hydra or similar brute-force tools
- Custom wordlists for credential testing
- Browser developer tools

### Required Access
- Target application URL
- Test account credentials
- Written authorization for testing

## Outputs and Deliverables

1. **Authentication Assessment Report** - Document all identified vulnerabilities
2. **Credential Testing Results** - Brute-force and dictionary attack outcomes
3. **Session Security Analysis** - Token randomness and timeout evaluation
4. **Remediation Recommendations** - Security hardening guidance

## Core Workflow

### Phase 1: Authentication Mechanism Analysis

Understand the application's authentication architecture:

```
# Identify authentication type
- Password-based (forms, basic auth, digest)
- Token-based (JWT, OAuth, API keys)
- Certificate-based (mutual TLS)
- Multi-factor (SMS, TOTP, hardware tokens)

# Map authentication endpoints
/login, /signin, /authenticate
/register, /signup
/forgot-password, /reset-password
/logout, /signout
/api/auth/*, /oauth/*
```

Capture and analyze authentication requests:

```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=test&password=test123
```

### Phase 2: Password Policy Testing

Evaluate password requirements and enforcement:

```bash
# Test minimum length (a, ab, abcdefgh)
# Test complexity (password, password1, Password1!)
# Test common weak passwords (123456, password, qwerty, admin)
# Test username as password (admin/admin, test/test)
```

Document policy gaps: Minimum length <8, no complexity, common passwords allowed, username as password.

### Phase 3: Credential Enumeration

Test for username enumeration vulnerabilities:

```bash
# Compare responses for valid vs invalid usernames
# Invalid: "Invalid username" vs Valid: "Invalid password"
# Check timing differences, response codes, registration messages
```

# Password reset
"Email sent if account exists" (secure)
"No account with that email" (leaks info)

# API responses
{"error": "user_not_found"}
{"error": "invalid_password"}
```

### Phase 4: Brute Force Testing

Test account lockout and rate limiting:

```bash
# Using Hydra for form-based auth
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials"

# Using Burp Intruder
1. Capture login request
2. Send to Intruder
3. Set payload positions on password field
4. Load wordlist
5. Start attack
6. Analyze response lengths/codes
```

Check for protections:

```bash
# Account lockout
- After how many attempts?
- Duration of lockout?
- Lockout notification?

# Rate limiting
- Requests per minute limit?
- IP-based or account-based?
- Bypass via headers (X-Forwarded-For)?

# CAPTCHA
- After failed attempts?
- Easily bypassable?
```

### Phase 5: Credential Stuffing

Test with known breached credentials:

```bash
# Credential stuffing differs from brute force
# Uses known email:password pairs from breaches

# Using Burp Intruder with Pitchfork attack
1. Set username and password as positions
2. Load email list as payload 1
3. Load password list as payload 2 (matched pairs)
4. Analyze for successful logins

# Detection evasion
- Slow request rate
- Rotate source IPs
- Randomize user agents
- Add delays between attempts
```

### Phase 6: Session Management Testing

Analyze session token security:

```bash
# Capture session cookie
Cookie: SESSIONID=abc123def456

# Test token characteristics
1. Entropy - Is it random enough?
2. Length - Sufficient length (128+ bits)?
3. Predictability - Sequential patterns?
4. Secure flags - HttpOnly, Secure, SameSite?
```

Session token analysis:

```python
#!/usr/bin/env python3
import requests
import hashlib

# Collect multiple session tokens
tokens = []
for i in range(100):
    response = requests.get("https://target.com/login")
    token = response.cookies.get("SESSIONID")
    tokens.append(token)

# Analyze for patterns
# Check for sequential increments
# Calculate entropy
# Look for timestamp components
```

### Phase 7: Session Fixation Testing

Test if session is regenerated after authentication:

```bash
# Step 1: Get session before login
GET /login HTTP/1.1
Response: Set-Cookie: SESSIONID=abc123

# Step 2: Login with same session
POST /login HTTP/1.1
Cookie: SESSIONID=ab
