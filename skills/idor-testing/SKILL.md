---
name: IDOR Vulnerability Testing
description: This skill should be used when the user asks to "test for insecure direct object references," "find IDOR vulnerabilities," "exploit broken access control," "enumerate user IDs or object references," o
category: Security & Systems
source: antigravity
tags: [python, javascript, pdf, xlsx, api, ai, workflow, template, document, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/idor-testing
---


# IDOR Vulnerability Testing

## Purpose

Provide systematic methodologies for identifying and exploiting Insecure Direct Object Reference (IDOR) vulnerabilities in web applications. This skill covers both database object references and static file references, detection techniques using parameter manipulation and enumeration, exploitation via Burp Suite, and remediation strategies for securing applications against unauthorized access.

## Inputs / Prerequisites

- **Target Web Application**: URL of application with user-specific resources
- **Multiple User Accounts**: At least two test accounts to verify cross-user access
- **Burp Suite or Proxy Tool**: Intercepting proxy for request manipulation
- **Authorization**: Written permission for security testing
- **Understanding of Application Flow**: Knowledge of how objects are referenced (IDs, filenames)

## Outputs / Deliverables

- **IDOR Vulnerability Report**: Documentation of discovered access control bypasses
- **Proof of Concept**: Evidence of unauthorized data access across user contexts
- **Affected Endpoints**: List of vulnerable API endpoints and parameters
- **Impact Assessment**: Classification of data exposure severity
- **Remediation Recommendations**: Specific fixes for identified vulnerabilities

## Core Workflow

### 1. Understand IDOR Vulnerability Types

#### Direct Reference to Database Objects
Occurs when applications reference database records via user-controllable parameters:
```
# Original URL (authenticated as User A)
example.com/user/profile?id=2023

# Manipulation attempt (accessing User B's data)
example.com/user/profile?id=2022
```

#### Direct Reference to Static Files
Occurs when applications expose file paths or names that can be enumerated:
```
# Original URL (User A's receipt)
example.com/static/receipt/205.pdf

# Manipulation attempt (User B's receipt)
example.com/static/receipt/200.pdf
```

### 2. Reconnaissance and Setup

#### Create Multiple Test Accounts
```
Account 1: "attacker" - Primary testing account
Account 2: "victim" - Account whose data we attempt to access
```

#### Identify Object References
Capture and analyze requests containing:
- Numeric IDs in URLs: `/api/user/123`
- Numeric IDs in parameters: `?id=123&action=view`
- Numeric IDs in request body: `{"userId": 123}`
- File paths: `/download/receipt_123.pdf`
- GUIDs/UUIDs: `/profile/a1b2c3d4-e5f6-...`

#### Map User IDs
```
# Access user ID endpoint (if available)
GET /api/user-id/

# Note ID patterns:
# - Sequential integers (1, 2, 3...)
# - Auto-incremented values
# - Predictable patterns
```

### 3. Detection Techniques

#### URL Parameter Manipulation
```
# Step 1: Capture original authenticated request
GET /api/user/profile?id=1001 HTTP/1.1
Cookie: session=attacker_session

# Step 2: Modify ID to target another user
GET /api/user/profile?id=1000 HTTP/1.1
Cookie: session=attacker_session

# Vulnerable if: Returns victim's data with attacker's session
```

#### Request Body Manipulation
```
# Original POST request
POST /api/address/update HTTP/1.1
Content-Type: application/json
Cookie: session=attacker_session

{"id": 5, "userId": 1001, "address": "123 Attacker St"}

# Modified request targeting victim
{"id": 5, "userId": 1000, "address": "123 Attacker St"}
```

#### HTTP Method Switching
```
# Original GET request may be protected
GET /api/admin/users/1000 → 403 Forbidden

# Try alternative methods
POST /api/admin/users/1000 → 200 OK (Vulnerable!)
PUT /api/admin/users/1000 → 200 OK (Vulnerable!)
```

### 4. Exploitation with Burp Suite

#### Manual Exploitation
```
1. Configure browser proxy through Burp Suite
2. Login as "attacker" user
3. Navigate to profile/data page
4. Enable Intercept in Proxy tab
5. Capture request with user ID
6. Modify ID to victim's ID
7. Forward request
8. Observe response for victim's data
```

#### Automated Enumeration with Intruder
```
1. Send request to Intruder (Ctrl+I)
2. Clear all payload positions
3. Select ID parameter as payload position
4. Configure attack type: Sniper
5. Payload settings:
   - Type: Numbers
   - Range: 1 to 10000
   - Step: 1
6. Start attack
7. Analyze responses for 200 status codes
```

#### Battering Ram Attack for Multiple Positions
```
# When same ID appears in multiple locations
PUT /api/addresses/§5§/update HTTP/1.1

{"id": §5§, "userId": 3}

Attack Type: Battering Ram
Payload: Numbers 1-1000
```

### 5. Common IDOR Locations

#### API Endpoints
```
/api/user/{id}
/api/profile/{id}
/api/order/{id}
/api/invoice/{id}
/api/document/{id}
/api/message/{id}
/api/address/{id}/update
/api/address/{id}/delete
```

#### File Downloads
```
/download/invoice_{id}.pdf
/static/receipts/{id}.pdf
/uploads/documents/{filename}
/files/reports/report_{date}_{id}.xlsx
```

#### Query Parameters
```
?userId=123
?orderId=456
?documentId=789
?file=report_123.pdf
?account=user@email.com
```

## Quick Reference

### IDOR Testing Checklist

| Test | Method | Indicator of Vulnerability |
|------|--------|-------------
