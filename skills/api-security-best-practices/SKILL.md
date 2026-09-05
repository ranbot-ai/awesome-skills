---
name: api-security-best-practices
description: Implement secure API design patterns including authentication, authorization, input validation, rate limiting, and protection against common API vulnerabilities 
category: Security & Systems
source: antigravity
tags: [javascript, node, api, ai, design, document, security, prisma, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/api-security-best-practices
---


# API Security Best Practices

Review the request boundary from caller identity through authorization, validated
input, storage and observable response. Preserve the application's actual identity
provider and data model rather than introducing a second authentication system.

## When to Use

Use when adding a protected endpoint, reviewing object access, replacing permissive
request parsing, or investigating an API abuse path. For a concrete defect, start
with the failing route and its callers; do not deploy unrelated security infrastructure.

## Inputs and prerequisites

Record the routes, caller/tenant model, identity provider, token contract, runtime and
locked dependency versions, database schema, proxy topology and authorized test scope.
Use synthetic identities in a test environment. Existing task authorization carries
forward; production scans, account writes and message sends need their own authority.
The Node examples below are integration sketches for Express, jsonwebtoken and Zod;
application/database adapters are deliberately named rather than presented as a full
runnable service. Confirm APIs against the installed versions before integrating.

## 1. Authenticate the exact token contract

Prefer the established provider/session middleware. When the service owns an HMAC
JWT contract, require a strong server-owned key, a fixed algorithm, exact issuer and
audience, and required runtime claims. Do not infer permissions from a decoded token
before signature verification. Never accept a caller-selected verification algorithm.

```javascript
const jwt = require('jsonwebtoken');

// Illustrative first-party access-token contract; not a third-party OAuth adapter.
const ACCESS_POLICY = {
  algorithms: ['HS256'], issuer: 'example-auth', audience: 'example-api'
};
function verifyAccessToken(token, signingKey) {
  const claims = jwt.verify(token, signingKey, ACCESS_POLICY);
  if (!claims || typeof claims !== 'object' ||
      typeof claims.sub !== 'string' || !claims.sub ||
      typeof claims.tenantId !== 'string' || !claims.tenantId ||
      !Number.isSafeInteger(claims.exp) || !Number.isSafeInteger(claims.iat) ||
      claims.exp <= claims.iat) {
    throw new Error('Invalid access claims');
  }
  return { subject: claims.sub, tenantId: claims.tenantId };
}
function readBearer(header) {
  if (typeof header !== 'string' || header.length > 8192) return null;
  const match = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i.exec(header);
  return match ? match[1] : null;
}
```

Issue access tokens with the same issuer/audience/algorithm and a short application-
approved expiration. Handle verification failure as a generic 401 without echoing the
token or exception. Expiration alone does not revoke a token; define revocation or
short-lived sessions according to the actual threat model. A service using asymmetric
provider keys needs the provider's discovery/JWKS validation and key-rotation policy,
not this HMAC example. Never reuse an access token as a refresh token.

### Refresh sessions

Use the provider's supported session flow or a server-side opaque refresh design:
store only a digest, expiry, user/session family and revocation state. In one atomic
transaction consume the old active token and create the replacement. Concurrent reuse
must not issue two successors; defined reuse handling revokes the affected family.
Check current user status and permissions when issuing new access tokens. Bind refresh
to the intended client/session and protect cookie-based requests against CSRF. Do not
log tokens, store them plaintext in a database, or return a refresh token through a URL.
Test simultaneous refresh, expiry, replay, revocation and transaction failure before
calling the flow complete. No database transaction adapter is bundled here.

## 2. Authorize the resource and operation

Authentication identifies the caller; authorization decides the exact operation on
an object and tenant. A role name does not automatically grant cross-tenant access.
Apply the owner/tenant predicate in the database mutation to avoid a check-then-write
race, and allowlist writable properties. Use 404/403 consistently with the product's
resource-disclosure policy.

```javascript
// Prisma-style sketch; id and tenant types must match your actual schema.
async function deleteOwnedPost(prisma, postId, principal) {
  const result = await prisma.post.deleteMany({
    where: { id: postId, userId: principal.subject, tenantId: principal.tenantId }
  });
  return result.count === 1;
}
```

An administrator path needs an explicit separate policy and audit event; do not add
an implicit admin bypass to every owner check. Test a valid user accessing another
user's object, the same ID in another tenant, deleted memberships and bulk endpoints.

## 3. Parse once, then use the validated value

Reject partial numeric parses (`12abc` is not ID 12), unsafe integers, unexpected
properties and oversized requests. Use parameterized database queries.
