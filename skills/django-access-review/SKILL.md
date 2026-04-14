---
name: django-access-review
description: name: django-access-review Find access control vulnerabilities by investigating how the codebase answers one question: 
category: Document Processing
source: antigravity
tags: [python, markdown, api, ai, document, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/django-access-review
---


---
name: django-access-review
description: Django access control and IDOR security review. Use when reviewing Django views, DRF viewsets, ORM queries, or any Python/Django code handling user authorization. Trigger keywords: "IDOR", "access control", "authorization", "Django permissions", "object permissions", "tenant...
--- LICENSE
---

<!--
Reference material based on OWASP Cheat Sheet Series (CC BY-SA 4.0)
https://cheatsheetseries.owasp.org/
-->

# Django Access Control & IDOR Review

Find access control vulnerabilities by investigating how the codebase answers one question:

**Can User A access, modify, or delete User B's data?**

## When to Use
- You need to review Django or DRF code for access control gaps, IDOR risk, or object-level authorization failures.
- The task involves confirming whether one user can access, modify, or delete another user's data.
- You want an investigation-driven authorization review instead of generic pattern matching.

## Philosophy: Investigation Over Pattern Matching

Do NOT scan for predefined vulnerable patterns. Instead:

1. **Understand** how authorization works in THIS codebase
2. **Ask questions** about specific data flows
3. **Trace code** to find where (or if) access checks happen
4. **Report** only what you've confirmed through investigation

Every codebase implements authorization differently. Your job is to understand this specific implementation, then find gaps.

---

## Phase 1: Understand the Authorization Model

Before looking for bugs, answer these questions about the codebase:

### How is authorization enforced?

Research the codebase to find:

```
□ Where are permission checks implemented?
  - Decorators? (@login_required, @permission_required, custom?)
  - Middleware? (TenantMiddleware, AuthorizationMiddleware?)
  - Base classes? (BaseAPIView, TenantScopedViewSet?)
  - Permission classes? (DRF permission_classes?)
  - Custom mixins? (OwnershipMixin, TenantMixin?)

□ How are queries scoped?
  - Custom managers? (TenantManager, UserScopedManager?)
  - get_queryset() overrides?
  - Middleware that sets query context?

□ What's the ownership model?
  - Single user ownership? (document.owner_id)
  - Organization/tenant ownership? (document.organization_id)
  - Hierarchical? (org -> team -> user -> resource)
  - Role-based within context? (org admin vs member)
```

### Investigation commands

```bash
# Find how auth is typically done
grep -rn "permission_classes\|@login_required\|@permission_required" --include="*.py" | head -20

# Find base classes that views inherit from
grep -rn "class Base.*View\|class.*Mixin.*:" --include="*.py" | head -20

# Find custom managers
grep -rn "class.*Manager\|def get_queryset" --include="*.py" | head -20

# Find ownership fields on models
grep -rn "owner\|user_id\|organization\|tenant" --include="models.py" | head -30
```

**Do not proceed until you understand the authorization model.**

---

## Phase 2: Map the Attack Surface

Identify endpoints that handle user-specific data:

### What resources exist?

```
□ What models contain user data?
□ Which have ownership fields (owner_id, user_id, organization_id)?
□ Which are accessed via ID in URLs or request bodies?
```

### What operations are exposed?

For each resource, map:
- List endpoints - what data is returned?
- Detail/retrieve endpoints - how is the object fetched?
- Create endpoints - who sets the owner?
- Update endpoints - can users modify others' data?
- Delete endpoints - can users delete others' data?
- Custom actions - what do they access?

---

## Phase 3: Ask Questions and Investigate

For each endpoint that handles user data, ask:

### The Core Question

**"If I'm User A and I know the ID of User B's resource, can I access it?"**

Trace the code to answer this:

```
1. Where does the resource ID enter the system?
   - URL path: /api/documents/{id}/
   - Query param: ?document_id=123
   - Request body: {"document_id": 123}

2. Where is that ID used to fetch data?
   - Find the ORM query or database call

3. Between (1) and (2), what checks exist?
   - Is the query scoped to current user?
   - Is there an explicit ownership check?
   - Is there a permission check on the object?
   - Does a base class or mixin enforce access?

4. If you can't find a check, is there one you missed?
   - Check parent classes
   - Check middleware
   - Check managers
   - Check decorators at URL level
```

### Follow-Up Questions

```
□ For list endpoints: Does the query filter to user's data, or return everything?

□ For create endpoints: Who sets the owner - the server or the request?

□ For bulk operations: Are they scoped to user's data?

□ For related resources: If I can access a document, can I access its comments?
  What if the document belongs to someone else?

□ For tenant/org resources: Can User in Org A access Org B's data by changing
  the org_id in the URL?
```

---

## Phase 4: Trace Specific Flows

Pick a concrete endpoint and trace it completely.

### Example Inves
