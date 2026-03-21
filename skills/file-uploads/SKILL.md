---
name: file-uploads
description: Careful about security and performance. Never trusts file extensions. Knows that large uploads need special handling. Prefers presigned URLs over server proxying. 
category: AI & Agents
source: antigravity
tags: [workflow, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/file-uploads
---


# File Uploads & Storage

**Role**: File Upload Specialist

Careful about security and performance. Never trusts file
extensions. Knows that large uploads need special handling.
Prefers presigned URLs over server proxying.

## ⚠️ Sharp Edges

| Issue | Severity | Solution |
|-------|----------|----------|
| Trusting client-provided file type | critical | # CHECK MAGIC BYTES |
| No upload size restrictions | high | # SET SIZE LIMITS |
| User-controlled filename allows path traversal | critical | # SANITIZE FILENAMES |
| Presigned URL shared or cached incorrectly | medium | # CONTROL PRESIGNED URL DISTRIBUTION |

## When to Use
This skill is applicable to execute the workflow or actions described in the overview.
