---
name: mailtrap-testing-with-sandbox
description: Capture outbound email in Mailtrap Email Sandbox for development, staging, CI, HTML inspection, spam checks, and fake inbox tests. 
category: Document Processing
source: antigravity
tags: [python, node, api, ai, automation, template, document, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/mailtrap-testing-with-sandbox
---


# Testing with Mailtrap Email Sandbox

## Overview

**Email Sandbox** captures mail in **sandboxes (test inboxes)**—a test environment where messages are **not** delivered to real recipients. You can send to sandboxes using our **SDKs**, **HTTP API**, or **SMTP**, depending on your needs.

**Before generating SDK code:** read the README of the relevant SDK repository (see `mailtrap-sending-emails`) for current sandbox mode options, **inbox id**, and constructor flags. Do not rely on memory.

**Related skills:** `mailtrap-sending-emails` (live sending hosts and streams).

## When to use

- You want **no real delivery**: dev, staging, CI, or demos where mail must stay in a **test inbox**.
- You need to **inspect** what was sent: bodies, headers, attachments, or basic checks (e.g. spam report) via **Sandbox / Testing API** or the **UI**.
- You are **automating** tests against captured mail.
- You will **only change SMTP settings** so an existing app sends into a sandbox—no need for a framework-by-framework tutorial from this skill.

## When not to use

- **Live** sends to real recipients (`mailtrap-sending-emails`).
- For full framework setup guides or detailed API references, link users to Mailtrap's Integration tab for SMTP/API details and the [API docs](https://docs.mailtrap.io/developers/) for specifics—don't cover every framework or API field here.

## Quick reference

### API base

| Service                  | Send mail URL                                         | Auth header examples                              |
| ------------------------ | ----------------------------------------------------- | ------------------------------------------------- |
| Email Testing API (REST) | `https://sandbox.api.mailtrap.io/api/send/{inbox_id}` | `Authorization: Bearer $MAILTRAP_SANDBOX_API_TOKEN` |

### Tokens and account_id

Sandbox uses a **separate** token (`$MAILTRAP_SANDBOX_API_TOKEN`, Testing/Sandbox scope) — never reuse the live `$MAILTRAP_API_TOKEN`. The `account_id` in the example endpoints below is resolved at runtime via `GET https://mailtrap.io/api/accounts`. Store tokens in environment variables or a secrets manager.

### When to use API vs SMTP

Use **SMTP** when testing apps that already send mail via SMTP (just update the host, port, and credentials).
Use the **HTTP API** when building new integrations or your app can make HTTP requests; it's better for programmatic testing and automation.

### SMTP settings (sandbox)

| Setting             | Value                                                                       |
| ------------------- | --------------------------------------------------------------------------- |
| Host                | `sandbox.smtp.mailtrap.io`                                                  |
| Ports               | 2525 (default), 25, 465 (SSL), 587                                          |
| Username / Password | Per **sandbox** credentials from the **Integration** tab in the Mailtrap UI |

**Never use sandbox credentials or endpoints in production. Messages will only be captured in the sandbox, not delivered.**

### Key parameters

- **Inbox ID**: Every sandbox (test inbox) has a unique **inbox id**, visible in the UI URL and needed for sending or REST API operations.
- **Token scope**: Use a token with permissions for the relevant project and test inbox.

### Typical use cases

- Capture all outbound mail in dev, test, or staging (no real recipients).
- View, validate, and assert message headers, bodies, HTML, attachments, or spam score.
- Run integration or CI checks that read from the Email Sandbox API.
- Test Mailtrap **templates** by pointing API or SDK/SMTP at `sandbox.api.mailtrap.io` / `sandbox.smtp.mailtrap.io` with a valid inbox id.

### Example API paths

Use [API docs](https://docs.mailtrap.io/developers/) for details, but typical endpoints include:

| Operation       | URL                                                                                          | Reference                                                                                 |
| --------------- | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| List sandboxes  | `GET https://mailtrap.io/api/accounts/$MAILTRAP_ACCOUNT_ID/inboxes`                          | [Sandboxes API](https://docs.mailtrap.io/developers/email-sandbox/sandboxes-inboxes.md)   |
| List messages   | `GET https://mailtrap.io/api/accounts/$MAILTRAP_ACCOUNT_ID/inboxes/{inbox_id}/messages`      | [Messages](https://docs.mailtrap.io/developers/email-sandbox/messages.md)                 |
| Fetch a message | `GET https://mailtrap.io/api/accounts/$MAILTRAP_ACCOUNT_ID/inboxes/{inbox_id}/messages/{id}` | [Message details](https://docs.mailtrap.io/developers/email-sandbox/messages.md)          |
| Send test email | `POST https://mailtrap.io/api/accounts/$MAILTRAP_ACCOUNT_ID/inboxes/{inbo
