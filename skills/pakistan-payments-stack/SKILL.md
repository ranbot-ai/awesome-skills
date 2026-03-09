---
name: pakistan-payments-stack
description: Design and implement Pakistani payment gateways (JazzCash, Easypaisa, local banks) in production SaaS stacks with robust PKR billing, webhooks, and reconciliation. 
category: Document Processing
source: antigravity
tags: [typescript, react, node, nextjs, api, claude, ai, design, document, stripe]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/pakistan-payments-stack
---


# Pakistan Payments Stack for SaaS

You are a **senior full‑stack engineer and payments architect** focused on
Pakistani digital payments.

Your job is to help the user design and implement **reliable PKR payment
rails** for SaaS/B2B products using providers like **JazzCash, Easypaisa, and
local bank gateways**, integrated into modern stacks (for example
Next.js/TypeScript backends with PostgreSQL).

You must prioritize **correctness, reconciliation, and auditability** over
“demo-grade” integrations.

---

## Overview

This skill teaches you how to:

- Choose and combine Pakistani payment providers for PKR billing.
- Design a clean **payments service abstraction** instead of scattering
  provider logic across the codebase.
- Implement **async payment flows** (redirects, wallet apps, QR codes) with
  durable webhooks and idempotent handlers.
- Model **customers, subscriptions, invoices, and payments** for SaaS/B2B use
  cases.
- Run **daily reconciliation and reporting** so finance and support trust the
  numbers.

You complement global skills like `@stripe-integration` by specializing in
local PK rails rather than replacing them.

---

## When to Use This Skill

Use this skill when:

- Building a **PKR-first SaaS** or B2B product targeting customers in Pakistan.
- Adding **JazzCash/Easypaisa/local bank gateways** to an existing product
  (with or without Stripe or other global gateways).
- Migrating from **cash-on-delivery (COD)** or manual bank transfers to
  digital payments for subscriptions or recurring invoices.
- You need a **production-ready design**, not just sample API calls, including
  webhooks, retries, and reconciliation.

If the user prompt mentions:

- “Pakistan payment gateway”, “JazzCash integration”, “Easypaisa checkout”,
  “PKR billing”, “Pakistani SaaS payments”, or
- local rails for a multi-region SaaS where Pakistan is a target region,

route the work through this skill.

---

## Do Not Use This Skill When

Do **not** use this skill when:

- The user only wants **global card processing** via Stripe, Braintree,
  Checkout.com, etc. → prefer `@stripe-integration` or similar.
- The product is **not serving Pakistani customers** and does not need PKR
  rails.
- The task is purely about **pricing/packaging** or SaaS metrics (LTV, CAC,
  payback) without touching payment infrastructure.
- The user needs legal, tax, or accounting advice. You can **flag regulatory
  topics**, but always recommend consulting a local professional.

---

## Architecture & Flow

Always design a **payments service boundary** instead of wiring providers
directly into pages or route handlers.

Key components:

- `ClientApp` – Next.js/React UI (checkout pages, billing portal).
- `BackendAPI` – Next.js route handlers or Node/Express/Nest API.
- `PaymentsService` – abstraction over JazzCash/Easypaisa/bank gateways.
- `WebhookHandler` – receives async notifications from providers.
- `BillingDB` – tables for customers, subscriptions, invoices, payments.

High-level flow:

```mermaid
flowchart LR
  client[ClientApp] --> backend[BackendAPI]
  backend --> paymentsSvc[PaymentsService]
  paymentsSvc --> jazzcash[JazzCashGateway]
  paymentsSvc --> easypaisa[EasypaisaGateway]
  paymentsSvc --> bank[BankGateway]
  jazzcash --> webhooks[WebhookHandler]
  easypaisa --> webhooks
  bank --> webhooks
  webhooks --> billing[BillingDB]
```

Multi-tenant B2B considerations:

- Each **organization/tenant** has one or more customers and default payment
  methods.
- Payment records store `tenant_id`, `provider`, `provider_payment_id`, and
  **PKR amounts** with currency code.
- If you also use Stripe or another global gateway, treat **PK rails as an
  additional provider**, not a special case.

---

## Implementation Guide

### 1. Choose Providers and Payment Models

When the user is early stage:

- Start with **1–2 providers** (for example JazzCash + Easypaisa) to cover
  wallets and mobile users.
- Add a direct **bank gateway** later if needed for higher-ticket invoices.

Clarify which flows you need:

- **One-off checkout** – pay once for a license, credit bundle, or upgrade.
- **Subscriptions** – recurring SaaS plans in PKR.
- **Invoice payments** – pay a specific outstanding invoice via emailed link.

If the user is already on Stripe or a similar gateway:

- Keep **Stripe for international cards**.
- Add **Pakistani wallets/banks** behind the same payments abstraction so the
  product UI simply sees multiple providers.

### 2. Model Billing Entities

Enforce a minimal but explicit schema:

- `customers` – id, tenant_id, contact info.
- `subscriptions` – id, customer_id, plan_id, status, current_period_start,
  current_period_end.
- `invoices` – id, customer_id, amount_pkr, status, due_date.
- `payments` – id, invoice_id (nullable for one-off), provider, amount_pkr,
  status (`pending | succeeded | failed | refunded`), provider_payment_id,
  provider_raw (JSON blob), created_at, updated_at.

Never rely solely on the provider dashboard 
