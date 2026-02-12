---
name: NetSuite Automation
description: NetSuite Automation: manage customers, sales orders, invoices, inventory, and records via Oracle NetSuite ERP with SuiteQL queries 
category: Development & Code Tools
source: composio
tags: [api, json, mcp, automation, ai, llm]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/netsuite-automation
---


# NetSuite Automation

Automate Oracle NetSuite ERP operations including creating customers and sales orders, running SuiteQL queries, upserting records by external ID, and inspecting record metadata for comprehensive business management.

**Toolkit docs:** [composio.dev/toolkits/netsuite](https://composio.dev/toolkits/netsuite)

---

## Setup

This skill requires the **Rube MCP server** connected at `https://rube.app/mcp`.

Before executing any tools, ensure an active connection exists for the `netsuite` toolkit. If no connection is active, initiate one via `RUBE_MANAGE_CONNECTIONS`.

---

## Core Workflows

### 1. Create Sales Orders

Create customer orders with line items including item references, quantities, and pricing.

**Tool:** `NETSUITE_CREATE_SALES_ORDER`

**Key Parameters:**
- `entity` (required) -- Customer reference: `{"id": "<internal_id>"}`
- `item` (required) -- Container with `items` array, each containing:
  - `item` (required) -- Item reference: `{"id": "<internal_id>"}`
  - `quantity` (required) -- Units to order (non-negative)
  - `rate` -- Unit price (optional if item has default pricing)
  - `amount` -- Total line amount (alternative to rate)
  - `taxcode` -- Tax code reference: `{"id": "<internal_id>"}` (required if SuiteTax enabled)
  - `description` -- Line item notes
- `tranDate` -- Transaction date in `YYYY-MM-DD` format
- `memo` -- Header memo
- `orderStatus` -- `"A"` (Pending Approval) or `"B"` (Pending Fulfillment)
- `otherrefnum` -- External reference or PO number

**Example:**
```
Tool: NETSUITE_CREATE_SALES_ORDER
Arguments:
  entity: {"id": "1234"}
  item: {
    "items": [
      {"item": {"id": "56"}, "quantity": 10, "rate": 25.00},
      {"item": {"id": "78"}, "quantity": 5, "rate": 50.00}
    ]
  }
  tranDate: "2026-02-11"
  memo: "Q1 bulk order"
  orderStatus: "B"
```

---

### 2. Run SuiteQL Queries

Execute ad-hoc SQL queries against NetSuite data with server-side paging.

**Tool:** `NETSUITE_RUN_SUITEQL_QUERY`

**Key Parameters:**
- `q` (required) -- SuiteQL SELECT statement
- `limit` -- Rows per page (default varies)
- `offset` -- Zero-based index of first row (must be a multiple of `limit`)

**Examples:**
```
Tool: NETSUITE_RUN_SUITEQL_QUERY
Arguments:
  q: "SELECT id, companyname, email FROM customer WHERE isinactive = 'F' ORDER BY companyname"
  limit: 100
  offset: 0
```

```
Tool: NETSUITE_RUN_SUITEQL_QUERY
Arguments:
  q: "SELECT id, entitystatus, total FROM transaction WHERE type = 'SalesOrd' AND trandate >= '2026-01-01'"
  limit: 50
```

---

### 3. Create and Manage Customers

Create new customer records with subsidiary assignment and contact details.

**Tools:**
- `NETSUITE_CREATE_CUSTOMER` -- Create a new customer
- `NETSUITE_GET_CUSTOMER` -- Retrieve customer by internal ID
- `NETSUITE_UPDATE_CUSTOMER` -- Update existing customer (PATCH semantics)

**Key Parameters for `NETSUITE_CREATE_CUSTOMER`:**
- `body` (required) -- JSON object with customer data. Required fields:
  - `subsidiary` -- Object with `id` (subsidiary internal ID)
  - Either `companyName` (for businesses) or `firstName` + `lastName` (for individuals)
  - Optional: `email`, `phone`, `isPerson` (set to `"T"` for individuals), `comments`
- `replace` -- Comma-separated sublist names to fully replace (e.g., `"contacts,addressbook"`)

**Example:**
```
Tool: NETSUITE_CREATE_CUSTOMER
Arguments:
  body: {
    "companyName": "Acme Corp",
    "subsidiary": {"id": "1"},
    "email": "info@acme.com",
    "phone": "555-0100"
  }
```

---

### 4. Upsert Records by External ID

Create or update records idempotently using an external identifier. Essential for sync workflows.

**Tool:** `NETSUITE_UPSERT_RECORD_BY_EXTERNAL_ID`

**Key Parameters:**
- `record_type` (required) -- Record type name, e.g., `"customer"`, `"salesorder"`, `"customrecord_myrec"`
- `external_id` (required) -- External ID value (letters, numbers, underscore, hyphen only)
- `body` (required) -- JSON object matching the record schema; include mandatory fields when creating

**Example:**
```
Tool: NETSUITE_UPSERT_RECORD_BY_EXTERNAL_ID
Arguments:
  record_type: "customer"
  external_id: "CRM-CUST-42"
  body: {
    "companyName": "Acme Corp",
    "subsidiary": {"id": "1"},
    "email": "updated@acme.com"
  }
```

> **Warning:** Idempotency depends on consistent external ID usage. Mismatches silently create additional records instead of updating.

---

### 5. Inspect Record Metadata

Discover available fields, data types, constraints, and requirements before creating or updating records.

**Tool:** `NETSUITE_GET_RECORD_METADATA`

**Key Parameters:**
- `record_type` (required) -- e.g., `"customer"`, `"salesorder"`, `"invoice"`, `"vendor"`, `"employee"`, `"item"`
- `accept` -- `"application/schema+json"` (default, JSON Schema) or `"application/swagger+json"` (OpenAPI 3.0)

**Example:**
```
Tool: NETSUITE_GET_RECORD_METADATA
Arguments:
  record_type: "salesorder"
```

---

### 6. List and Filter Records

Retrieve multiple records with optional
