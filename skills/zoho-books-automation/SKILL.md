---
name: Zoho Books Automation
description: Automate Zoho Books accounting workflows including invoice creation, bill management, contact lookup, payment tracking, and multi-organization support through natural language commands 
category: Development & Code Tools
source: composio
tags: [html, pdf, json, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/zoho-books-automation
---


# Zoho Books Automation

Automate Zoho Books accounting workflows -- create and manage invoices, track bills and payments, look up contacts, export PDFs, and handle multi-organization setups -- all through natural language.

**Toolkit docs:** [composio.dev/toolkits/zoho_books](https://composio.dev/toolkits/zoho_books)

---

## Setup

1. Add the Rube MCP server to your environment: `https://rube.app/mcp`
2. Connect your Zoho Books account when prompted (OAuth flow via Composio)
3. Start issuing natural language commands for Zoho Books automation

---

## Core Workflows

### 1. Discover Organizations

Retrieve all organizations for the authenticated user. This is a prerequisite since `organization_id` is required by nearly every other endpoint.

**Tool:** `ZOHO_BOOKS_LIST_ORGANIZATIONS`

No parameters required. Returns organization IDs, names, and metadata.

> Always call this first to obtain the `organization_id` needed by all other Zoho Books tools.

Example prompt:
> "List my Zoho Books organizations"

---

### 2. Create and Manage Invoices

Create invoices with line items, manage existing invoices, and export them as PDFs.

**Create:** `ZOHO_BOOKS_CREATE_INVOICE`

Key parameters:
- `organization_id` -- target organization (required)
- `customer_id` -- customer to bill (required)
- `line_items` -- array of line items (required), each with:
  - `item_id` or `name` -- reference existing item or create ad-hoc line
  - `quantity`, `rate` -- amount details
  - `description`, `tax_id`, `discount` -- optional details
- `date` / `due_date` -- dates in `YYYY-MM-DD` format
- `invoice_number` -- custom number (set `ignore_auto_number_generation=true`)
- `discount` / `discount_type` -- invoice-level discount (`entity_level` or `item_level`)
- `notes` / `terms` -- printed on the invoice
- `send` -- email the invoice immediately after creation
- `payment_terms` -- number of days for payment

**List:** `ZOHO_BOOKS_LIST_INVOICES`

Key parameters:
- `organization_id` (required)
- `status` -- `sent`, `draft`, `overdue`, `paid`, `void`, `unpaid`, `partially_paid`, `viewed`
- `customer_id` / `customer_name` -- filter by customer
- `date_start` / `date_end` -- date range filter (`YYYY-MM-DD`)
- `search_text` -- search invoice number, reference, or customer name
- `sort_column` / `sort_order` -- sort by `date`, `due_date`, `total`, `balance`, etc.
- `page` / `per_page` -- pagination (max 200 per page)

**Get details:** `ZOHO_BOOKS_GET_INVOICE` -- fetch by `invoice_id` with `accept` format: `json`, `pdf`, or `html`

**Delete:** `ZOHO_BOOKS_DELETE_INVOICE` -- remove by `invoice_id`

**Bulk export:** `ZOHO_BOOKS_BULK_EXPORT_INVOICES_PDF` -- merge up to 25 invoices into a single PDF

**Bulk print:** `ZOHO_BOOKS_BULK_PRINT_INVOICES` -- generate a combined print-ready PDF for up to 25 invoices

Example prompt:
> "Create an invoice for customer 1234567890 with 2 line items: 10 units of Widget A at $25 each, and 5 units of Widget B at $50 each, due in 30 days"

---

### 3. Track and Manage Bills

List, view, and update vendor bills with comprehensive filtering.

**List:** `ZOHO_BOOKS_LIST_BILLS`

Key parameters:
- `organization_id` (required)
- `status` -- `paid`, `open`, `overdue`, `void`, `partially_paid`
- `vendor_id` / `vendor_name_contains` -- filter by vendor
- `bill_number` / `bill_number_contains` -- filter by bill number
- `date_start` / `date_end` -- date range filter
- `total_greater_than` / `total_less_than` -- amount range filters
- `sort_column` / `sort_order` -- sort by `vendor_name`, `bill_number`, `date`, `due_date`, `total`, etc.
- `page` / `per_page` -- pagination (max 200)

**Get details:** `ZOHO_BOOKS_GET_BILL` -- fetch full bill by `bill_id` and `organization_id`

**Update:** `ZOHO_BOOKS_UPDATE_BILL` -- modify existing bill (requires `bill_id`, `organization_id`, `vendor_id`, `bill_number`)

Example prompt:
> "List all overdue bills for my organization, sorted by due date"

---

### 4. Look Up Contacts

Search and filter contacts (customers and vendors) for use in invoices and bills.

**Tool:** `ZOHO_BOOKS_LIST_CONTACTS`

Key parameters:
- `organization_id` (required)
- `contact_type` -- `customer` or `vendor`
- `contact_name_contains` / `contact_name_startswith` -- name filters
- `email_contains` / `email_startswith` -- email filters
- `company_name_contains` -- company name filter
- `filter_by` -- status filter: `Status.Active`, `Status.Inactive`, `Status.Duplicate`, etc.
- `search_text` -- search by contact name or notes (max 100 chars)
- `sort_column` -- sort by `contact_name`, `email`, `outstanding_receivable_amount`, `created_time`, etc.
- `page` / `per_page` -- pagination (max 200)

Example prompt:
> "Find all active customers whose company name contains 'Acme'"

---

### 5. Track Invoice Payments

List all payments recorded against a specific invoice.

**Tool:** `ZOHO_BOOKS_LIST_INVOICE_PAYMENTS`

Key parameters:
- `invoice_id` -- the invoice to check (required)
- `organization_id` -- the organization (re
