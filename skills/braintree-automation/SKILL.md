---
name: Braintree Automation
description: Braintree Automation: manage payment processing via Stripe-compatible tools for customers, subscriptions, payment methods, and transactions 
category: Development & Code Tools
source: composio
tags: [mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/braintree-automation
---


# Braintree Automation

Automate payment processing operations via Stripe-compatible tooling including managing customers, subscriptions, payment methods, balance transactions, and customer searches. The Composio platform routes Braintree payment workflows through the Stripe toolkit for unified payment management.

**Toolkit docs:** [composio.dev/toolkits/braintree](https://composio.dev/toolkits/braintree)

---

## Setup

This skill requires the **Rube MCP server** connected at `https://rube.app/mcp`.

Before executing any tools, ensure an active connection exists for the `stripe` toolkit. If no connection is active, initiate one via `RUBE_MANAGE_CONNECTIONS`.

---

## Core Workflows

### 1. Create and Manage Customers

Create new customers and retrieve existing customer details.

**Tools:**
- `STRIPE_CREATE_CUSTOMER` -- Create a new customer
- `STRIPE_GET_CUSTOMERS_CUSTOMER` -- Retrieve a customer by ID
- `STRIPE_POST_CUSTOMERS_CUSTOMER` -- Update an existing customer
- `STRIPE_LIST_CUSTOMERS` -- List customers with pagination
- `STRIPE_GET_V1_CUSTOMERS_SEARCH_CUSTOMERS` -- Search customers by email, name, metadata

**Key Parameters for `STRIPE_CREATE_CUSTOMER`:**
- `email` -- Customer's primary email address
- `name` -- Full name or business name
- `phone` -- Phone number with country code
- `description` -- Internal reference notes
- `address` -- Billing address object with `line1`, `city`, `state`, `postal_code`, `country`

**Key Parameters for `STRIPE_GET_V1_CUSTOMERS_SEARCH_CUSTOMERS`:**
- `query` (required) -- Stripe Search Query Language. Must use `field:value` syntax:
  - `email:'user@example.com'` -- Exact match (case insensitive)
  - `name~'John'` -- Substring match (min 3 chars)
  - `metadata['key']:'value'` -- Metadata search
  - `created>1609459200` -- Timestamp comparison
  - Combine with `AND` or `OR` (max 10 clauses, cannot mix)
- `limit` -- Results per page (1--100, default 10)

**Example:**
```
Tool: STRIPE_CREATE_CUSTOMER
Arguments:
  email: "jane@example.com"
  name: "Jane Doe"
  description: "Enterprise plan customer"
  address: {
    "line1": "123 Main St",
    "city": "San Francisco",
    "state": "CA",
    "postal_code": "94105",
    "country": "US"
  }
```

---

### 2. Manage Subscriptions

Create subscriptions and view customer subscription details.

**Tools:**
- `STRIPE_CREATE_SUBSCRIPTION` -- Create a new subscription for an existing customer
- `STRIPE_GET_CUSTOMERS_CUSTOMER_SUBSCRIPTIONS` -- List all subscriptions for a customer
- `STRIPE_GET_CUSTOMERS_CUSTOMER_SUBS_SUB_EXPOSED_ID` -- Get a specific subscription

**Key Parameters for `STRIPE_CREATE_SUBSCRIPTION`:**
- `customer` (required) -- Customer ID, e.g., `"cus_xxxxxxxxxxxxxx"`
- `items` (required) -- Array of subscription items, each with:
  - `price` -- Price ID, e.g., `"price_xxxxxxxxxxxxxx"` (use this OR `price_data`)
  - `price_data` -- Inline price definition with `currency`, `product`, `unit_amount`, `recurring`
  - `quantity` -- Item quantity
- `default_payment_method` -- Payment method ID (not required for trials or invoice billing)
- `trial_period_days` -- Trial days (no payment required during trial)
- `collection_method` -- `"charge_automatically"` (default) or `"send_invoice"`
- `cancel_at_period_end` -- Cancel at end of billing period (boolean)

**Key Parameters for `STRIPE_GET_CUSTOMERS_CUSTOMER_SUBSCRIPTIONS`:**
- `customer` (required) -- Customer ID
- `status` -- Filter: `"active"`, `"all"`, `"canceled"`, `"trialing"`, `"past_due"`, etc.
- `limit` -- Results per page (1--100, default 10)

**Example:**
```
Tool: STRIPE_CREATE_SUBSCRIPTION
Arguments:
  customer: "cus_abc123"
  items: [{"price": "price_xyz789", "quantity": 1}]
  trial_period_days: 14
```

---

### 3. Manage Payment Methods

List and attach payment methods to customers.

**Tools:**
- `STRIPE_GET_CUSTOMERS_CUSTOMER_PAYMENT_METHODS` -- List a customer's payment methods
- `STRIPE_ATTACH_PAYMENT_METHOD` -- Attach a payment method to a customer

**Key Parameters for `STRIPE_GET_CUSTOMERS_CUSTOMER_PAYMENT_METHODS`:**
- `customer` (required) -- Customer ID
- `type` -- Filter by type: `"card"`, `"sepa_debit"`, `"us_bank_account"`, etc.
- `limit` -- Results per page (1--100, default 10)

**Example:**
```
Tool: STRIPE_GET_CUSTOMERS_CUSTOMER_PAYMENT_METHODS
Arguments:
  customer: "cus_abc123"
  type: "card"
  limit: 10
```

---

### 4. View Balance Transactions

Retrieve the history of balance changes for a customer.

**Tool:** `STRIPE_GET_CUSTOMERS_CUSTOMER_BALANCE_TRANSACTIONS`

**Key Parameters:**
- `customer` (required) -- Customer ID
- `created` -- Filter by creation date with comparison operators: `{"gte": 1609459200}` or `{"gt": 1609459200, "lt": 1640995200}`
- `invoice` -- Filter by related invoice ID
- `limit` -- Results per page (1--100)
- `starting_after` / `ending_before` -- Pagination cursors

**Example:**
```
Tool: STRIPE_GET_CUSTOMERS_CUSTOMER_BALANCE_TRANSACTIONS
Arguments:
  customer: "cus_abc123"
  limit: 25
  created: {"gte": 17040672
