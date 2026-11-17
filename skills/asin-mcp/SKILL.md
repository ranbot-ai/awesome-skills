---
name: asin-mcp
description: Find Amazon ASINs, read current offers and price history, and manage a price watchlist with target-price alerts through Asin's MCP server. Use when the user chooses Asin. 
category: Development & Code Tools
source: antigravity
tags: [api, mcp, ai, agent, workflow, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/asin-mcp
---


# Asin MCP

## Overview

Use the Asin MCP tools to answer Amazon price questions and to keep a watchlist
of products. The read tools search Amazon for an ASIN, list who sells a product
and at what price, and return the price history of any ASIN on 11 Amazon
marketplaces. The watchlist tools add a product, check it on a schedule, email
the account owner when the price reaches a target, and pause or remove it.

The server requires an Asin API key. Some calls use credits from the account
that owns the key; tracked products also use credits on each scheduled check.

`pangolinfo-amazon-data-research` and `datawebot` read Amazon product, review and
seller data for research. This skill adds price history over time and a
persistent watchlist with alerts, which change the user's Asin account.

## When to Use This Skill

- The user chooses Asin, or the Asin tools that are connected to the host.
- The user wants the price history, lowest price or average price of an Amazon
  product.
- The user wants the current offers for an ASIN: Amazon's own price and the
  cheapest new and used offers.
- The user wants to track a product and get an email when it drops to a price,
  or wants to see, change or remove the products they track.

Respect an explicitly chosen provider. This skill does not change defaults or
configure servers automatically.

## Prerequisites

The host must already have a remote MCP connection to
`https://www.asin.dev/api/mcp` with Streamable HTTP, and the user's API key as a
Bearer token in the `Authorization` header. Keys are issued in the
[Asin dashboard](https://www.asin.dev/app). The same server is also published
as the `@asindev/mcp` npm package for stdio; it reads the key from the
`ASIN_API_KEY` environment variable. See the
[server README](https://github.com/asindotdev/asin-mcp) for client examples.

Client configuration formats differ. Get the user's approval before you change
their agent configuration. Reference the key through the host's environment or
secret mechanism. Do not put it in a shared config file or in chat. Do not
replace an existing connection.

Use the host's tool discovery to confirm that the server exposes the tools named
below. Hosts can add a server prefix to the names. Installing this skill does not
install or connect the MCP server. To stop using the service, disable or remove
its connection in the host's MCP settings.

## How It Works

### 1. Find the product

Get the ASIN or an Amazon link, and the marketplace (`com`, `co.uk`, `de`, `fr`,
`it`, `es`, `ca`, `co.jp`, `com.br`, `com.mx` or `in`; default `com`). If the
user only has a product name, call `search_amazon` with `query` and
`marketplace`. It is free and limited to 30 searches per hour. Confirm the right
result with the user when several products match.

### 2. Read prices

| Tool | Main arguments | Notes |
| --- | --- | --- |
| `get_offers` | `asin`, `marketplace` | Offers as last read. Free; never reads Amazon. |
| `fetch_offers` | `asin`, `marketplace`, optional `refresh` | Reads Amazon for 1 credit, refunded if Amazon does not answer. A read from the last 3 hours is returned free instead. |
| `get_asin_history` | `asin`, `marketplace`, `days` (default 90) | Every price Asin read for that ASIN, with lowest, highest and average. |
| `list_products` | optional `asin`, `marketplace`, `filter`, `page`, `limit` | The user's watchlist. |
| `get_product` | `id`, `days` | One tracked product and its price history. |
| `get_account` | none | Plan, credits left, products tracked and their monthly credit use. |

Start with `get_offers`. Call `fetch_offers` only when the user needs a fresh
read, and `refresh: true` only when even a 3-hour-old read is too old. Each tool
description states its cost; read it before a batch of calls.

`list_products` takes a `filter` that matches the app's tabs: `all`, `drops`,
`target`, `out_of_stock`, `attention` or `paused`.

### 3. Change the watchlist only on request

These tools change the user's Asin account. Before each call, state what will
change and the credit impact, and wait for the user's confirmation.

| Tool | Effect |
| --- | --- |
| `track_product` | Adds a product (`product`: ASIN or Amazon link) with an optional `target_price` and `interval_minutes` (default 1440, daily). It is then checked on that schedule. |
| `update_product` | Changes `target_price`, `alert_on_drop`, `interval_minutes` or `paused` on a tracked product (`id`). Send only what changes. |
| `check_product` | Asks for a check now (1 credit), at most once per 5 minutes. A paused product must be resumed first. |
| `delete_product` | Removes the product and its price history. This cannot be undone. |

Scheduled checks use credits. Checks more often than daily need a plan or a
credit pack (every 60 minutes with a pack or Starter, 30 with Pro, 5 with
Business, per the tool description). Call `get_account` to show the user the
monthly credit use before you shorten an interval or track many products.

Target-price an
