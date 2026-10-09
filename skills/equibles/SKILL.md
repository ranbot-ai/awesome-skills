---
name: equibles
description: Query Equibles for US stock market data: SEC filing search, XBRL financial statements, earnings call transcripts, insider and 13F holdings, and daily prices. 
category: Document Processing
source: antigravity
tags: [python, api, mcp, claude, ai, gpt, workflow, document, security, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/equibles
---


# Equibles: US Stock Market Data

## Overview

Equibles serves data on US-listed companies from SEC filings, company releases and earnings calls: full-text search over 10-K, 10-Q, 8-K and other filings, XBRL financial statements, earnings call transcripts, Form 4 insider transactions, 13F institutional holdings, congressional trades, short interest and end-of-day prices. Search results and statement lines carry the filing date and document they came from, so answers can cite their source.

The same data is available through a hosted MCP server and a JSON REST API. This skill covers both: when to use which, the filing search and read workflow, statements, insider and 13F data, transcripts, and the plan limits.

## When to Use

- Use when the user asks what a company's 10-K, 10-Q or 8-K says about a topic and wants the passage quoted.
- Use when the user wants an income statement, balance sheet or cash-flow statement for a fiscal year or quarter.
- Use when the user asks who bought or sold shares: company insiders (Forms 4 and 5), 13F institutional holders, or members of Congress.
- Use when the user wants an earnings call transcript or daily price history for a US-listed stock.
- Do not use for order execution, crypto or non-US macro series. Equibles never places trades.

## Access and Authentication

### MCP server (preferred when the client supports it)

- Endpoint: `https://mcp.equibles.com/mcp` (Streamable HTTP), listed in the official MCP registry as `io.github.daniel3303/equibles`.
- ChatGPT and Claude connect over OAuth with no API key. In Claude Code: `claude mcp add --transport http equibles https://mcp.equibles.com/mcp`, then run `/mcp` and choose Authenticate.
- If the client already has it connected, prefer its tools (`SearchDocuments`, `GetFinancialStatement`, `GetInsiderTransactions`, `GetTopHolders`, `GetEarningsCallTranscript`) over raw HTTP calls.
- Most tools only read data. Portfolio, watchlist and feedback tools write to the user's own Equibles account; call them only when the user asks.

### REST API

- Base URL: `https://api.equibles.com/v1`. OpenAPI spec: `https://api.equibles.com/openapi/v1.json`.
- Every request needs an API key (it starts with `eq_`). Read it from the `EQUIBLES_API_KEY` environment variable and send it as `Authorization: Bearer $EQUIBLES_API_KEY`. Never put the key in the URL or print it.
- A request without a key returns HTTP 401 with `"code": "unauthorized"`. That means a key is needed, not that the data is missing.
- Responses are JSON with camelCase fields and `yyyy-MM-dd` dates. Paged endpoints return `data` plus `meta` (`limit`, `offset`, `count`, `hasMore`).
- Errors share one shape: `{"error": {"code", "message", "status"}}`.

### Plans

- The free plan allows 100 requests a day, shared between MCP tool calls and REST requests, and resets at 00:00 UTC. No credit card.
- Free covers end-of-day prices. Option chains and intraday quotes need a Plus or Pro plan.
- REST responses with status 400 to 599 do not count against the daily allowance.

## How It Works

### Step 1: Search filings for the topic

```bash
curl -s -H "Authorization: Bearer $EQUIBLES_API_KEY" \
  "https://api.equibles.com/v1/stocks/AAPL/filings/search?query=tariffs&documentType=TenK&limit=3" \
  | jq '.data[] | {documentId, documentTypeName, filedDate, startLineNumber, url, text}'
```

Use `/v1/filings/search?query=...` (no ticker in the path) to search every company. Each excerpt carries a `documentId` and the line where it starts.

### Step 2: Read the surrounding lines

```bash
curl -s -H "Authorization: Bearer $EQUIBLES_API_KEY" \
  "https://api.equibles.com/v1/filings/$DOCUMENT_ID/lines?startLine=698&endLine=764" \
  | jq -r '.lines[] | "\(.number): \(.text)"'
```

Start at the excerpt's `startLineNumber` (Apple's tariff risk factor sat at line 698 of its 2025 10-K) and read at most 500 lines per request. Quote from these lines, and cite the filing type and `filedDate`.

### Step 3: Pull the numbers

```bash
curl -s -H "Authorization: Bearer $EQUIBLES_API_KEY" \
  "https://api.equibles.com/v1/stocks/MSFT/financial-statements/income?year=2025&period=FY" \
  | jq '{companyName, fiscalYear, fiscalPeriod, rows: [.data[] | {lineItem, value, unit, periodStart, periodEnd, form, filedDate}]}'
```

`statement` is `income`, `balance` or `cashflow`; `period` is `FY` or `Q1` to `Q4`. Fiscal years follow the company's own calendar (Microsoft's fiscal 2025 ended in June 2025), so state `periodEnd` with every figure.

## Examples

### Example 1: Open-market insider trades

```bash
curl -s -H "Authorization: Bearer $EQUIBLES_API_KEY" \
  "https://api.equibles.com/v1/stocks/INTC/insider-transactions?startDate=2026-01-01&limit=100" \
  | jq '[.data[] | select(.isOpenMarketTrade) | {transactionDate, insiderName, role, transactionType, shares, pricePerShare, value}]'
```

Filter on `isOpenMarketTrade`. `transactionType` also labels conversions, tax withholding and expirations as Buy or Sell, and those are n
