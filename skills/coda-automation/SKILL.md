---
name: coda-automation
description: Automate Coda tasks via Rube MCP (Composio): manage docs, pages, tables, rows, formulas, permissions, and publishing. Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [html, api, markdown, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/coda-automation
---


# Coda Automation via Rube MCP

Automate Coda document and data operations through Composio's Coda toolkit via Rube MCP.

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Coda connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `coda`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `coda`
3. If connection is not ACTIVE, follow the returned auth link to complete Coda authentication
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Search and Browse Documents

**When to use**: User wants to find, list, or inspect Coda documents

**Tool sequence**:
1. `CODA_SEARCH_DOCS` or `CODA_LIST_AVAILABLE_DOCS` - Find documents [Required]
2. `CODA_RESOLVE_BROWSER_LINK` - Resolve a Coda URL to doc/page/table IDs [Alternative]
3. `CODA_LIST_PAGES` - List pages within a document [Optional]
4. `CODA_GET_A_PAGE` - Get specific page details [Optional]

**Key parameters**:
- `query`: Search term for finding documents
- `isOwner`: Filter to docs owned by the user
- `docId`: Document ID for page operations
- `pageIdOrName`: Page identifier or name
- `url`: Browser URL for resolve operations

**Pitfalls**:
- Document IDs are alphanumeric strings (e.g., 'AbCdEfGhIj')
- `CODA_RESOLVE_BROWSER_LINK` is the best way to convert a Coda URL to API IDs
- Page names may not be unique within a doc; prefer page IDs
- Search results include docs shared with the user, not just owned docs

### 2. Work with Tables and Data

**When to use**: User wants to read, write, or query table data

**Tool sequence**:
1. `CODA_LIST_TABLES` - List tables in a document [Prerequisite]
2. `CODA_LIST_COLUMNS` - Get column definitions for a table [Prerequisite]
3. `CODA_LIST_TABLE_ROWS` - List all rows with optional filters [Required]
4. `CODA_SEARCH_ROW` - Search for specific rows by query [Alternative]
5. `CODA_GET_A_ROW` - Get a specific row by ID [Optional]
6. `CODA_UPSERT_ROWS` - Insert or update rows in a table [Optional]
7. `CODA_GET_A_COLUMN` - Get details of a specific column [Optional]

**Key parameters**:
- `docId`: Document ID containing the table
- `tableIdOrName`: Table identifier or name
- `query`: Filter query for searching rows
- `rows`: Array of row objects for upsert operations
- `keyColumns`: Column IDs used for matching during upsert
- `sortBy`: Column to sort results by
- `useColumnNames`: Use column names instead of IDs in row data

**Pitfalls**:
- Table names may contain spaces; URL-encode if needed
- `CODA_UPSERT_ROWS` does insert if no match on `keyColumns`, update if match found
- `keyColumns` must reference columns that have unique values for reliable upserts
- Column IDs are different from column names; list columns first to map names to IDs
- `useColumnNames: true` allows using human-readable names in row data
- Row data values must match the column type (text, number, date, etc.)

### 3. Manage Formulas

**When to use**: User wants to list or evaluate formulas in a document

**Tool sequence**:
1. `CODA_LIST_FORMULAS` - List all named formulas in a doc [Required]
2. `CODA_GET_A_FORMULA` - Get a specific formula's current value [Optional]

**Key parameters**:
- `docId`: Document ID
- `formulaIdOrName`: Formula identifier or name

**Pitfalls**:
- Formulas are named calculations defined in the document
- Formula values are computed server-side; results reflect the current state
- Formula names are case-sensitive

### 4. Export Document Content

**When to use**: User wants to export a document or page to HTML or Markdown

**Tool sequence**:
1. `CODA_BEGIN_CONTENT_EXPORT` - Start an export job [Required]
2. `CODA_CONTENT_EXPORT_STATUS` - Poll export status until complete [Required]

**Key parameters**:
- `docId`: Document ID to export
- `outputFormat`: Export format ('html' or 'markdown')
- `pageIdOrName`: Specific page to export (optional, omit for full doc)
- `requestId`: Export request ID for status polling

**Pitfalls**:
- Export is asynchronous; poll status until `status` is 'complete'
- Large documents may take significant time to export
- Export URL in the completed response is temporary; download promptly
- Polling too frequently may hit rate limits; use 2-5 second intervals

### 5. Manage Permissions and Sharing

**When to use**: User wants to view or manage document access

**Tool sequence**:
1. `CODA_GET_SHARING_METADATA` - View current sharing settings [Required]
2. `CODA_GET_ACL_SETTINGS` - Get access control list settings [Optional]
3. `CODA_ADD_PERMISSION` - Grant access to a user or email [Optional]

**Key parameters**:
- `docId`: Document ID
- `access`: Permission level ('readonly', 'write', 'comment')
- `principal`: Object with email or u
