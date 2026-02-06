---
name: googlesheets-automation
description: Automate Google Sheets operations (read, write, format, filter, manage spreadsheets) via Rube MCP (Composio). Read/write data, manage tabs, apply formatting, and search rows programmatically. 
category: Development & Code Tools
source: composio
tags: [api, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/googlesheets-automation
---


# Google Sheets Automation via Rube MCP

Automate Google Sheets workflows including reading/writing data, managing spreadsheets and tabs, formatting cells, filtering rows, and upserting records through Composio's Google Sheets toolkit.

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Google Sheets connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `googlesheets`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `googlesheets`
3. If connection is not ACTIVE, follow the returned auth link to complete Google OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Read and Write Data

**When to use**: User wants to read data from or write data to a Google Sheet

**Tool sequence**:
1. `GOOGLESHEETS_SEARCH_SPREADSHEETS` - Find spreadsheet by name if ID unknown [Prerequisite]
2. `GOOGLESHEETS_GET_SHEET_NAMES` - Enumerate tab names to target the right sheet [Prerequisite]
3. `GOOGLESHEETS_BATCH_GET` - Read data from one or more ranges [Required]
4. `GOOGLESHEETS_BATCH_UPDATE` - Write data to a range or append rows [Required]
5. `GOOGLESHEETS_VALUES_UPDATE` - Update a single specific range [Alternative]
6. `GOOGLESHEETS_SPREADSHEETS_VALUES_APPEND` - Append rows to end of table [Alternative]

**Key parameters**:
- `spreadsheet_id`: Alphanumeric ID from the spreadsheet URL (between '/d/' and '/edit')
- `ranges`: A1 notation array (e.g., 'Sheet1!A1:Z1000'); always use bounded ranges
- `sheet_name`: Tab name (case-insensitive matching supported)
- `values`: 2D array where each inner array is a row
- `first_cell_location`: Starting cell in A1 notation (omit to append)
- `valueInputOption`: 'USER_ENTERED' (parsed) or 'RAW' (literal)

**Pitfalls**:
- Mis-cased or non-existent tab names error "Sheet 'X' not found"
- Empty ranges may omit `valueRanges[i].values`; treat missing as empty array
- `GOOGLESHEETS_BATCH_UPDATE` values must be a 2D array (list of lists), even for a single row
- Unbounded ranges like 'A:Z' on sheets with >10,000 rows may cause timeouts; always bound with row limits
- Append follows the detected `tableRange`; use returned `updatedRange` to verify placement

### 2. Create and Manage Spreadsheets

**When to use**: User wants to create a new spreadsheet or manage tabs within one

**Tool sequence**:
1. `GOOGLESHEETS_CREATE_GOOGLE_SHEET1` - Create a new spreadsheet [Required]
2. `GOOGLESHEETS_ADD_SHEET` - Add a new tab/worksheet [Required]
3. `GOOGLESHEETS_UPDATE_SHEET_PROPERTIES` - Rename, hide, reorder, or color tabs [Optional]
4. `GOOGLESHEETS_GET_SPREADSHEET_INFO` - Get full spreadsheet metadata [Optional]
5. `GOOGLESHEETS_FIND_WORKSHEET_BY_TITLE` - Check if a specific tab exists [Optional]

**Key parameters**:
- `title`: Spreadsheet or sheet tab name
- `spreadsheetId`: Target spreadsheet ID
- `forceUnique`: Auto-append suffix if tab name exists (default true)
- `properties.gridProperties`: Set row/column counts, frozen rows

**Pitfalls**:
- Sheet names must be unique within a spreadsheet
- Default sheet names are locale-dependent ('Sheet1' in English, 'Hoja 1' in Spanish)
- Don't use `index` when creating multiple sheets in parallel (causes 'index too high' errors)
- `GOOGLESHEETS_GET_SPREADSHEET_INFO` can return 403 if account lacks access

### 3. Search and Filter Rows

**When to use**: User wants to find specific rows or apply filters to sheet data

**Tool sequence**:
1. `GOOGLESHEETS_LOOKUP_SPREADSHEET_ROW` - Find first row matching exact cell value [Required]
2. `GOOGLESHEETS_SET_BASIC_FILTER` - Apply filter/sort to a range [Alternative]
3. `GOOGLESHEETS_CLEAR_BASIC_FILTER` - Remove existing filter [Optional]
4. `GOOGLESHEETS_BATCH_GET` - Read filtered results [Optional]

**Key parameters**:
- `query`: Exact text value to match (matches entire cell content)
- `range`: A1 notation range to search within
- `case_sensitive`: Boolean for case-sensitive matching (default false)
- `filter.range`: Grid range with sheet_id for basic filter
- `filter.criteria`: Column-based filter conditions
- `filter.sortSpecs`: Sort specifications

**Pitfalls**:
- `GOOGLESHEETS_LOOKUP_SPREADSHEET_ROW` matches entire cell content, not substrings
- Sheet names with spaces must be single-quoted in ranges (e.g., "'My Sheet'!A:Z")
- Bare sheet names without ranges are not supported for lookup; always specify a range

### 4. Upsert Rows by Key

**When to use**: User wants to update existing rows or insert new ones based on a unique key column

**Tool sequence**:
1. `GOOGLESHEETS_UPSERT_ROWS` - Update matching rows or append new ones [Required]

**Key parameters**:
- `spreadsheetId`: Target spreadsheet ID
- `sheetName`: Tab name
- `keyColumn`
