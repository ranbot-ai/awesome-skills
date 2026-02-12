---
name: monday-automation
description: Automate Monday.com work management including boards, items, columns, groups, subitems, and updates via Rube MCP (Composio). Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [api, json, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/monday-automation
---


# Monday.com Automation via Rube MCP

Automate Monday.com work management workflows including board creation, item management, column value updates, group organization, subitems, and update/comment threads through Composio's Monday toolkit.

**Toolkit docs**: [composio.dev/toolkits/monday](https://composio.dev/toolkits/monday)

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Monday.com connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `monday`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `monday`
3. If connection is not ACTIVE, follow the returned auth link to complete Monday.com OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Create and Manage Boards

**When to use**: User wants to create a new board, list existing boards, or set up workspace structure.

**Tool sequence**:
1. `MONDAY_GET_WORKSPACES` - List available workspaces and resolve workspace ID [Prerequisite]
2. `MONDAY_LIST_BOARDS` - List existing boards to check for duplicates [Optional]
3. `MONDAY_CREATE_BOARD` - Create a new board with name, kind, and workspace [Required]
4. `MONDAY_CREATE_COLUMN` - Add columns to the new board [Optional]
5. `MONDAY_CREATE_GROUP` - Add groups to organize items [Optional]
6. `MONDAY_BOARDS` - Retrieve detailed board metadata [Optional]

**Key parameters**:
- `board_name`: Name for the new board (required)
- `board_kind`: "public", "private", or "share" (required)
- `workspace_id`: Numeric workspace ID; omit for default workspace
- `folder_id`: Folder ID; must be within `workspace_id` if both provided
- `template_id`: ID of accessible template to clone

**Pitfalls**:
- `board_kind` is required and must be one of: "public", "private", "share"
- If both `workspace_id` and `folder_id` are provided, the folder must exist within that workspace
- `template_id` must reference a template the authenticated user can access
- Board IDs are large integers; always use the exact value from API responses

### 2. Create and Manage Items

**When to use**: User wants to add tasks/items to a board, list existing items, or move items between groups.

**Tool sequence**:
1. `MONDAY_LIST_BOARDS` - Resolve board name to board ID [Prerequisite]
2. `MONDAY_LIST_GROUPS` - List groups on the board to get group_id [Prerequisite]
3. `MONDAY_LIST_COLUMNS` - Get column IDs and types for setting values [Prerequisite]
4. `MONDAY_CREATE_ITEM` - Create a new item with name and column values [Required]
5. `MONDAY_LIST_BOARD_ITEMS` - List all items on the board [Optional]
6. `MONDAY_MOVE_ITEM_TO_GROUP` - Move an item to a different group [Optional]
7. `MONDAY_ITEMS_PAGE` - Paginated item retrieval with filtering [Optional]

**Key parameters**:
- `board_id`: Board ID (required, integer)
- `item_name`: Item name, max 256 characters (required)
- `group_id`: Group ID string to place the item in (optional)
- `column_values`: JSON object or string mapping column IDs to values

**Pitfalls**:
- `column_values` must use column IDs (not titles); get them from `MONDAY_LIST_COLUMNS`
- Column value formats vary by type: status uses `{"index": 0}` or `{"label": "Done"}`, date uses `{"date": "YYYY-MM-DD"}`, people uses `{"personsAndTeams": [{"id": 123, "kind": "person"}]}`
- `item_name` has a 256-character maximum
- Subitem boards are NOT supported by `MONDAY_CREATE_ITEM`; use GraphQL via `MONDAY_CREATE_OBJECT`

### 3. Update Item Column Values

**When to use**: User wants to change status, date, text, or other column values on existing items.

**Tool sequence**:
1. `MONDAY_LIST_COLUMNS` or `MONDAY_COLUMNS` - Get column IDs and types [Prerequisite]
2. `MONDAY_LIST_BOARD_ITEMS` or `MONDAY_ITEMS_PAGE` - Find the target item ID [Prerequisite]
3. `MONDAY_CHANGE_SIMPLE_COLUMN_VALUE` - Update text, status, or dropdown with a string value [Required]
4. `MONDAY_UPDATE_ITEM` - Update complex column types (timeline, people, date) with JSON [Required]

**Key parameters for MONDAY_CHANGE_SIMPLE_COLUMN_VALUE**:
- `board_id`: Board ID (integer, required)
- `item_id`: Item ID (integer, required)
- `column_id`: Column ID string (required)
- `value`: Simple string value (e.g., "Done", "Working on it")
- `create_labels_if_missing`: true to auto-create status/dropdown labels (default true)

**Key parameters for MONDAY_UPDATE_ITEM**:
- `board_id`: Board ID (integer, required)
- `item_id`: Item ID (integer, required)
- `column_id`: Column ID string (required)
- `value`: JSON object matching the column type schema
- `create_labels_if_missing`: false by default; set true for status/dropdown

**Pitfalls**:
- Use `MONDAY_CHANGE_SIMPLE_COLUMN_VALUE` for simple text/status/dropdown updates (str
