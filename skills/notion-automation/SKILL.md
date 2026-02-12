---
name: notion-automation
description: Automate Notion tasks via Rube MCP (Composio): pages, databases, blocks, comments, users. Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [api, notion, json, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/notion-automation
---


# Notion Automation via Rube MCP

Automate Notion operations through Composio's Notion toolkit via Rube MCP.

**Toolkit docs**: [composio.dev/toolkits/notion](https://composio.dev/toolkits/notion)

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Notion connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `notion`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `notion`
3. If connection is not ACTIVE, follow the returned auth link to complete Notion OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Create and Manage Pages

**When to use**: User wants to create, update, or archive Notion pages

**Tool sequence**:
1. `NOTION_SEARCH_NOTION_PAGE` - Find parent page or existing page [Prerequisite]
2. `NOTION_CREATE_NOTION_PAGE` - Create a new page under a parent [Optional]
3. `NOTION_RETRIEVE_PAGE` - Get page metadata/properties [Optional]
4. `NOTION_UPDATE_PAGE` - Update page properties, title, icon, cover [Optional]
5. `NOTION_ARCHIVE_NOTION_PAGE` - Soft-delete (archive) a page [Optional]

**Key parameters**:
- `query`: Search text for SEARCH_NOTION_PAGE
- `parent_id`: Parent page or database ID
- `page_id`: Page ID for retrieval/update/archive
- `properties`: Page property values matching parent schema

**Pitfalls**:
- RETRIEVE_PAGE returns only metadata/properties, NOT body content; use FETCH_BLOCK_CONTENTS for page body
- ARCHIVE_NOTION_PAGE is a soft-delete (sets archived=true), not permanent deletion
- Broad searches can look incomplete unless has_more/next_cursor is fully paginated

### 2. Query and Manage Databases

**When to use**: User wants to query database rows, insert entries, or update records

**Tool sequence**:
1. `NOTION_SEARCH_NOTION_PAGE` - Find the database by name [Prerequisite]
2. `NOTION_FETCH_DATABASE` - Inspect schema and properties [Prerequisite]
3. `NOTION_QUERY_DATABASE` / `NOTION_QUERY_DATABASE_WITH_FILTER` - Query rows [Required]
4. `NOTION_INSERT_ROW_DATABASE` - Add new entries [Optional]
5. `NOTION_UPDATE_ROW_DATABASE` - Update existing entries [Optional]

**Key parameters**:
- `database_id`: Database ID (from search or URL)
- `filter`: Filter object matching Notion filter syntax
- `sorts`: Array of sort objects
- `start_cursor`: Pagination cursor from previous response
- `properties`: Property values matching database schema for inserts/updates

**Pitfalls**:
- 404 object_not_found usually means wrong database_id or the database is not shared with the integration
- Results are paginated; ignoring has_more/next_cursor silently truncates reads
- Schema mismatches or missing required properties cause 400 validation_error
- Formula and read-only fields cannot be set via INSERT_ROW_DATABASE
- Property names in filters must match schema exactly (case-sensitive)

### 3. Manage Blocks and Page Content

**When to use**: User wants to read, append, or modify content blocks in a page

**Tool sequence**:
1. `NOTION_FETCH_BLOCK_CONTENTS` - Read child blocks of a page [Required]
2. `NOTION_ADD_MULTIPLE_PAGE_CONTENT` - Append blocks to a page [Optional]
3. `NOTION_APPEND_TEXT_BLOCKS` - Append text-only blocks [Optional]
4. `NOTION_REPLACE_PAGE_CONTENT` - Replace all page content [Optional]
5. `NOTION_DELETE_BLOCK` - Remove a specific block [Optional]

**Key parameters**:
- `block_id` / `page_id`: Target page or block ID
- `content_blocks`: Array of block objects (NOT child_blocks)
- `text`: Plain text content for APPEND_TEXT_BLOCKS

**Pitfalls**:
- Use `content_blocks` parameter, NOT `child_blocks` -- the latter fails validation
- ADD_MULTIPLE_PAGE_CONTENT fails on archived pages; unarchive via UPDATE_PAGE first
- Created blocks are in response.data.results; persist block IDs for later edits
- DELETE_BLOCK is archival (archived=true), not permanent deletion

### 4. Manage Database Schema

**When to use**: User wants to create databases or modify their structure

**Tool sequence**:
1. `NOTION_FETCH_DATABASE` - Inspect current schema [Prerequisite]
2. `NOTION_CREATE_DATABASE` - Create a new database [Optional]
3. `NOTION_UPDATE_SCHEMA_DATABASE` - Modify database properties [Optional]

**Key parameters**:
- `parent_id`: Parent page ID for new databases
- `title`: Database title
- `properties`: Property definitions with types and options
- `database_id`: Database ID for schema updates

**Pitfalls**:
- Cannot change property types via UPDATE_SCHEMA; must create new property and migrate data
- Formula, rollup, and relation properties have complex configuration requirements

### 5. Manage Users and Comments

**When to use**: User wants to list workspace users or manage comments on pages

**Tool sequence**:
1. 
