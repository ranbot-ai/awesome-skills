---
name: confluence-automation
description: Automate Confluence page creation, content search, space management, labels, and hierarchy navigation via Rube MCP (Composio). Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [html, api, markdown, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/confluence-automation
---


# Confluence Automation via Rube MCP

Automate Confluence operations including page creation and updates, content search with CQL, space management, label tagging, and page hierarchy navigation through Composio's Confluence toolkit.

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Confluence connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `confluence`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `confluence`
3. If connection is not ACTIVE, follow the returned auth link to complete Confluence OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Create and Update Pages

**When to use**: User wants to create new documentation or update existing Confluence pages

**Tool sequence**:
1. `CONFLUENCE_GET_SPACES` - List spaces to find the target space ID [Prerequisite]
2. `CONFLUENCE_SEARCH_CONTENT` - Find existing page to avoid duplicates or locate parent [Optional]
3. `CONFLUENCE_GET_PAGE_BY_ID` - Get current page content and version number before updating [Prerequisite for updates]
4. `CONFLUENCE_CREATE_PAGE` - Create a new page in a space [Required for creation]
5. `CONFLUENCE_UPDATE_PAGE` - Update an existing page with new content and incremented version [Required for updates]
6. `CONFLUENCE_ADD_CONTENT_LABEL` - Tag the page with labels after creation [Optional]

**Key parameters**:
- `spaceId`: Space ID or key (e.g., `"DOCS"`, `"12345678"`) -- space keys are auto-converted to IDs
- `title`: Page title (must be unique within a space)
- `parentId`: Parent page ID for creating child pages; omit to place under space homepage
- `body.storage.value`: HTML/XHTML content in Confluence storage format
- `body.storage.representation`: Must be `"storage"` for create operations
- `version.number`: For updates, must be current version + 1
- `version.message`: Optional change description

**Pitfalls**:
- Confluence enforces unique page titles per space; creating a page with a duplicate title will fail
- `UPDATE_PAGE` requires `version.number` set to current version + 1; always fetch current version first with `GET_PAGE_BY_ID`
- Content must be in Confluence storage format (XHTML), not plain text or Markdown
- `CREATE_PAGE` uses `body.storage.value` while `UPDATE_PAGE` uses `body.value` with `body.representation`
- `GET_PAGE_BY_ID` requires a numeric long ID, not a UUID or string

### 2. Search Content

**When to use**: User wants to find pages, blog posts, or content across Confluence

**Tool sequence**:
1. `CONFLUENCE_SEARCH_CONTENT` - Keyword search with intelligent relevance ranking [Required]
2. `CONFLUENCE_CQL_SEARCH` - Advanced search using Confluence Query Language [Alternative]
3. `CONFLUENCE_GET_PAGE_BY_ID` - Hydrate full content for selected search results [Optional]
4. `CONFLUENCE_GET_PAGES` - Browse pages sorted by date when search relevance is weak [Fallback]

**Key parameters for SEARCH_CONTENT**:
- `query`: Search text matched against page titles with intelligent ranking
- `spaceKey`: Limit search to a specific space
- `limit`: Max results (default 25, max 250)
- `start`: Pagination offset (0-based)

**Key parameters for CQL_SEARCH**:
- `cql`: CQL query string (e.g., `text ~ "API docs" AND space = DOCS AND type = page`)
- `expand`: Comma-separated properties (e.g., `content.space`, `content.body.storage`)
- `excerpt`: `highlight`, `indexed`, or `none`
- `limit`: Max results (max 250; reduced to 25-50 when using body expansions)

**CQL operators and fields**:
- Fields: `text`, `title`, `label`, `space`, `type`, `creator`, `lastModified`, `created`, `ancestor`
- Operators: `=`, `!=`, `~` (contains), `!~`, `>`, `<`, `>=`, `<=`, `IN`, `NOT IN`
- Functions: `currentUser()`, `now("-7d")`, `now("-30d")`
- Example: `title ~ "meeting" AND lastModified > now("-7d") ORDER BY lastModified DESC`

**Pitfalls**:
- `CONFLUENCE_SEARCH_CONTENT` fetches up to 300 pages and applies client-side filtering -- not a true full-text search
- `CONFLUENCE_CQL_SEARCH` is the real full-text search; use `text ~ "term"` for content body search
- HTTP 429 rate limits can occur; throttle to ~2 requests/second with backoff
- Using body expansions in CQL_SEARCH may reduce max results to 25-50
- Search indexing is not immediate; recently created pages may not appear

### 3. Manage Spaces

**When to use**: User wants to list, create, or inspect Confluence spaces

**Tool sequence**:
1. `CONFLUENCE_GET_SPACES` - List all spaces with optional filtering [Required]
2. `CONFLUENCE_GET_SPACE_BY_ID` - Get detailed metadata for a specific space [Optional]
3. `CONFLUENCE_CREATE_SPACE` - Create a new space with key and name [Optional]
4. `CONFLUENCE_GET_SPACE_PRO
