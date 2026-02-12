---
name: webflow-automation
description: Automate Webflow CMS collections, site publishing, page management, asset uploads, and ecommerce orders via Rube MCP (Composio). Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [html, node, api, pdf, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/webflow-automation
---


# Webflow Automation via Rube MCP

Automate Webflow operations including CMS collection management, site publishing, page inspection, asset uploads, and ecommerce order retrieval through Composio's Webflow toolkit.

**Toolkit docs**: [composio.dev/toolkits/webflow](https://composio.dev/toolkits/webflow)

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Webflow connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `webflow`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `webflow`
3. If connection is not ACTIVE, follow the returned auth link to complete Webflow OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Manage CMS Collection Items

**When to use**: User wants to create, update, list, or delete items in Webflow CMS collections (blog posts, products, team members, etc.)

**Tool sequence**:
1. `WEBFLOW_LIST_WEBFLOW_SITES` - List sites to find the target site_id [Prerequisite]
2. `WEBFLOW_LIST_COLLECTIONS` - List all collections for the site [Prerequisite]
3. `WEBFLOW_GET_COLLECTION` - Get collection schema to find valid field slugs [Prerequisite for create/update]
4. `WEBFLOW_LIST_COLLECTION_ITEMS` - List existing items with filtering and pagination [Optional]
5. `WEBFLOW_GET_COLLECTION_ITEM` - Get a specific item's full details [Optional]
6. `WEBFLOW_CREATE_COLLECTION_ITEM` - Create a new item with field data [Required for creation]
7. `WEBFLOW_UPDATE_COLLECTION_ITEM` - Update an existing item's fields [Required for updates]
8. `WEBFLOW_DELETE_COLLECTION_ITEM` - Permanently remove an item [Optional]
9. `WEBFLOW_PUBLISH_SITE` - Publish changes to make them live [Optional]

**Key parameters for CREATE_COLLECTION_ITEM**:
- `collection_id`: 24-character hex string from LIST_COLLECTIONS
- `field_data`: Object with field slug keys (NOT display names); must include `name` and `slug`
- `field_data.name`: Display name for the item
- `field_data.slug`: URL-friendly identifier (lowercase, hyphens, no spaces)
- `is_draft`: Boolean to create as draft (default false)

**Key parameters for UPDATE_COLLECTION_ITEM**:
- `collection_id`: Collection identifier
- `item_id`: 24-character hex MongoDB ObjectId of the existing item
- `fields`: Object with field slug keys and new values
- `live`: Boolean to publish changes immediately (default false)

**Field value types**:
- Text/Email/Link/Date: string
- Number: integer or float
- Boolean: true/false
- Image: `{"url": "...", "alt": "...", "fileId": "..."}`
- Multi-reference: array of reference ID strings
- Multi-image: array of image objects
- Option: option ID string

**Pitfalls**:
- Field keys must use the exact field `slug` from the collection schema, NOT display names
- Always call `GET_COLLECTION` first to retrieve the schema and identify correct field slugs
- `CREATE_COLLECTION_ITEM` requires `name` and `slug` in `field_data`
- `UPDATE_COLLECTION_ITEM` cannot create new items; it requires a valid existing `item_id`
- `item_id` must be a 24-character hexadecimal MongoDB ObjectId
- Slug must be lowercase alphanumeric with hyphens: `^[a-z0-9]+(?:-[a-z0-9]+)*$`
- CMS items are staged; use `PUBLISH_SITE` or set `live: true` to push to production

### 2. Manage Sites and Publishing

**When to use**: User wants to list sites, inspect site configuration, or publish staged changes

**Tool sequence**:
1. `WEBFLOW_LIST_WEBFLOW_SITES` - List all accessible sites [Required]
2. `WEBFLOW_GET_SITE_INFO` - Get detailed site metadata including domains and settings [Optional]
3. `WEBFLOW_PUBLISH_SITE` - Deploy all staged changes to live site [Required for publishing]

**Key parameters for PUBLISH_SITE**:
- `site_id`: Site identifier from LIST_WEBFLOW_SITES
- `custom_domains`: Array of custom domain ID strings (from GET_SITE_INFO)
- `publish_to_webflow_subdomain`: Boolean to publish to `{shortName}.webflow.io`
- At least one of `custom_domains` or `publish_to_webflow_subdomain` must be specified

**Pitfalls**:
- `PUBLISH_SITE` republishes ALL staged changes for selected domains -- verify no unintended drafts are pending
- Rate limit: 1 successful publish per minute
- For sites without custom domains, must set `publish_to_webflow_subdomain: true`
- `custom_domains` expects domain IDs (hex strings), not domain names
- Publishing is a production action -- always confirm with the user first

### 3. Manage Pages

**When to use**: User wants to list pages, inspect page metadata, or examine page DOM structure

**Tool sequence**:
1. `WEBFLOW_LIST_WEBFLOW_SITES` - Find the target site_id [Prerequisite]
2. `WEBFLOW_LIST_PAGES` - List all pages for a site with pagination [Required]
3. `WEBFLOW_GET_PAGE` - Get det
