---
name: supabase-automation
description: Automate Supabase database queries, table management, project administration, storage, edge functions, and SQL execution via Rube MCP (Composio). Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [typescript, api, json, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/supabase-automation
---


# Supabase Automation via Rube MCP

Automate Supabase operations including database queries, table schema inspection, SQL execution, project and organization management, storage buckets, edge functions, and service health monitoring through Composio's Supabase toolkit.

**Toolkit docs**: [composio.dev/toolkits/supabase](https://composio.dev/toolkits/supabase)

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Supabase connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `supabase`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `supabase`
3. If connection is not ACTIVE, follow the returned auth link to complete Supabase authentication
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Query and Manage Database Tables

**When to use**: User wants to read data from tables, inspect schemas, or perform CRUD operations

**Tool sequence**:
1. `SUPABASE_LIST_ALL_PROJECTS` - List projects to find the target project_ref [Prerequisite]
2. `SUPABASE_LIST_TABLES` - List all tables and views in the database [Prerequisite]
3. `SUPABASE_GET_TABLE_SCHEMAS` - Get detailed column types, constraints, and relationships [Prerequisite for writes]
4. `SUPABASE_SELECT_FROM_TABLE` - Query rows with filtering, sorting, and pagination [Required for reads]
5. `SUPABASE_BETA_RUN_SQL_QUERY` - Execute arbitrary SQL for complex queries, inserts, updates, or deletes [Required for writes]

**Key parameters for SELECT_FROM_TABLE**:
- `project_ref`: 20-character lowercase project reference
- `table`: Table or view name to query
- `select`: Comma-separated column list (supports nested selections and JSON paths like `profile->avatar_url`)
- `filters`: Array of filter objects with `column`, `operator`, `value`
- `order`: Sort expression like `created_at.desc`
- `limit`: Max rows to return (minimum 1)
- `offset`: Rows to skip for pagination

**PostgREST filter operators**:
- `eq`, `neq`: Equal / not equal
- `gt`, `gte`, `lt`, `lte`: Comparison operators
- `like`, `ilike`: Pattern matching (case-sensitive / insensitive)
- `is`: IS check (for null, true, false)
- `in`: In a list of values
- `cs`, `cd`: Contains / contained by (arrays)
- `fts`, `plfts`, `phfts`, `wfts`: Full-text search variants

**Key parameters for RUN_SQL_QUERY**:
- `ref`: Project reference (20 lowercase letters, pattern `^[a-z]{20}$`)
- `query`: Valid PostgreSQL SQL statement
- `read_only`: Boolean to force read-only transaction (safer for SELECTs)

**Pitfalls**:
- `project_ref` must be exactly 20 lowercase letters (a-z only, no numbers or hyphens)
- `SELECT_FROM_TABLE` is read-only; use `RUN_SQL_QUERY` for INSERT, UPDATE, DELETE operations
- For PostgreSQL array columns (text[], integer[]), use `ARRAY['item1', 'item2']` or `'{"item1", "item2"}'` syntax, NOT JSON array syntax `'["item1", "item2"]'`
- SQL identifiers that are case-sensitive must be double-quoted in queries
- Complex DDL operations may timeout (~60 second limit); break into smaller queries
- ERROR 42P01 "relation does not exist" usually means unquoted case-sensitive identifiers
- ERROR 42883 "function does not exist" means you are calling non-standard helpers; prefer information_schema queries

### 2. Manage Projects and Organizations

**When to use**: User wants to list projects, inspect configurations, or manage organizations

**Tool sequence**:
1. `SUPABASE_LIST_ALL_ORGANIZATIONS` - List all organizations (IDs and names) [Required]
2. `SUPABASE_GETS_INFORMATION_ABOUT_THE_ORGANIZATION` - Get detailed org info by slug [Optional]
3. `SUPABASE_LIST_MEMBERS_OF_AN_ORGANIZATION` - List org members with roles and MFA status [Optional]
4. `SUPABASE_LIST_ALL_PROJECTS` - List all projects with metadata [Required]
5. `SUPABASE_GETS_PROJECT_S_POSTGRES_CONFIG` - Get database configuration [Optional]
6. `SUPABASE_GETS_PROJECT_S_AUTH_CONFIG` - Get authentication configuration [Optional]
7. `SUPABASE_GET_PROJECT_API_KEYS` - Get API keys (sensitive -- handle carefully) [Optional]
8. `SUPABASE_GETS_PROJECT_S_SERVICE_HEALTH_STATUS` - Check service health [Optional]

**Key parameters**:
- `ref`: Project reference for project-specific tools
- `slug`: Organization slug (URL-friendly identifier) for org tools
- `services`: Array of services for health check: `auth`, `db`, `db_postgres_user`, `pg_bouncer`, `pooler`, `realtime`, `rest`, `storage`

**Pitfalls**:
- `LIST_ALL_ORGANIZATIONS` returns both `id` and `slug`; `LIST_MEMBERS_OF_AN_ORGANIZATION` expects `slug`, not `id`
- `GET_PROJECT_API_KEYS` returns live secrets -- NEVER log, display, or persist full key values
- `GETS_PROJECT_S_SERVICE_HEALTH_STATUS` requires a non-empty `services` array; empty a
