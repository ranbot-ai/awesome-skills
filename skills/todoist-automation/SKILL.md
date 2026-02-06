---
name: todoist-automation
description: Automate Todoist task management, projects, sections, filtering, and bulk operations via Rube MCP (Composio). Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [api, markdown, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/todoist-automation
---


# Todoist Automation via Rube MCP

Automate Todoist operations including task creation and management, project organization, section management, filtering, and bulk task workflows through Composio's Todoist toolkit.

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Todoist connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `todoist`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `todoist`
3. If connection is not ACTIVE, follow the returned auth link to complete Todoist OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Create and Manage Tasks

**When to use**: User wants to create, update, complete, reopen, or delete tasks

**Tool sequence**:
1. `TODOIST_GET_ALL_PROJECTS` - List projects to find the target project ID [Prerequisite]
2. `TODOIST_GET_ALL_SECTIONS` - List sections within a project for task placement [Optional]
3. `TODOIST_CREATE_TASK` - Create a single task with content, due date, priority, labels [Required]
4. `TODOIST_BULK_CREATE_TASKS` - Create multiple tasks in one request [Alternative]
5. `TODOIST_UPDATE_TASK` - Modify task properties (content, due date, priority, labels) [Optional]
6. `TODOIST_CLOSE_TASK` - Mark a task as completed [Optional]
7. `TODOIST_REOPEN_TASK` - Restore a previously completed task [Optional]
8. `TODOIST_DELETE_TASK` - Permanently remove a task [Optional]

**Key parameters for CREATE_TASK**:
- `content`: Task title (supports markdown and hyperlinks)
- `description`: Additional notes (do NOT put due dates here)
- `project_id`: Alphanumeric project ID; omit to add to Inbox
- `section_id`: Alphanumeric section ID for placement within a project
- `parent_id`: Task ID for creating subtasks
- `priority`: 1 (normal) to 4 (urgent) -- note: Todoist UI shows p1=urgent, API p4=urgent
- `due_string`: Natural language date like `"tomorrow at 3pm"`, `"every Friday at 9am"`
- `due_date`: Specific date `YYYY-MM-DD` format
- `due_datetime`: Specific date+time in RFC3339 `YYYY-MM-DDTHH:mm:ssZ`
- `labels`: Array of label name strings
- `duration` + `duration_unit`: Task duration (e.g., `30` + `"minute"`)

**Pitfalls**:
- Only one `due_*` field can be used at a time (except `due_lang` which can accompany any)
- Do NOT embed due dates in `content` or `description` -- use `due_string` field
- Do NOT embed duration phrases like "for 30 minutes" in `due_string` -- use `duration` + `duration_unit`
- `priority` in API: 1=normal, 4=urgent (opposite of Todoist UI display where p1=urgent)
- Task IDs can be numeric or alphanumeric; use the format returned by the API
- `CLOSE_TASK` marks complete; `DELETE_TASK` permanently removes -- they are different operations

### 2. Manage Projects

**When to use**: User wants to list, create, update, or inspect projects

**Tool sequence**:
1. `TODOIST_GET_ALL_PROJECTS` - List all projects with metadata [Required]
2. `TODOIST_GET_PROJECT` - Get details for a specific project by ID [Optional]
3. `TODOIST_CREATE_PROJECT` - Create a new project with name, color, view style [Optional]
4. `TODOIST_UPDATE_PROJECT` - Modify project properties [Optional]

**Key parameters**:
- `name`: Project name (required for creation)
- `color`: Todoist palette color (e.g., `"blue"`, `"red"`, `"green"`, `"charcoal"`)
- `view_style`: `"list"` or `"board"` layout
- `parent_id`: Parent project ID for creating sub-projects
- `is_favorite` / `favorite`: Boolean to mark as favorite
- `project_id`: Required for update and get operations

**Pitfalls**:
- Projects with similar names can lead to selecting the wrong project_id; always verify
- `CREATE_PROJECT` uses `favorite` while `UPDATE_PROJECT` uses `is_favorite` -- different field names
- Use the project `id` returned by API, not the `v2_id`, for downstream operations
- Alphanumeric/URL-style project IDs may cause HTTP 400 in some tools; use numeric ID if available

### 3. Manage Sections

**When to use**: User wants to organize tasks within projects using sections

**Tool sequence**:
1. `TODOIST_GET_ALL_PROJECTS` - Find the target project ID [Prerequisite]
2. `TODOIST_GET_ALL_SECTIONS` - List existing sections to avoid duplicates [Prerequisite]
3. `TODOIST_CREATE_SECTION` - Create a new section in a project [Required]
4. `TODOIST_UPDATE_SECTION` - Rename an existing section [Optional]
5. `TODOIST_DELETE_SECTION` - Permanently remove a section [Optional]

**Key parameters**:
- `project_id`: Required -- the project to create the section in
- `name`: Section name (required for creation)
- `order`: Integer position within the project (lower values appear first)
- `section_id`: Required for update and delete operations

**Pitfalls**:
- `CREATE_SECT
