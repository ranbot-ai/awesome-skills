---
name: box-automation
description: Automate Box cloud storage operations including file upload/download, search, folder management, sharing, collaborations, and metadata queries via Rube MCP (Composio). Always search tools first for cu
category: Development & Code Tools
source: composio
tags: [api, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/box-automation
---


# Box Automation via Rube MCP

Automate Box operations including file upload/download, content search, folder management, collaboration, metadata queries, and sign requests through Composio's Box toolkit.

**Toolkit docs**: [composio.dev/toolkits/box](https://composio.dev/toolkits/box)

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Box connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `box`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `box`
3. If connection is not ACTIVE, follow the returned auth link to complete Box OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Upload and Download Files

**When to use**: User wants to upload files to Box or download files from it

**Tool sequence**:
1. `BOX_SEARCH_FOR_CONTENT` - Find the target folder if path is unknown [Prerequisite]
2. `BOX_GET_FOLDER_INFORMATION` - Verify folder exists and get folder_id [Prerequisite]
3. `BOX_LIST_ITEMS_IN_FOLDER` - Browse folder contents and discover file IDs [Optional]
4. `BOX_UPLOAD_FILE` - Upload a file to a specific folder [Required for upload]
5. `BOX_DOWNLOAD_FILE` - Download a file by file_id [Required for download]
6. `BOX_CREATE_ZIP_DOWNLOAD` - Bundle multiple files/folders into a zip [Optional]

**Key parameters**:
- `parent_id`: Folder ID for upload destination (use `"0"` for root folder)
- `file`: FileUploadable object with `s3key`, `mimetype`, and `name` for uploads
- `file_id`: Unique file identifier for downloads
- `version`: Optional file version ID for downloading specific versions
- `fields`: Comma-separated list of attributes to return

**Pitfalls**:
- Uploading to a folder with existing filenames can trigger conflict behavior; decide overwrite vs rename semantics
- Files over 50MB should use chunk upload APIs (not available via standard tools)
- The `attributes` part of upload must come before the `file` part or you get HTTP 400 with `metadata_after_file_contents`
- File IDs and folder IDs are numeric strings extractable from Box web app URLs (e.g., `https://*.app.box.com/files/123` gives file_id `"123"`)

### 2. Search and Browse Content

**When to use**: User wants to find files, folders, or web links by name, content, or metadata

**Tool sequence**:
1. `BOX_SEARCH_FOR_CONTENT` - Full-text search across files, folders, and web links [Required]
2. `BOX_LIST_ITEMS_IN_FOLDER` - Browse contents of a specific folder [Optional]
3. `BOX_GET_FILE_INFORMATION` - Get detailed metadata for a specific file [Optional]
4. `BOX_GET_FOLDER_INFORMATION` - Get detailed metadata for a specific folder [Optional]
5. `BOX_QUERY_FILES_FOLDERS_BY_METADATA` - Search by metadata template values [Optional]
6. `BOX_LIST_RECENTLY_ACCESSED_ITEMS` - List recently accessed items [Optional]

**Key parameters**:
- `query`: Search string supporting operators (`""` exact match, `AND`, `OR`, `NOT` - uppercase only)
- `type`: Filter by `"file"`, `"folder"`, or `"web_link"`
- `ancestor_folder_ids`: Limit search to specific folders (comma-separated IDs)
- `file_extensions`: Filter by file type (comma-separated, no dots)
- `content_types`: Search in `"name"`, `"description"`, `"file_content"`, `"comments"`, `"tags"`
- `created_at_range` / `updated_at_range`: Date filters as comma-separated RFC3339 timestamps
- `limit`: Results per page (default 30)
- `offset`: Pagination offset (max 10000)
- `folder_id`: For `LIST_ITEMS_IN_FOLDER` (use `"0"` for root)

**Pitfalls**:
- Queries with offset > 10000 are rejected with HTTP 400
- `BOX_SEARCH_FOR_CONTENT` requires either `query` or `mdfilters` parameter
- Misconfigured filters can silently omit expected items; validate with small test queries first
- Boolean operators (`AND`, `OR`, `NOT`) must be uppercase
- `BOX_LIST_ITEMS_IN_FOLDER` requires pagination via `marker` or `offset`/`usemarker`; partial listings are common
- Standard folders sort items by type first (folders before files before web links)

### 3. Manage Folders

**When to use**: User wants to create, update, move, copy, or delete folders

**Tool sequence**:
1. `BOX_GET_FOLDER_INFORMATION` - Verify folder exists and check permissions [Prerequisite]
2. `BOX_CREATE_FOLDER` - Create a new folder [Required for create]
3. `BOX_UPDATE_FOLDER` - Rename, move, or update folder settings [Required for update]
4. `BOX_COPY_FOLDER` - Copy a folder to a new location [Optional]
5. `BOX_DELETE_FOLDER` - Move folder to trash [Required for delete]
6. `BOX_PERMANENTLY_REMOVE_FOLDER` - Permanently delete a trashed folder [Optional]

**Key parameters**:
- `name`: Folder name (no `/`, `\`, trailing spaces, or `.`/`..`)
- `parent__id`: Parent folder ID (use `"0"` for r
