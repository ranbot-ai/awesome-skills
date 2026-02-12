---
name: dropbox-automation
description: Automate Dropbox file management, sharing, search, uploads, downloads, and folder operations via Rube MCP (Composio). Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [html, api, pdf, markdown, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/dropbox-automation
---


# Dropbox Automation via Rube MCP

Automate Dropbox operations including file upload/download, search, folder management, sharing links, batch operations, and metadata retrieval through Composio's Dropbox toolkit.

**Toolkit docs**: [composio.dev/toolkits/dropbox](https://composio.dev/toolkits/dropbox)

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Dropbox connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `dropbox`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `dropbox`
3. If connection is not ACTIVE, follow the returned auth link to complete Dropbox OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Search for Files and Folders

**When to use**: User wants to find files or folders by name, content, or type

**Tool sequence**:
1. `DROPBOX_SEARCH_FILE_OR_FOLDER` - Search by query string with optional path scope and filters [Required]
2. `DROPBOX_SEARCH_CONTINUE` - Paginate through additional results using cursor [Required if has_more]
3. `DROPBOX_GET_METADATA` - Validate and get canonical path for a search result [Optional]
4. `DROPBOX_READ_FILE` - Read file content to verify it is the intended document [Optional]

**Key parameters**:
- `query`: Search string (case-insensitive, 1+ non-whitespace characters)
- `options.path`: Scope search to a folder (e.g., `"/Documents"`); empty string for root
- `options.file_categories`: Filter by type (`"image"`, `"document"`, `"pdf"`, `"folder"`, etc.)
- `options.file_extensions`: Filter by extension (e.g., `["jpg", "png"]`)
- `options.filename_only`: Set `true` to match filenames only (not content)
- `options.max_results`: Results per page (default 100, max 1000)

**Pitfalls**:
- Search returns `has_more: true` with a `cursor` when more results exist; MUST continue to avoid silently missing matches
- Maximum 10,000 matches total across all pages of search + search_continue
- `DROPBOX_GET_METADATA` returned `path_display` may differ in casing from user input; always use the returned canonical path
- File content from `DROPBOX_READ_FILE` may be returned as base64-encoded `file_content_bytes`; decode before parsing

### 2. Upload and Download Files

**When to use**: User wants to upload files to Dropbox or download files from it

**Tool sequence**:
1. `DROPBOX_UPLOAD_FILE` - Upload a file to a specified path [Required for upload]
2. `DROPBOX_READ_FILE` - Download/read a file from Dropbox [Required for download]
3. `DROPBOX_DOWNLOAD_ZIP` - Download an entire folder as a zip file [Optional]
4. `DROPBOX_SAVE_URL` - Save a file from a public URL directly to Dropbox [Optional]
5. `DROPBOX_GET_SHARED_LINK_FILE` - Download a file from a shared link URL [Optional]
6. `DROPBOX_EXPORT_FILE` - Export non-downloadable files like Dropbox Paper to markdown/HTML [Optional]

**Key parameters**:
- `path`: Dropbox path (must start with `/`, e.g., `"/Documents/report.pdf"`)
- `mode`: `"add"` (default, fail on conflict) or `"overwrite"` for uploads
- `autorename`: `true` to auto-rename on conflict instead of failing
- `content`: FileUploadable object with `s3key`, `mimetype`, and `name` for uploads
- `url`: Public URL for `DROPBOX_SAVE_URL`
- `export_format`: `"markdown"`, `"html"`, or `"plain_text"` for Paper docs

**Pitfalls**:
- `DROPBOX_SAVE_URL` is asynchronous and may take up to 15 minutes for large files
- `DROPBOX_DOWNLOAD_ZIP` folder must be under 20 GB with no single file over 4 GB and fewer than 10,000 entries
- `DROPBOX_READ_FILE` content may be base64-encoded; check response format
- Shared link downloads via `DROPBOX_GET_SHARED_LINK_FILE` may require `link_password` for protected links

### 3. Share Files and Manage Links

**When to use**: User wants to create sharing links or manage existing shared links

**Tool sequence**:
1. `DROPBOX_GET_METADATA` - Confirm file/folder exists and get canonical path [Prerequisite]
2. `DROPBOX_LIST_SHARED_LINKS` - Check for existing shared links to avoid duplicates [Prerequisite]
3. `DROPBOX_CREATE_SHARED_LINK` - Create a new shared link [Required]
4. `DROPBOX_GET_SHARED_LINK_METADATA` - Resolve a shared link URL to metadata [Optional]
5. `DROPBOX_LIST_SHARED_FOLDERS` - List all shared folders the user has access to [Optional]

**Key parameters**:
- `path`: File or folder path for link creation
- `settings.audience`: `"public"`, `"team"`, or `"no_one"`
- `settings.access`: `"viewer"` or `"editor"`
- `settings.expires`: ISO 8601 expiration date (e.g., `"2026-12-31T23:59:59Z"`)
- `settings.require_password` / `settings.link_password`: Password protection
- `settings.allow_download`: Boolean for download permission
- `direct_only`: For `LIST_SHARED_LI
