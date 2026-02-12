---
name: one-drive-automation
description: Automate OneDrive file management, search, uploads, downloads, sharing, permissions, and folder operations via Rube MCP (Composio). Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [api, pdf, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/one-drive-automation
---


# OneDrive Automation via Rube MCP

Automate OneDrive operations including file upload/download, search, folder management, sharing links, permissions management, and drive browsing through Composio's OneDrive toolkit.

**Toolkit docs**: [composio.dev/toolkits/one_drive](https://composio.dev/toolkits/one_drive)

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active OneDrive connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `one_drive`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `one_drive`
3. If connection is not ACTIVE, follow the returned auth link to complete Microsoft OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Search and Browse Files

**When to use**: User wants to find files or browse folder contents in OneDrive

**Tool sequence**:
1. `ONE_DRIVE_GET_DRIVE` - Verify drive access and get drive details [Prerequisite]
2. `ONE_DRIVE_SEARCH_ITEMS` - Keyword search across filenames, metadata, and content [Required]
3. `ONE_DRIVE_ONEDRIVE_LIST_ITEMS` - List all items in the root of a drive [Optional]
4. `ONE_DRIVE_GET_ITEM` - Get detailed metadata for a specific item, expand children [Optional]
5. `ONE_DRIVE_ONEDRIVE_FIND_FILE` - Find a specific file by exact name in a folder [Optional]
6. `ONE_DRIVE_ONEDRIVE_FIND_FOLDER` - Find a specific folder by name [Optional]
7. `ONE_DRIVE_LIST_DRIVES` - List all accessible drives [Optional]

**Key parameters**:
- `q`: Search query (plain keywords only, NOT KQL syntax)
- `search_scope`: `"root"` (folder hierarchy) or `"drive"` (includes shared items)
- `top`: Max items per page (default 200)
- `skip_token`: Pagination token from `@odata.nextLink`
- `select`: Comma-separated fields to return (e.g., `"id,name,webUrl,size"`)
- `orderby`: Sort order (e.g., `"name asc"`, `"name desc"`)
- `item_id`: Item ID for `GET_ITEM`
- `expand_relations`: Array like `["children"]` or `["thumbnails"]` for `GET_ITEM`
- `user_id`: `"me"` (default) or specific user ID/email

**Pitfalls**:
- `ONE_DRIVE_SEARCH_ITEMS` does NOT support KQL operators (`folder:`, `file:`, `filetype:`, `path:`); these are treated as literal text
- Wildcard characters (`*`, `?`) are NOT supported and are auto-removed; use file extension keywords instead (e.g., `"pdf"` not `"*.pdf"`)
- `ONE_DRIVE_ONEDRIVE_LIST_ITEMS` returns only root-level contents; use recursive `ONE_DRIVE_GET_ITEM` with `expand_relations: ["children"]` for deeper levels
- Large folders paginate; always follow `skip_token` / `@odata.nextLink` until exhausted
- Some drive ID formats may return "ObjectHandle is Invalid" errors due to Microsoft Graph API limitations

### 2. Upload and Download Files

**When to use**: User wants to upload files to OneDrive or download files from it

**Tool sequence**:
1. `ONE_DRIVE_ONEDRIVE_FIND_FOLDER` - Locate the target folder [Prerequisite]
2. `ONE_DRIVE_ONEDRIVE_UPLOAD_FILE` - Upload a file to a specified folder [Required for upload]
3. `ONE_DRIVE_DOWNLOAD_FILE` - Download a file by item ID [Required for download]
4. `ONE_DRIVE_GET_ITEM` - Get file details before download [Optional]

**Key parameters**:
- `file`: FileUploadable object with `s3key`, `mimetype`, and `name` for uploads
- `folder`: Destination path (e.g., `"/Documents/Reports"`) or folder ID for uploads
- `item_id`: File's unique identifier for downloads
- `file_name`: Desired filename with extension for downloads
- `drive_id`: Specific drive ID (for SharePoint or OneDrive for Business)
- `user_id`: `"me"` (default) or specific user identifier

**Pitfalls**:
- Upload automatically renames on conflict (no overwrite option by default)
- Large files are automatically handled via chunking
- `drive_id` overrides `user_id` when both are provided
- Item IDs vary by platform: OneDrive for Business uses `01...` prefix, OneDrive Personal uses `HASH!NUMBER` format
- Item IDs are case-sensitive; use exactly as returned from API

### 3. Share Files and Manage Permissions

**When to use**: User wants to share files/folders or manage who has access

**Tool sequence**:
1. `ONE_DRIVE_ONEDRIVE_FIND_FILE` or `ONE_DRIVE_ONEDRIVE_FIND_FOLDER` - Locate the item [Prerequisite]
2. `ONE_DRIVE_GET_ITEM_PERMISSIONS` - Check current permissions [Prerequisite]
3. `ONE_DRIVE_INVITE_USER_TO_DRIVE_ITEM` - Grant access to specific users [Required]
4. `ONE_DRIVE_CREATE_LINK` - Create a shareable link [Optional]
5. `ONE_DRIVE_UPDATE_DRIVE_ITEM_METADATA` - Update item metadata [Optional]

**Key parameters**:
- `item_id`: The file or folder to share
- `recipients`: Array of objects with `email` or `object_id`
- `roles`: Array with `"read"` or `"write"`
- `send_invitation`: `true` to send no
