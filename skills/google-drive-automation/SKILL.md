---
name: google-drive-automation
description: Automate Google Drive file operations (upload, download, search, share, organize) via Rube MCP (Composio). Upload/download files, manage folders, share with permissions, and search across drives progr
category: Development & Code Tools
source: composio
tags: [html, api, gmail, pdf, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/google-drive-automation
---


# Google Drive Automation via Rube MCP

Automate Google Drive workflows including file upload/download, search, folder management, sharing/permissions, and organization through Composio's Google Drive toolkit.

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Google Drive connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `googledrive`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `googledrive`
3. If connection is not ACTIVE, follow the returned auth link to complete Google OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Upload and Download Files

**When to use**: User wants to upload files to or download files from Google Drive

**Tool sequence**:
1. `GOOGLEDRIVE_FIND_FILE` - Locate target folder for upload [Prerequisite]
2. `GOOGLEDRIVE_UPLOAD_FILE` - Upload a file (max 5MB) [Required]
3. `GOOGLEDRIVE_RESUMABLE_UPLOAD` - Upload large files [Fallback]
4. `GOOGLEDRIVE_DOWNLOAD_FILE` - Download a file by ID [Required]
5. `GOOGLEDRIVE_DOWNLOAD_FILE_OPERATION` - Track long-running downloads [Fallback]
6. `GOOGLEDRIVE_GET_FILE_METADATA` - Verify file after upload/download [Optional]

**Key parameters**:
- `file_to_upload`: Object with `name`, `mimetype`, and `s3key` (file must be in internal storage)
- `folder_to_upload_to`: Target folder ID (optional; uploads to root if omitted)
- `file_id`: ID of file to download
- `mime_type`: Export format for Google Workspace files only (omit for native files)

**Pitfalls**:
- `GOOGLEDRIVE_UPLOAD_FILE` requires `file_to_upload.s3key`; files must already be in internal storage
- For non-Google formats (Excel, PDF), do NOT set `mime_type`; it causes errors for native files
- Download responses provide a temporary URL at `data.downloaded_file_content.s3url`, not inline bytes
- Use `GOOGLEDRIVE_RESUMABLE_UPLOAD` for files >5MB or when basic uploads fail

### 2. Search and List Files

**When to use**: User wants to find specific files or browse Drive contents

**Tool sequence**:
1. `GOOGLEDRIVE_FIND_FILE` - Search by name, content, type, date, or folder [Required]
2. `GOOGLEDRIVE_LIST_FILES` - Browse files with folder scoping [Alternative]
3. `GOOGLEDRIVE_LIST_SHARED_DRIVES` - Enumerate shared drives [Optional]
4. `GOOGLEDRIVE_GET_FILE_METADATA` - Get detailed file info [Optional]
5. `GOOGLEDRIVE_GET_ABOUT` - Check storage quota and supported formats [Optional]

**Key parameters**:
- `q`: Drive query string (e.g., "name contains 'report'", "mimeType = 'application/pdf'")
- `corpora`: Search scope ('user', 'domain', 'drive', 'allDrives')
- `fields`: Response fields to include (e.g., 'files(id,name,mimeType)')
- `orderBy`: Sort key ('modifiedTime desc', 'name', 'quotaBytesUsed desc')
- `pageSize`: Results per page (max 1000)
- `pageToken`: Pagination cursor from `nextPageToken`
- `folder_id`: Scope search to a specific folder

**Pitfalls**:
- 403 PERMISSION_DENIED if OAuth scopes insufficient for shared drives
- Pagination required; files are in `response.data.files`; follow `nextPageToken` until exhausted
- `corpora="domain"` may trigger 400; try `"allDrives"` with `includeItemsFromAllDrives=true`
- Query complexity limits: >5-10 OR clauses may error "The query is too complex"
- Wildcards (*) NOT supported in `name`; use `contains` for partial matching
- 'My Drive' is NOT searchable by name; use `folder_id='root'` for root folder
- User email searches: use `'user@example.com' in owners` (NOT `owner:user@example.com`)

### 3. Share Files and Manage Permissions

**When to use**: User wants to share files or manage access permissions

**Tool sequence**:
1. `GOOGLEDRIVE_FIND_FILE` - Locate the file to share [Prerequisite]
2. `GOOGLEDRIVE_ADD_FILE_SHARING_PREFERENCE` - Set sharing permission [Required]
3. `GOOGLEDRIVE_LIST_PERMISSIONS` - View current permissions [Optional]
4. `GOOGLEDRIVE_GET_PERMISSION` - Inspect a specific permission [Optional]
5. `GOOGLEDRIVE_UPDATE_PERMISSION` - Modify existing permission [Optional]
6. `GOOGLEDRIVE_DELETE_PERMISSION` - Revoke access [Optional]

**Key parameters**:
- `file_id`: ID of file to share
- `type`: 'user', 'group', 'domain', or 'anyone'
- `role`: 'owner', 'organizer', 'fileOrganizer', 'writer', 'commenter', 'reader'
- `email_address`: Required for type='user' or 'group'
- `domain`: Required for type='domain'
- `transfer_ownership`: Required when role='owner'

**Pitfalls**:
- Invalid type/email combinations trigger 4xx errors
- Using `type='anyone'` or powerful roles is risky; get explicit user confirmation
- Org policies may block certain sharing types, causing 403
- Permission changes may take time to propagate
- Use `GMAIL_SEARCH_PEOPLE` to 
