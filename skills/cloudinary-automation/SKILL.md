---
name: Cloudinary Automation
description: Automate Cloudinary media management including folder organization, upload presets, asset lookup, transformations, and usage monitoring through natural language commands 
category: Development & Code Tools
source: composio
tags: [api, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/cloudinary-automation
---


# Cloudinary Automation

Automate Cloudinary media management workflows -- create folders, configure upload presets, look up assets, manage transformations, search folders, and monitor usage -- all through natural language.

**Toolkit docs:** [composio.dev/toolkits/cloudinary](https://composio.dev/toolkits/cloudinary)

---

## Setup

1. Add the Rube MCP server to your environment: `https://rube.app/mcp`
2. Connect your Cloudinary account when prompted (API key auth via Composio)
3. Start issuing natural language commands for Cloudinary automation

---

## Core Workflows

### 1. Organize Assets with Folders

Create folder structures for organizing hosted images, videos, and raw files.

**Tool:** `CLOUDINARY_CREATE_FOLDER`

Key parameters:
- `folder` -- full path of the new asset folder (required), e.g., `images/events/2023`

Supporting tools:
- `CLOUDINARY_SEARCH_FOLDERS` -- search folders by name, path, or creation date using Lucene-like expressions
  - `expression` -- search filter (e.g., `name:sample AND path:events`)
  - `max_results` -- 1-500 results (default 50)
  - `sort_by` -- list of sort objects (e.g., `[{"created_at": "desc"}]`)
  - `next_cursor` -- pagination cursor
- `CLOUDINARY_GET_RESOURCES_BY_ASSET_FOLDER` -- list assets within a specific folder

Example prompt:
> "Create a folder called 'marketing/campaigns/spring-2026' in Cloudinary"

---

### 2. Configure Upload Presets

Define centralized upload behavior including target folder, allowed formats, transformations, tags, and overwrite rules.

**Tool:** `CLOUDINARY_CREATE_UPLOAD_PRESET`

Key parameters:
- `name` -- preset name (auto-generated if omitted)
- `folder` -- target folder path for uploads (e.g., `samples/`)
- `allowed_formats` -- comma-separated list (e.g., `jpg,png,webp`)
- `tags` -- comma-separated tags to apply (e.g., `marketing,thumbnail`)
- `transformation` -- incoming transformation (e.g., `c_limit,w_500`)
- `eager` -- eager transformations to generate on upload (e.g., `c_fill,g_face,h_150,w_150`)
- `unsigned` -- allow unsigned uploads (`true`/`false`)
- `overwrite` -- overwrite existing assets with same public_id (cannot be `true` when `unsigned=true`)
- `resource_type` -- `image`, `video`, or `raw` (default `image`)
- `unique_filename` -- append random suffix to avoid collisions (default `true`)
- `use_filename` -- use original filename (default `false`)
- `moderation` -- moderation type: `manual`, `webpurify`, `aws_rek`, etc.
- `auto_tagging` -- confidence threshold 0.0-1.0 for AI auto-tagging
- `notification_url` -- webhook URL for upload notifications

Example prompt:
> "Create an upload preset called 'product-images' that only allows JPG and PNG, stores in 'products/' folder, and auto-tags with 0.7 confidence"

---

### 3. Look Up Asset Details

Retrieve full details for a specific asset by its public ID, including metadata, derived assets, and related resources.

**Tool:** `CLOUDINARY_GET_RESOURCE_BY_PUBLIC_ID`

Key parameters:
- `public_id` -- the asset's public ID (required)
- `resource_type` -- `image`, `video`, or `raw` (required)
- `type` -- delivery type: `upload`, `private`, `authenticated`, `fetch`, etc. (required)
- `colors` -- include color histogram and predominant colors
- `faces` -- include detected face coordinates
- `media_metadata` -- include IPTC, XMP, and detailed metadata
- `quality_analysis` -- include quality analysis scores
- `phash` -- include perceptual hash for similarity detection
- `versions` -- include backed-up versions
- `related` -- include related assets
- `max_results` -- max derived/related assets to return (1-500)

Example prompt:
> "Get full details for the image 'products/hero-banner' including color analysis and quality scores"

---

### 4. Manage Transformations and Derived Assets

List existing transformations, apply eager transformations to uploaded assets, and clean up derived resources.

**Tools:**
- `CLOUDINARY_GET_TRANSFORMATIONS` -- list all named and unnamed transformations
  - `max_results` -- 1-500 (default 10)
  - `next_cursor` -- pagination cursor
- `CLOUDINARY_EXPLICIT_RESOURCE` -- update an existing asset: pre-generate transformations, update metadata, move to new folders, or modify tags
  - `public_id` -- target asset (required)
  - `eager` -- list of transformation strings to pre-generate (e.g., `["c_fill,w_300,h_200", "c_thumb,w_100,h_100,g_face"]`)
  - `eager_async` -- generate transformations asynchronously
  - `tags` -- replace existing tags
  - `asset_folder` -- move asset to a new folder
  - `display_name` -- set display name
  - `context` -- key-value metadata (e.g., `{"alt": "Mountain view"}`)
  - `invalidate` -- invalidate CDN cache (takes up to 1 hour)
- `CLOUDINARY_DELETE_DERIVED_RESOURCES` -- delete specific derived assets by IDs (up to 100 per call)

Example prompt:
> "Pre-generate a 300x200 fill crop and a 100x100 face-detection thumbnail for asset 'products/hero-banner'"

---

### 5. Monitor Usage and Configuration

Check account-level usage limits, 
