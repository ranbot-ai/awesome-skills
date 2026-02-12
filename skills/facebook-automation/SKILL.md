---
name: Facebook Automation
description: Automate Facebook Page management including post creation, scheduling, video uploads, Messenger conversations, and audience engagement via Composio 
category: Development & Code Tools
source: composio
tags: [mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/facebook-automation
---


# Facebook Automation

Automate Facebook Page operations -- create and schedule posts, upload videos, manage Messenger conversations, retrieve page insights, and handle scheduled content -- all orchestrated through the Composio MCP integration.

**Toolkit docs:** [composio.dev/toolkits/facebook](https://composio.dev/toolkits/facebook)

---

## Setup

1. Connect your Facebook account through the Composio MCP server at `https://rube.app/mcp`
2. The agent will prompt you with an authentication link if no active connection exists
3. Once connected, all `FACEBOOK_*` tools become available for execution
4. **Note:** This toolkit supports Facebook Pages only, not personal Facebook accounts

---

## Core Workflows

### 1. Discover Managed Pages
List all Facebook Pages you manage to get page IDs and access tokens for subsequent operations.

**Tool:** `FACEBOOK_LIST_MANAGED_PAGES`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `fields` | string | No | Comma-separated fields (default: `id,name,access_token,category,tasks,about,link,picture`) |
| `limit` | integer | No | Max pages per request (default: 25) |
| `user_id` | string | No | User ID (default: `me`) |

**Always run this first** to cache `page_id` values. Avoid repeating discovery calls -- cache the results.

---

### 2. Create & Schedule Posts
Publish or schedule text posts with optional links on a Facebook Page.

**Tool:** `FACEBOOK_CREATE_POST`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `page_id` | string | Yes | Numeric Page ID from managed pages |
| `message` | string | Yes | Text content of the post |
| `published` | boolean | No | `true` to publish immediately, `false` for draft/scheduled (default: true) |
| `scheduled_publish_time` | integer | No | Unix UTC timestamp; must be at least 10 minutes in the future |
| `link` | string | No | URL to include in the post |
| `targeting` | object | No | Audience targeting specifications |

**When scheduling:** Set `published=false` and provide `scheduled_publish_time` as a Unix UTC timestamp.

---

### 3. Create & Schedule Video Posts
Upload and schedule video content on a Facebook Page.

**Tool:** `FACEBOOK_CREATE_VIDEO_POST`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `page_id` | string | Yes | Numeric Page ID |
| `file_url` | string | Conditional | URL of the video file (provide `file_url` or `video`) |
| `video` | object | Conditional | Local file upload with `name`, `mimetype`, `s3key` |
| `title` | string | No | Video title |
| `description` | string | No | Video description |
| `published` | boolean | No | Publish immediately (default: true) |
| `scheduled_publish_time` | integer | No | Unix timestamp for scheduled publishing |

---

### 4. Manage Scheduled Posts
Review, reschedule, update, or publish scheduled content.

**Tools:**

- **`FACEBOOK_GET_SCHEDULED_POSTS`** -- List scheduled/unpublished posts for a page
  - `page_id` (required), `fields`, `limit` (max 100)
- **`FACEBOOK_RESCHEDULE_POST`** -- Change the scheduled publish time
- **`FACEBOOK_UPDATE_POST`** -- Edit caption/text on an existing post
- **`FACEBOOK_PUBLISH_SCHEDULED_POST`** -- Publish a scheduled post immediately

---

### 5. Read Page Messenger Conversations
Retrieve inbox conversations and message threads between users and your Page.

**Tool:** `FACEBOOK_GET_PAGE_CONVERSATIONS`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `page_id` | string | Yes | The Facebook Page ID |
| `fields` | string | No | Fields to return (default: `participants,updated_time,id`) |
| `limit` | integer | No | Conversations to return, max 25 |

Then retrieve full message threads:

**Tool:** `FACEBOOK_GET_CONVERSATION_MESSAGES`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `page_id` | string | Yes | Page ID that owns the conversation |
| `conversation_id` | string | Yes | Conversation ID in `t_` format (e.g., `t_3638640842939952`) |
| `fields` | string | No | Default: `id,created_time,from,to,message` |
| `limit` | integer | No | Messages to return, max 25 |

---

### 6. Send Messages & Mark as Seen
Respond to users via Messenger and mark messages as read.

**Tools:**

- **`FACEBOOK_SEND_MESSAGE`** -- Send a text message from the Page to a user via Messenger
- **`FACEBOOK_MARK_MESSAGE_SEEN`** -- Mark a user's message as seen by the Page

**Warning:** Both tools cause user-visible side effects. Only call after explicit confirmation.

---

## Known Pitfalls

| Pitfall | Details |
|---------|---------|
| **Scheduling too close to now** | `FACEBOOK_CREATE_POST` with `scheduled_publish_time` less than ~10 minutes in the future returns HTTP 400 -- enforce a larger buffer for bulk runs |
| **Unix UTC timestamps required** | `scheduled_publish_time` must be Unix UTC -- timezone conversion mistakes cause off-by-hours sched
