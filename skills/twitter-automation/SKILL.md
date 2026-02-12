---
name: twitter-automation
description: Automate Twitter/X tasks via Rube MCP (Composio): posts, search, users, bookmarks, lists, media. Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [api, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/twitter-automation
---


# Twitter/X Automation via Rube MCP

Automate Twitter/X operations through Composio's Twitter toolkit via Rube MCP.

**Toolkit docs**: [composio.dev/toolkits/twitter](https://composio.dev/toolkits/twitter)

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Twitter connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `twitter`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `twitter`
3. If connection is not ACTIVE, follow the returned auth link to complete Twitter OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Create and Manage Posts

**When to use**: User wants to create, delete, or look up tweets/posts

**Tool sequence**:
1. `TWITTER_USER_LOOKUP_ME` - Get authenticated user info [Prerequisite]
2. `TWITTER_UPLOAD_MEDIA` / `TWITTER_UPLOAD_LARGE_MEDIA` - Upload media [Optional]
3. `TWITTER_CREATION_OF_A_POST` - Create a new post [Required]
4. `TWITTER_POST_LOOKUP_BY_POST_ID` - Look up a specific post [Optional]
5. `TWITTER_POST_DELETE_BY_POST_ID` - Delete a post [Optional]

**Key parameters**:
- `text`: Post text content (max 280 weighted characters)
- `media__media_ids`: Array of media ID strings for attachments
- `reply__in_reply_to_tweet_id`: Tweet ID to reply to
- `quote_tweet_id`: Tweet ID to quote
- `id`: Post ID for lookup/delete

**Pitfalls**:
- Post text is limited to 280 weighted characters; some characters count as more than one
- Posting is NOT idempotent; retrying on timeout will create duplicate posts
- Media IDs must be numeric strings, not integers
- UPLOAD_LARGE_MEDIA is for videos/GIFs; UPLOAD_MEDIA for images
- Always call USER_LOOKUP_ME first to get the authenticated user's ID

### 2. Search Posts

**When to use**: User wants to find tweets matching specific criteria

**Tool sequence**:
1. `TWITTER_RECENT_SEARCH` - Search recent tweets (last 7 days) [Required]
2. `TWITTER_FULL_ARCHIVE_SEARCH` - Search full archive (Academic access) [Optional]
3. `TWITTER_RECENT_SEARCH_COUNTS` - Get tweet count matching query [Optional]

**Key parameters**:
- `query`: Search query using Twitter search operators
- `max_results`: Results per page (10-100)
- `next_token`: Pagination token
- `start_time`/`end_time`: ISO 8601 time range
- `tweet__fields`: Comma-separated fields to include
- `expansions`: Related objects to expand

**Pitfalls**:
- RECENT_SEARCH covers only the last 7 days; use FULL_ARCHIVE_SEARCH for older tweets
- FULL_ARCHIVE_SEARCH requires Academic Research or Enterprise access
- Query operators: `from:username`, `to:username`, `is:retweet`, `has:media`, `-is:retweet`
- Empty results return `meta.result_count: 0` with no `data` field
- Rate limits vary by endpoint and access level; check response headers

### 3. Look Up Users

**When to use**: User wants to find or inspect Twitter user profiles

**Tool sequence**:
1. `TWITTER_USER_LOOKUP_ME` - Get authenticated user [Optional]
2. `TWITTER_USER_LOOKUP_BY_USERNAME` - Look up by username [Optional]
3. `TWITTER_USER_LOOKUP_BY_ID` - Look up by user ID [Optional]
4. `TWITTER_USER_LOOKUP_BY_IDS` - Batch look up multiple users [Optional]

**Key parameters**:
- `username`: Twitter handle without @ prefix
- `id`: Numeric user ID string
- `ids`: Comma-separated user IDs for batch lookup
- `user__fields`: Fields to return (description, public_metrics, etc.)

**Pitfalls**:
- Usernames are case-insensitive but must not include the @ prefix
- User IDs are numeric strings, not integers
- Suspended or deleted accounts return errors, not empty results
- LOOKUP_BY_IDS accepts max 100 IDs per request

### 4. Manage Bookmarks

**When to use**: User wants to save, view, or remove bookmarked tweets

**Tool sequence**:
1. `TWITTER_USER_LOOKUP_ME` - Get authenticated user ID [Prerequisite]
2. `TWITTER_BOOKMARKS_BY_USER` - List bookmarked posts [Required]
3. `TWITTER_ADD_POST_TO_BOOKMARKS` - Bookmark a post [Optional]
4. `TWITTER_REMOVE_A_BOOKMARKED_POST` - Remove bookmark [Optional]

**Key parameters**:
- `id`: User ID (from USER_LOOKUP_ME) for listing bookmarks
- `tweet_id`: Tweet ID to bookmark or unbookmark
- `max_results`: Results per page
- `pagination_token`: Token for next page

**Pitfalls**:
- Bookmarks require the authenticated user's ID, not username
- Bookmarks are private; only the authenticated user can see their own
- Pagination uses `pagination_token`, not `next_token`

### 5. Manage Lists

**When to use**: User wants to view or manage Twitter lists

**Tool sequence**:
1. `TWITTER_USER_LOOKUP_ME` - Get authenticated user ID [Prerequisite]
2. `TWITTER_GET_A_USER_S_OWNED_LISTS` - List owned lists [Optional]
3. `TWITTER_GET_A_USER_S_LIST_MEMBERSHIPS` - List member
