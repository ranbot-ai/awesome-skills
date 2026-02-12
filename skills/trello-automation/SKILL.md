---
name: trello-automation
description: Automate Trello boards, cards, and workflows via Rube MCP (Composio). Create cards, manage lists, assign members, and search across boards programmatically. 
category: Development & Code Tools
source: composio
tags: [api, markdown, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/trello-automation
---


# Trello Automation via Rube MCP

Automate Trello board management, card creation, and team workflows through Composio's Rube MCP integration.

**Toolkit docs**: [composio.dev/toolkits/trello](https://composio.dev/toolkits/trello)

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Trello connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `trello`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `trello`
3. If connection is not ACTIVE, follow the returned auth link to complete Trello auth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Create a Card on a Board

**When to use**: User wants to add a new card/task to a Trello board

**Tool sequence**:
1. `TRELLO_GET_MEMBERS_BOARDS_BY_ID_MEMBER` - List boards to find target board ID [Prerequisite]
2. `TRELLO_GET_BOARDS_LISTS_BY_ID_BOARD` - Get lists on board to find target list ID [Prerequisite]
3. `TRELLO_ADD_CARDS` - Create the card on the resolved list [Required]
4. `TRELLO_ADD_CARDS_CHECKLISTS_BY_ID_CARD` - Add a checklist to the card [Optional]
5. `TRELLO_ADD_CARDS_CHECKLIST_CHECK_ITEM_BY_ID_CARD_BY_ID_CHECKLIST` - Add items to the checklist [Optional]

**Key parameters**:
- `idList`: 24-char hex ID (NOT list name)
- `name`: Card title
- `desc`: Card description (supports Markdown)
- `pos`: Position ('top'/'bottom')
- `due`: Due date (ISO 8601 format)

**Pitfalls**:
- Store returned id (idCard) immediately; downstream checklist operations fail without it
- Checklist payload may be nested (data.data); extract idChecklist from inner object
- One API call per checklist item; large checklists can trigger rate limits

### 2. Manage Boards and Lists

**When to use**: User wants to view, browse, or restructure board layout

**Tool sequence**:
1. `TRELLO_GET_MEMBERS_BOARDS_BY_ID_MEMBER` - List all boards for the user [Required]
2. `TRELLO_GET_BOARDS_BY_ID_BOARD` - Get detailed board info [Required]
3. `TRELLO_GET_BOARDS_LISTS_BY_ID_BOARD` - Get lists (columns) on the board [Optional]
4. `TRELLO_GET_BOARDS_MEMBERS_BY_ID_BOARD` - Get board members [Optional]
5. `TRELLO_GET_BOARDS_LABELS_BY_ID_BOARD` - Get labels on the board [Optional]

**Key parameters**:
- `idMember`: Use 'me' for authenticated user
- `filter`: 'open', 'starred', or 'all'
- `idBoard`: 24-char hex or 8-char shortLink (NOT board name)

**Pitfalls**:
- Some runs return boards under response.data.details[]—don't assume flat top-level array
- Lists may be nested under results[0].response.data.details—parse defensively
- ISO 8601 timestamps with trailing 'Z' must be parsed as timezone-aware

### 3. Move Cards Between Lists

**When to use**: User wants to change a card's status by moving it to another list

**Tool sequence**:
1. `TRELLO_GET_SEARCH` - Find the card by name or keyword [Prerequisite]
2. `TRELLO_GET_BOARDS_LISTS_BY_ID_BOARD` - Get destination list ID [Prerequisite]
3. `TRELLO_UPDATE_CARDS_BY_ID_CARD` - Update card's idList to move it [Required]

**Key parameters**:
- `idCard`: Card ID from search
- `idList`: Destination list ID
- `pos`: Optional ordering within new list

**Pitfalls**:
- Search returns partial matches; verify card name before updating
- Moving doesn't update position within new list; set pos if ordering matters

### 4. Assign Members to Cards

**When to use**: User wants to assign team members to cards

**Tool sequence**:
1. `TRELLO_GET_BOARDS_MEMBERS_BY_ID_BOARD` - Get member IDs from the board [Prerequisite]
2. `TRELLO_ADD_CARDS_ID_MEMBERS_BY_ID_CARD` - Add a member to the card [Required]

**Key parameters**:
- `idCard`: Target card ID
- `value`: Member ID to assign

**Pitfalls**:
- UPDATE_CARDS_ID_MEMBERS replaces entire member list; use ADD_CARDS_ID_MEMBERS to append
- Member must have board permissions

### 5. Search and Filter Cards

**When to use**: User wants to find specific cards across boards

**Tool sequence**:
1. `TRELLO_GET_SEARCH` - Search by query string [Required]

**Key parameters**:
- `query`: Search string (supports board:, list:, label:, is:open/archived operators)
- `modelTypes`: Set to 'cards'
- `partial`: Set to 'true' for prefix matching

**Pitfalls**:
- Search indexing has delay; newly created cards may not appear for several minutes
- For exact name matching, use TRELLO_GET_BOARDS_CARDS_BY_ID_BOARD and filter locally
- Query uses word tokenization; common words may be ignored as stop words

### 6. Add Comments and Attachments

**When to use**: User wants to add context to an existing card

**Tool sequence**:
1. `TRELLO_ADD_CARDS_ACTIONS_COMMENTS_BY_ID_CARD` - Post a comment on the card [Required]
2. `TRELLO_ADD_CARDS_ATTACHMENTS_BY_ID_CARD` - Attach a file or URL [
