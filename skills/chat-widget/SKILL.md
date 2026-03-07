---
name: chat-widget
description: Build a real-time support chat system with a floating widget for users and an admin dashboard for support staff. Use when the user wants live chat, customer support chat, real-time messaging, or in-ap
category: Document Processing
source: antigravity
tags: [typescript, react, node, api, ai, template, design, document, security, prisma]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/chat-widget
---


# Live Support Chat Widget

Build a real-time support chat system with a floating widget for users and an admin dashboard for support staff.

## When to Use This Skill

Use when the user wants to:
- Add a live chat widget to their app
- Build customer support chat functionality
- Create real-time messaging between users and admins
- Add an in-app support channel

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        FRONTEND                                 │
├─────────────────────────────┬───────────────────────────────────┤
│   User Widget               │   Admin Dashboard                 │
│   - Floating chat button    │   - Chat list (active/archived)   │
│   - Message panel           │   - Conversation view             │
│   - Unread badge            │   - Archive/restore controls      │
│   - Connection indicator    │   - User info display             │
└─────────────┬───────────────┴───────────────┬───────────────────┘
              │                               │
              │     WebSocket + REST API      │
              ▼                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                        BACKEND                                  │
├─────────────────────────────────────────────────────────────────┤
│   Channels                  │   Controllers                     │
│   - ChatChannel (per chat)  │   - User: get/create chat         │
│   - AdminChannel (global)   │   - Admin: list, view, archive    │
├─────────────────────────────┼───────────────────────────────────┤
│   Models                    │   Jobs                            │
│   - Chat (1 per user)       │   - Email notification (delayed)  │
│   - Message (many per chat) │                                   │
└─────────────────────────────────────────────────────────────────┘
```

## Implementation Guide

### Step 1: Data Models

Create two tables: `support_chats` and `support_messages`.

**support_chats**
```
id              - primary key (UUID recommended)
user_id         - foreign key to users (UNIQUE - one chat per user)
last_message_at - timestamp (for sorting chats by recency)
admin_viewed_at - timestamp (tracks when admin last viewed)
archived_at     - timestamp (null = active, set = archived)
created_at
updated_at
```

**support_messages**
```
id              - primary key (UUID recommended)
chat_id         - foreign key to support_chats
content         - text (required)
sender_type     - enum: 'user' | 'admin'
read_at         - timestamp (null = unread)
created_at
updated_at
```

**Key indexes:**
- `support_chats.user_id` (unique)
- `support_chats.last_message_at` (for sorting)
- `support_chats.archived_at` (for filtering)
- `support_messages.chat_id`
- `support_messages.(chat_id, created_at)` (composite, for ordering)

**Model relationships:**
```
User has_one SupportChat
SupportChat belongs_to User
SupportChat has_many SupportMessages
SupportMessage belongs_to SupportChat
```

**Model methods to implement:**

Chat model:
```pseudo
function touch_last_message()
  update last_message_at = now()

function unread_for_admin?()
  return exists message where sender_type = 'user'
    and created_at > admin_viewed_at

function mark_viewed_by_admin()
  update admin_viewed_at = now()

function archive()
  update archived_at = now()

function unarchive()
  update archived_at = null

function archived?()
  return archived_at != null
```

Message model:
```pseudo
after_create:
  chat.touch_last_message()
  if sender_type == 'user' and chat.archived?:
    chat.unarchive()  // Auto-reactivate on new user message

after_create_commit:
  broadcast_to_chat_channel(message_data)
  if sender_type == 'user':
    broadcast_to_admin_notification_channel(message_data, chat_info)
  if sender_type == 'admin':
    schedule_email_notification(delay: 5.minutes)
```

### Step 2: API Endpoints

**User-facing:**
```
GET  /support_chat       - Get or create user's chat with messages
PATCH /support_chat/mark_read - Mark admin messages as read
```

**Admin-facing:**
```
GET  /admin/chats              - List chats (query: archived=true/false)
GET  /admin/chats/:id          - Get chat with messages
POST /admin/chats/:id/archive  - Archive chat
POST /admin/chats/:id/unarchive - Restore chat
```

**Controller logic:**

User GET /support_chat:
```pseudo
function show()
  chat = current_user.support_chat || create_chat(user: current_user)
  return {
    id: chat.id,
    messages: chat.messages.map(m => serialize_message(m))
  }
```

Admin GET /admin/chats:
```pseudo
function index()
  chats = SupportChat
    .where(archived_at: params.archived ? not_null : null)
    .includes(:user, :messages)
    .order(last_message_at: desc)

  return chats.map(c => {
    id: c.id,
    user_email: c.user.email,
    last_message_preview: c.messages.last?.content.truncate(100),
    last_message_sender: c.messages.last?.sender_type,
    message_count: c.messages.
