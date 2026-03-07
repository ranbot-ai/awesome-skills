---
name: robius-matrix-integration
description: CRITICAL: Use for Matrix SDK integration with Makepad. Triggers on: Matrix SDK, sliding sync, MatrixRequest, timeline, matrix-sdk, matrix client, robrix, matrix room, Matrix 集成, 聊天客户端 
category: AI & Agents
source: antigravity
tags: [react, api, mcp, ai, llm, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/robius-matrix-integration
---


# Robius Matrix SDK Integration Skill

Best practices for integrating external APIs with Makepad applications based on Robrix and Moly codebases.

**Source codebases:**
- **Robrix**: Matrix SDK integration - sliding sync, timeline subscriptions, real-time updates
- **Moly**: OpenAI/LLM API integration - SSE streaming, MCP protocol, multi-provider support

## Triggers

Use this skill when:
- Integrating Matrix SDK with Makepad
- Building a Matrix client with Makepad
- Implementing Matrix features (rooms, timelines, messages)
- Handling Matrix SDK async operations in UI
- Keywords: matrix-sdk, matrix client, robrix, matrix timeline, matrix room, sliding sync

## Overview

Robrix uses the `matrix-sdk` and `matrix-sdk-ui` crates to connect to Matrix homeservers. The key architectural decisions:

1. **Sliding Sync**: Uses native sliding sync for efficient room list updates
2. **Separate Runtime**: Tokio runtime runs Matrix operations, Makepad handles UI
3. **Request/Response Pattern**: UI sends requests, receives actions/updates back
4. **Per-Room Background Tasks**: Each room has dedicated timeline subscriber task

## MatrixRequest Pattern

### Request Enum Definition

```rust
/// All async requests that can be made to the Matrix worker task
pub enum MatrixRequest {
    /// Login requests
    Login(LoginRequest),
    Logout { is_desktop: bool },

    /// Timeline operations
    PaginateRoomTimeline {
        room_id: OwnedRoomId,
        num_events: u16,
        direction: PaginationDirection,
    },
    SendMessage {
        room_id: OwnedRoomId,
        message: RoomMessageEventContent,
        replied_to: Option<Reply>,
    },
    EditMessage {
        room_id: OwnedRoomId,
        timeline_event_item_id: TimelineEventItemId,
        edited_content: EditedContent,
    },
    RedactMessage {
        room_id: OwnedRoomId,
        timeline_event_id: TimelineEventItemId,
        reason: Option<String>,
    },

    /// Room operations
    JoinRoom { room_id: OwnedRoomId },
    LeaveRoom { room_id: OwnedRoomId },
    GetRoomMembers {
        room_id: OwnedRoomId,
        memberships: RoomMemberships,
        local_only: bool,
    },

    /// User operations
    GetUserProfile {
        user_id: OwnedUserId,
        room_id: Option<OwnedRoomId>,
        local_only: bool,
    },
    IgnoreUser {
        ignore: bool,
        room_member: RoomMember,
        room_id: OwnedRoomId,
    },

    /// Media operations
    FetchAvatar {
        mxc_uri: OwnedMxcUri,
        on_fetched: fn(AvatarUpdate),
    },
    FetchMedia {
        media_request: MediaRequestParameters,
        on_fetched: OnMediaFetchedFn,
        destination: MediaCacheEntryRef,
        update_sender: Option<crossbeam_channel::Sender<TimelineUpdate>>,
    },

    /// Typing/read indicators
    SendTypingNotice { room_id: OwnedRoomId, typing: bool },
    ReadReceipt { room_id: OwnedRoomId, event_id: OwnedEventId },
    FullyReadReceipt { room_id: OwnedRoomId, event_id: OwnedEventId },

    /// Reactions
    ToggleReaction {
        room_id: OwnedRoomId,
        timeline_event_id: TimelineEventItemId,
        reaction: String,
    },

    /// Subscriptions
    SubscribeToTypingNotices { room_id: OwnedRoomId, subscribe: bool },
    SubscribeToPinnedEvents { room_id: OwnedRoomId, subscribe: bool },
}
```

### Submit Pattern

```rust
static REQUEST_SENDER: Mutex<Option<UnboundedSender<MatrixRequest>>> = Mutex::new(None);

/// Submit request from UI thread to async runtime
pub fn submit_async_request(req: MatrixRequest) {
    if let Some(sender) = REQUEST_SENDER.lock().unwrap().as_ref() {
        sender.send(req).expect("BUG: matrix worker task receiver died!");
    }
}

// Usage in UI
submit_async_request(MatrixRequest::SendMessage {
    room_id: room_id.clone(),
    message: RoomMessageEventContent::text_plain(&text),
    replied_to: self.reply_to.take(),
});
```

## Worker Task Handler

```rust
async fn matrix_worker_task(
    mut request_receiver: UnboundedReceiver<MatrixRequest>,
    login_sender: Sender<LoginRequest>,
) -> Result<()> {
    while let Some(request) = request_receiver.recv().await {
        match request {
            MatrixRequest::PaginateRoomTimeline { room_id, num_events, direction } => {
                let (timeline, sender) = {
                    let rooms = ALL_JOINED_ROOMS.lock().unwrap();
                    let Some(room_info) = rooms.get(&room_id) else {
                        continue;  // Room not ready yet
                    };
                    (room_info.timeline.clone(), room_info.update_sender.clone())
                };

                // Spawn dedicated task for this operation
                Handle::current().spawn(async move {
                    // Notify UI pagination is starting
                    sender.send(TimelineUpdate::PaginationRunning(direction)).unwrap();
                    SignalToUI::set_ui_signal();

                    // Perform pagination
                    let res = if direction == Pagin
