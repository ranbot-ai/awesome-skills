---
name: robius-state-management
description: CRITICAL: Use for Robius state management patterns. Triggers on: AppState, persistence, theme switch, 状态管理, Scope::with_data, save state, load state, serde, 状态持久化, 主题切换 
category: AI & Agents
source: antigravity
tags: [ai, design, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/robius-state-management
---


# Robius State Management Skill

Best practices for state management and persistence in Makepad applications based on Robrix and Moly codebases.

**Source codebases:**
- **Robrix**: Matrix chat client - AppState, SelectedRoom, persistence via serde
- **Moly**: AI chat application - Central Store pattern, async initialization, Preferences

## Triggers

Use this skill when:
- Designing application state structure
- Implementing state persistence
- Passing state through widget tree
- Managing UI state across sessions
- Keywords: app state, makepad state, persistence, Scope::with_data, save state, load state

## Production Patterns

For production-ready state management patterns, see the `_base/` directory:

| Pattern | Description |
|---------|-------------|
| 06-global-registry | Global widget registry with Cx::set_global |
| 07-radio-navigation | Tab-style navigation with radio buttons |
| 10-state-machine | Enum-based state machine widgets |
| 11-theme-switching | Multi-theme support with apply_over |
| 12-local-persistence | Save/load user preferences |

## AppState Structure

### Core State Definition

```rust
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use matrix_sdk::ruma::OwnedRoomId;

/// App-wide state that is stored persistently across multiple app runs
/// and shared/updated across various parts of the app.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct AppState {
    /// The currently-selected room
    pub selected_room: Option<SelectedRoom>,

    /// Saved UI layout state for main view
    pub saved_layout_state: SavedLayoutState,

    /// Per-item saved states (e.g., per-space dock layouts)
    pub saved_state_per_item: HashMap<OwnedRoomId, SavedLayoutState>,

    /// Whether a user is currently logged in
    #[serde(skip)]  // Don't persist login state
    pub logged_in: bool,
}

/// Represents a currently selected item
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SelectedRoom {
    JoinedRoom { room_name_id: RoomNameId },
    InvitedRoom { room_name_id: RoomNameId },
    Space { space_name_id: RoomNameId },
}

impl SelectedRoom {
    pub fn room_id(&self) -> &OwnedRoomId {
        match self {
            Self::JoinedRoom { room_name_id } => room_name_id.room_id(),
            Self::InvitedRoom { room_name_id } => room_name_id.room_id(),
            Self::Space { space_name_id } => space_name_id.room_id(),
        }
    }

    /// Upgrade from invited to joined state
    pub fn upgrade_invite_to_joined(&mut self, room_id: &RoomId) -> bool {
        match self {
            Self::InvitedRoom { room_name_id } if room_name_id.room_id() == room_id => {
                let name = room_name_id.clone();
                *self = Self::JoinedRoom { room_name_id: name };
                true
            }
            _ => false,
        }
    }
}

// Equality based on room_id only
impl PartialEq for SelectedRoom {
    fn eq(&self, other: &Self) -> bool {
        self.room_id() == other.room_id()
    }
}
impl Eq for SelectedRoom {}
```

### Layout/Dock State Persistence

```rust
/// A snapshot of UI layout state for restoration
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct SavedLayoutState {
    /// All items contained in the layout, keyed by ID
    pub layout_items: HashMap<LiveIdSerde, LayoutItemSerde>,

    /// Items currently open, keyed by ID
    pub open_items: HashMap<LiveIdSerde, SelectedRoom>,

    /// Order items were opened (chronological)
    pub item_order: Vec<SelectedRoom>,

    /// Currently selected item when state was saved
    pub selected_item: Option<SelectedRoom>,
}

/// Serializable wrapper for LiveId
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct LiveIdSerde(pub u64);

impl From<LiveId> for LiveIdSerde {
    fn from(id: LiveId) -> Self {
        Self(id.0)
    }
}

impl From<LiveIdSerde> for LiveId {
    fn from(s: LiveIdSerde) -> Self {
        LiveId(s.0)
    }
}
```

## State Propagation via Scope

### Passing State Through Widget Tree

```rust
impl AppMain for App {
    fn handle_event(&mut self, cx: &mut Cx, event: &Event) {
        // Forward to MatchEvent
        self.match_event(cx, event);

        // Create Scope with AppState data
        let scope = &mut Scope::with_data(&mut self.app_state);

        // Pass to widget tree - all children can access AppState
        self.ui.handle_event(cx, event, scope);
    }
}
```

### Accessing State in Child Widgets

```rust
impl Widget for RoomScreen {
    fn handle_event(&mut self, cx: &mut Cx, event: &Event, scope: &mut Scope) {
        // Access AppState from scope
        if let Some(app_state) = scope.data.get::<AppState>() {
            if let Some(selected) = &app_state.selected_room {
                self.update_for_room(cx, selected);
            }
        }

        self.view.handle_event(cx, event, scope);
    }
}
```

### Modifying State

```rust
impl Widget for RoomsList {
    fn handle_event(&mut self, cx:
