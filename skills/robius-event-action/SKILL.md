---
name: robius-event-action
description: CRITICAL: Use for Robius event and action patterns. Triggers on: custom action, MatchEvent, post_action, cx.widget_action, handle_actions, DefaultNone, widget action, event handling, 事件处理, 自
category: AI & Agents
source: antigravity
tags: [react, ai, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/robius-event-action
---


# Robius Event and Action Patterns Skill

Best practices for event handling and action patterns in Makepad applications based on Robrix and Moly codebases.

**Source codebases:**
- **Robrix**: Matrix chat client - MessageAction, RoomsListAction, AppStateAction
- **Moly**: AI chat application - StoreAction, ChatAction, NavigationAction, Timer patterns

## Triggers

Use this skill when:
- Implementing custom actions in Makepad
- Handling events in widgets
- Centralizing action handling in App
- Widget-to-widget communication
- Keywords: makepad action, makepad event, widget action, handle_actions, cx.widget_action

## Custom Action Pattern

### Defining Domain-Specific Actions

```rust
use makepad_widgets::*;

/// Actions emitted by the Message widget
#[derive(Clone, DefaultNone, Debug)]
pub enum MessageAction {
    /// User wants to react to a message
    React { details: MessageDetails, reaction: String },
    /// User wants to reply to a message
    Reply(MessageDetails),
    /// User wants to edit a message
    Edit(MessageDetails),
    /// User wants to delete a message
    Delete(MessageDetails),
    /// User requested to open context menu
    OpenContextMenu { details: MessageDetails, abs_pos: DVec2 },
    /// Required default variant
    None,
}

/// Data associated with a message action
#[derive(Clone, Debug)]
pub struct MessageDetails {
    pub room_id: OwnedRoomId,
    pub event_id: OwnedEventId,
    pub content: String,
    pub sender_id: OwnedUserId,
}
```

### Emitting Actions from Widgets

```rust
impl Widget for Message {
    fn handle_event(&mut self, cx: &mut Cx, event: &Event, scope: &mut Scope) {
        self.view.handle_event(cx, event, scope);

        let area = self.view.area();
        match event.hits(cx, area) {
            Hit::FingerDown(_fe) => {
                cx.set_key_focus(area);
            }
            Hit::FingerUp(fe) => {
                if fe.is_over && fe.is_primary_hit() && fe.was_tap() {
                    // Emit widget action
                    cx.widget_action(
                        self.widget_uid(),
                        &scope.path,
                        MessageAction::Reply(self.get_details()),
                    );
                }
            }
            Hit::FingerLongPress(lpe) => {
                cx.widget_action(
                    self.widget_uid(),
                    &scope.path,
                    MessageAction::OpenContextMenu {
                        details: self.get_details(),
                        abs_pos: lpe.abs,
                    },
                );
            }
            _ => {}
        }
    }
}
```

## Centralized Action Handling in App

### Using MatchEvent Trait

```rust
impl MatchEvent for App {
    fn handle_startup(&mut self, cx: &mut Cx) {
        // Called once on app startup
        self.initialize(cx);
    }

    fn handle_actions(&mut self, cx: &mut Cx, actions: &Actions) {
        for action in actions {
            // Pattern 1: Direct downcast for non-widget actions
            if let Some(action) = action.downcast_ref::<LoginAction>() {
                match action {
                    LoginAction::LoginSuccess => {
                        self.app_state.logged_in = true;
                        self.update_ui_visibility(cx);
                    }
                    LoginAction::LoginFailure(error) => {
                        self.show_error(cx, error);
                    }
                }
                continue;  // Action handled
            }

            // Pattern 2: Widget action cast
            if let MessageAction::OpenContextMenu { details, abs_pos } =
                action.as_widget_action().cast()
            {
                self.show_context_menu(cx, details, abs_pos);
                continue;
            }

            // Pattern 3: Match on downcast_ref for enum variants
            match action.downcast_ref() {
                Some(AppStateAction::RoomFocused(room)) => {
                    self.app_state.selected_room = Some(room.clone());
                    continue;
                }
                Some(AppStateAction::NavigateToRoom { destination }) => {
                    self.navigate_to_room(cx, destination);
                    continue;
                }
                _ => {}
            }

            // Pattern 4: Modal actions
            match action.downcast_ref() {
                Some(ModalAction::Open { kind }) => {
                    self.ui.modal(ids!(my_modal)).open(cx);
                    continue;
                }
                Some(ModalAction::Close { was_internal }) => {
                    if *was_internal {
                        self.ui.modal(ids!(my_modal)).close(cx);
                    }
                    continue;
                }
                _ => {}
            }
        }
    }
}

impl AppMain for App {
    fn handle_event(&mut self, cx: &mut Cx, event: &Event) {
        // Forward to MatchEvent
        self.match_even
