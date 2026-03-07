---
name: robius-widget-patterns
description: CRITICAL: Use for Robius widget patterns. Triggers on: apply_over, TextOrImage, modal, 可复用, 模态, collapsible, drag drop, reusable widget, widget design, pageflip, 组件设计, 组件模式 
category: AI & Agents
source: antigravity
tags: [api, ai, template, design, image, aws, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/robius-widget-patterns
---


# Robius Widget Patterns Skill

Best practices for designing reusable Makepad widgets based on Robrix and Moly codebase patterns.

**Source codebases:**
- **Robrix**: Matrix chat client - Avatar, RoomsList, RoomScreen widgets
- **Moly**: AI chat application - Slot, ChatLine, PromptInput, AdaptiveView widgets

## Triggers

Use this skill when:
- Creating reusable Makepad widgets
- Designing widget component APIs
- Implementing text/image toggle patterns
- Dynamic styling in Makepad
- Keywords: robrix widget, makepad component, reusable widget, widget design pattern

## Production Patterns

For production-ready widget patterns, see the `_base/` directory:

| Pattern | Description |
|---------|-------------|
| 01-widget-extension | Add helper methods to widget references |
| 02-modal-overlay | Popups, dialogs using DrawList2d overlay |
| 03-collapsible | Expandable/collapsible sections |
| 04-list-template | Dynamic lists with LivePtr templates |
| 05-lru-view-cache | Memory-efficient view caching |
| 14-callout-tooltip | Tooltips with arrow positioning |
| 20-redraw-optimization | Efficient redraw patterns |
| 15-dock-studio-layout | IDE-style resizable panels |
| 16-hover-effect | Hover effects with instance variables |
| 17-row-based-grid-layout | Dynamic grid layouts |
| 18-drag-drop-reorder | Drag-and-drop widget reordering |
| 19-pageflip-optimization | PageFlip 切换优化，即刻销毁/缓存模式 |
| 21-collapsible-row-portal-list | Auto-grouping consecutive items in portal lists with FoldHeader |
| 22-dropdown-overlay | Dropdown popups using DrawList2d overlay (no layout push) |

## Standard Widget Structure

```rust
use makepad_widgets::*;

live_design! {
    use link::theme::*;
    use link::widgets::*;

    pub MyWidget = {{MyWidget}} {
        width: Fill, height: Fit,
        flow: Down,

        // Child widgets defined in DSL
        inner_view = <View> {
            // ...
        }
    }
}

#[derive(Live, LiveHook, Widget)]
pub struct MyWidget {
    #[deref] view: View,              // Delegate to inner View

    #[live] some_property: f64,       // DSL-configurable property
    #[live(100.0)] default_val: f64,  // With default value

    #[rust] internal_state: State,    // Rust-only state (not in DSL)

    #[animator] animator: Animator,   // For animations
}

impl Widget for MyWidget {
    fn handle_event(&mut self, cx: &mut Cx, event: &Event, scope: &mut Scope) {
        self.view.handle_event(cx, event, scope);
        // Custom event handling...
    }

    fn draw_walk(&mut self, cx: &mut Cx2d, scope: &mut Scope, walk: Walk) -> DrawStep {
        self.view.draw_walk(cx, scope, walk)
    }
}
```

## Text/Image Toggle Pattern

A common pattern for widgets that show either text or an image (like avatars):

```rust
live_design! {
    pub Avatar = {{Avatar}} {
        width: 36.0, height: 36.0,
        align: { x: 0.5, y: 0.5 }
        flow: Overlay,  // Stack views on top of each other

        text_view = <View> {
            visible: true,  // Default visible
            show_bg: true,
            draw_bg: {
                uniform background_color: #888888
                fn pixel(self) -> vec4 {
                    let sdf = Sdf2d::viewport(self.pos * self.rect_size);
                    let c = self.rect_size * 0.5;
                    sdf.circle(c.x, c.x, c.x)
                    sdf.fill_keep(self.background_color);
                    return sdf.result
                }
            }
            text = <Label> {
                text: "?"
            }
        }

        img_view = <View> {
            visible: false,  // Hidden by default
            img = <Image> {
                fit: Stretch,
                width: Fill, height: Fill,
            }
        }
    }
}

#[derive(LiveHook, Live, Widget)]
pub struct Avatar {
    #[deref] view: View,
    #[rust] info: Option<UserInfo>,
}

impl Avatar {
    /// Show text content, hiding the image
    pub fn show_text<T: AsRef<str>>(
        &mut self,
        cx: &mut Cx,
        bg_color: Option<Vec4>,
        info: Option<AvatarTextInfo>,
        username: T,
    ) {
        self.info = info.map(|i| i.into());

        // Get first character
        let first_char = utils::first_letter(username.as_ref())
            .unwrap_or("?").to_uppercase();
        self.label(ids!(text_view.text)).set_text(cx, &first_char);

        // Toggle visibility
        self.view(ids!(text_view)).set_visible(cx, true);
        self.view(ids!(img_view)).set_visible(cx, false);

        // Apply optional background color
        if let Some(color) = bg_color {
            self.view(ids!(text_view)).apply_over(cx, live! {
                draw_bg: { background_color: (color) }
            });
        }
    }

    /// Show image content, hiding the text
    pub fn show_image<F, E>(
        &mut self,
        cx: &mut Cx,
        info: Option<AvatarImageInfo>,
        image_set_fn: F,
    ) -> Result<(), E>
    where
        F: FnOnce(&mut Cx, ImageRef) -> Result<(), E>
    {
   
