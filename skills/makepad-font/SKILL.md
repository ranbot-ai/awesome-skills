---
name: makepad-font
description: CRITICAL: Use for Makepad font and text rendering. Triggers on: makepad font, makepad text, makepad glyph, makepad typography, font atlas, text layout, font family, font size, text shaping, makepad �
category: Document Processing
source: antigravity
tags: [api, claude, ai, design, document, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/makepad-font
---


# Makepad Font Skill

> **Version:** makepad-widgets (dev branch) | **Last Updated:** 2026-01-19
>
> Check for updates: https://crates.io/crates/makepad-widgets

You are an expert at Makepad text and font rendering. Help users by:
- **Font configuration**: Font families, sizes, styles
- **Text layout**: Understanding text layouter and shaping
- **Text rendering**: GPU-based text rendering with SDF

## Documentation

Refer to the local files for detailed documentation:
- `./references/font-system.md` - Font module structure and APIs

## IMPORTANT: Documentation Completeness Check

**Before answering questions, Claude MUST:**

1. Read the relevant reference file(s) listed above
2. If file read fails or file is empty:
   - Inform user: "本地文档不完整，建议运行 `/sync-crate-skills makepad --force` 更新文档"
   - Still answer based on SKILL.md patterns + built-in knowledge
3. If reference file exists, incorporate its content into the answer

## Text Module Structure

```
draw/src/text/
├── font.rs           # Font handle and metrics
├── font_atlas.rs     # GPU texture atlas for glyphs
├── font_face.rs      # Font face data
├── font_family.rs    # Font family management
├── fonts.rs          # Built-in fonts
├── glyph_outline.rs  # Glyph vector outlines
├── glyph_raster_image.rs # Rasterized glyph images
├── layouter.rs       # Text layout engine
├── rasterizer.rs     # Glyph rasterization
├── sdfer.rs          # Signed distance field generator
├── selection.rs      # Text selection/cursor
├── shaper.rs         # Text shaping (harfbuzz)
```

## Using Fonts in DSL

### Text Style

```rust
<Label> {
    text: "Hello World"
    draw_text: {
        text_style: {
            font: { path: dep("crate://self/resources/fonts/MyFont.ttf") }
            font_size: 16.0
            line_spacing: 1.5
            letter_spacing: 0.0
        }
        color: #FFFFFF
    }
}
```

### Theme Fonts

```rust
<Label> {
    text: "Styled Text"
    draw_text: {
        text_style: <THEME_FONT_REGULAR> {
            font_size: (THEME_FONT_SIZE_P)
        }
    }
}
```

## Font Definition in DSL

```rust
live_design! {
    // Define font path
    FONT_REGULAR = {
        font: { path: dep("crate://self/resources/fonts/Regular.ttf") }
    }

    FONT_BOLD = {
        font: { path: dep("crate://self/resources/fonts/Bold.ttf") }
    }

    // Use in widget
    <Label> {
        draw_text: {
            text_style: <FONT_REGULAR> {
                font_size: 14.0
            }
        }
    }
}
```

## Layouter API

```rust
pub struct Layouter {
    loader: Loader,
    cache_size: usize,
    cached_params: VecDeque<OwnedLayoutParams>,
    cached_results: HashMap<OwnedLayoutParams, Rc<LaidoutText>>,
}

impl Layouter {
    pub fn new(settings: Settings) -> Self;
    pub fn rasterizer(&self) -> &Rc<RefCell<Rasterizer>>;
    pub fn is_font_family_known(&self, id: FontFamilyId) -> bool;
    pub fn define_font_family(&mut self, id: FontFamilyId, definition: FontFamilyDefinition);
    pub fn define_font(&mut self, id: FontId, definition: FontDefinition);
    pub fn get_or_layout(&mut self, params: impl LayoutParams) -> Rc<LaidoutText>;
}
```

## Layout Parameters

```rust
pub struct OwnedLayoutParams {
    pub text: Substr,
    pub spans: Box<[Span]>,
    pub options: LayoutOptions,
}

pub struct Span {
    pub style: Style,
    pub len: usize,
}

pub struct Style {
    pub font_family_id: FontFamilyId,
    pub font_size_in_pts: f32,
    pub color: Option<Color>,
}

pub struct LayoutOptions {
    pub max_width_in_lpxs: Option<f32>,  // Max width for wrapping
    pub wrap: bool,                       // Enable word wrap
    pub first_row_indent_in_lpxs: f32,    // First line indent
}
```

## Rasterizer Settings

```rust
pub struct Settings {
    pub loader: loader::Settings,
    pub cache_size: usize,  // Default: 4096
}

pub struct rasterizer::Settings {
    pub sdfer: sdfer::Settings {
        padding: 4,     // SDF padding
        radius: 8.0,    // SDF radius
        cutoff: 0.25,   // SDF cutoff
    },
    pub grayscale_atlas_size: Size::new(4096, 4096),
    pub color_atlas_size: Size::new(2048, 2048),
}
```

## DrawText Widget

```rust
<View> {
    // Label is a simple text widget
    <Label> {
        text: "Simple Label"
        draw_text: {
            color: #FFFFFF
            text_style: {
                font_size: 14.0
            }
        }
    }

    // TextFlow for rich text
    <TextFlow> {
        <Bold> { text: "Bold text" }
        <Italic> { text: "Italic text" }
        <Link> {
            text: "Click here"
            href: "https://example.com"
        }
    }
}
```

## Text Properties

| Property | Type | Description |
|----------|------|-------------|
| `text` | String | Text content |
| `font` | Font | Font resource |
| `font_size` | f64 | Size in points |
| `line_spacing` | f64 | Line height multiplier |
| `letter_spacing` | f64 | Character spacing |
| `color` | Vec4 | Text color |
| `brightness` | f64 | Text brightness |
| `curv
