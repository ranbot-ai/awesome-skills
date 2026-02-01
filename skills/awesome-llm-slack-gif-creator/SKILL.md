---
name: slack-gif-creator
description: Toolkit for creating animated GIFs optimized for Slack, with validators for size constraints and composable animation primitives. This skill applies when users request animated GIFs or emoji animation
category: Creative & Media
source: awesome-llm
tags: [python, react, ai, template, design, slack, image, gif, creator]
url: https://github.com/Prat011/awesome-llm-skills/tree/master/slack-gif-creator
---


# Slack GIF Creator - Flexible Toolkit

A toolkit for creating animated GIFs optimized for Slack. Provides validators for Slack's constraints, composable animation primitives, and optional helper utilities. **Apply these tools however needed to achieve the creative vision.**

## Slack's Requirements

Slack has specific requirements for GIFs based on their use:

**Message GIFs:**
- Max size: ~2MB
- Optimal dimensions: 480x480
- Typical FPS: 15-20
- Color limit: 128-256
- Duration: 2-5s

**Emoji GIFs:**
- Max size: 64KB (strict limit)
- Optimal dimensions: 128x128
- Typical FPS: 10-12
- Color limit: 32-48
- Duration: 1-2s

**Emoji GIFs are challenging** - the 64KB limit is strict. Strategies that help:
- Limit to 10-15 frames total
- Use 32-48 colors maximum
- Keep designs simple
- Avoid gradients
- Validate file size frequently

## Toolkit Structure

This skill provides three types of tools:

1. **Validators** - Check if a GIF meets Slack's requirements
2. **Animation Primitives** - Composable building blocks for motion (shake, bounce, move, kaleidoscope)
3. **Helper Utilities** - Optional functions for common needs (text, colors, effects)

**Complete creative freedom is available in how these tools are applied.**

## Core Validators

To ensure a GIF meets Slack's constraints, use these validators:

```python
from core.gif_builder import GIFBuilder

# After creating your GIF, check if it meets requirements
builder = GIFBuilder(width=128, height=128, fps=10)
# ... add your frames however you want ...

# Save and check size
info = builder.save('emoji.gif', num_colors=48, optimize_for_emoji=True)

# The save method automatically warns if file exceeds limits
# info dict contains: size_kb, size_mb, frame_count, duration_seconds
```

**File size validator**:
```python
from core.validators import check_slack_size

# Check if GIF meets size limits
passes, info = check_slack_size('emoji.gif', is_emoji=True)
# Returns: (True/False, dict with size details)
```

**Dimension validator**:
```python
from core.validators import validate_dimensions

# Check dimensions
passes, info = validate_dimensions(128, 128, is_emoji=True)
# Returns: (True/False, dict with dimension details)
```

**Complete validation**:
```python
from core.validators import validate_gif, is_slack_ready

# Run all validations
all_pass, results = validate_gif('emoji.gif', is_emoji=True)

# Or quick check
if is_slack_ready('emoji.gif', is_emoji=True):
    print("Ready to upload!")
```

## Animation Primitives

These are composable building blocks for motion. Apply these to any object in any combination:

### Shake
```python
from templates.shake import create_shake_animation

# Shake an emoji
frames = create_shake_animation(
    object_type='emoji',
    object_data={'emoji': '😱', 'size': 80},
    num_frames=20,
    shake_intensity=15,
    direction='both'  # or 'horizontal', 'vertical'
)
```

### Bounce
```python
from templates.bounce import create_bounce_animation

# Bounce a circle
frames = create_bounce_animation(
    object_type='circle',
    object_data={'radius': 40, 'color': (255, 100, 100)},
    num_frames=30,
    bounce_height=150
)
```

### Spin / Rotate
```python
from templates.spin import create_spin_animation, create_loading_spinner

# Clockwise spin
frames = create_spin_animation(
    object_type='emoji',
    object_data={'emoji': '🔄', 'size': 100},
    rotation_type='clockwise',
    full_rotations=2
)

# Wobble rotation
frames = create_spin_animation(rotation_type='wobble', full_rotations=3)

# Loading spinner
frames = create_loading_spinner(spinner_type='dots')
```

### Pulse / Heartbeat
```python
from templates.pulse import create_pulse_animation, create_attention_pulse

# Smooth pulse
frames = create_pulse_animation(
    object_data={'emoji': '❤️', 'size': 100},
    pulse_type='smooth',
    scale_range=(0.8, 1.2)
)

# Heartbeat (double-pump)
frames = create_pulse_animation(pulse_type='heartbeat')

# Attention pulse for emoji GIFs
frames = create_attention_pulse(emoji='⚠️', num_frames=20)
```

### Fade
```python
from templates.fade import create_fade_animation, create_crossfade

# Fade in
frames = create_fade_animation(fade_type='in')

# Fade out
frames = create_fade_animation(fade_type='out')

# Crossfade between two emojis
frames = create_crossfade(
    object1_data={'emoji': '😊', 'size': 100},
    object2_data={'emoji': '😂', 'size': 100}
)
```

### Zoom
```python
from templates.zoom import create_zoom_animation, create_explosion_zoom

# Zoom in dramatically
frames = create_zoom_animation(
    zoom_type='in',
    scale_range=(0.1, 2.0),
    add_motion_blur=True
)

# Zoom out
frames = create_zoom_animation(zoom_type='out')

# Explosion zoom
frames = create_explosion_zoom(emoji='💥')
```

### Explode / Shatter
```python
from templates.explode import create_explode_animation, create_particle_burst

# Burst explosion
frames = create_explode_animation(
    explode_type='burst',
    num_pieces=25
)

# Shatter effect
frames = create_explode
