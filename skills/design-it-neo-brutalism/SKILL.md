---
name: neo-brutalism
description: Web and App implementation guide for Neo-Brutalism. Trigger when user wants thick borders, hard shadows, bright colors, and a playful yet structured look. 
category: Creative & Media
source: antigravity
tags: [react, ai, design, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/neo-brutalism
---


# Neo-Brutalism

> "Brutalism, but make it pop. Hard lines, stark shadows, and vibrant, unashamed colors."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Hard Drop Shadows**: Solid black shadows with no blur. Usually offset by a few pixels down and to the right.
2. **Thick Outlines**: Everything has a heavy, solid black border (usually 2px-4px).
3. **Flat, High-Contrast Colors**: Bright, saturated pastels or primary colors contrasting against pure white or black.

## Visual DNA
- **Colors**: Start with an off-white background (like `#FDF8F5`), add stark black borders `#000000`, and use saturated accents like lemon yellow, bright cyan, or coral.
- **Typography**: Very bold, geometric sans-serifs (e.g., `Space Grotesk`, `Archivo Black`, `Inter Black`).
- **Shapes**: Sharp rectangles or completely rounded pill shapes, but always with a heavy stroke.

## Web Implementation
- The defining feature is the `box-shadow` with `0` blur.
- **CSS Example**:
```css
:root {
  --neo-border: 3px solid #000000;
  --neo-shadow: 6px 6px 0px #000000;
  --neo-bg: #F4F4F0;
  --neo-accent: #FF3366;
}

body {
  background-color: var(--neo-bg);
  font-family: 'Space Grotesk', sans-serif;
}

.neo-card {
  background-color: #ffffff;
  border: var(--neo-border);
  box-shadow: var(--neo-shadow);
  border-radius: 8px; /* Optional, sharp is fine too */
  padding: 32px;
  transition: transform 0.1s, box-shadow 0.1s;
}

.neo-btn {
  background-color: var(--neo-accent);
  color: #000;
  font-weight: 800;
  text-transform: uppercase;
  border: var(--neo-border);
  box-shadow: 4px 4px 0px #000000;
  padding: 16px 32px;
  cursor: pointer;
  transition: all 0.1s ease;
}

.neo-btn:active {
  /* The "press" effect is removing the shadow and moving it down */
  transform: translate(4px, 4px);
  box-shadow: 0px 0px 0px #000000;
}
```

## App Implementation

### SwiftUI
```swift
struct NeoCard: View {
    @State private var isPressed = false
    let neoBorder: CGFloat = 3
    let neoShadow: CGFloat = 6
    
    var body: some View {
        Button(action: {}) {
            VStack(alignment: .leading, spacing: 16) {
                Text("NEO-BRUTALISM")
                    .font(.system(size: 24, weight: .black, design: .default))
                    .foregroundColor(.black)
                Text("Stark shadows, bright colors.")
                    .font(.system(size: 16, weight: .bold))
                    .foregroundColor(.black)
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(red: 1.0, green: 0.2, blue: 0.4)) // Bright Coral
            // Neo-brutalist solid outline
            .overlay(
                Rectangle()
                    .stroke(Color.black, lineWidth: neoBorder)
            )
        }
        .buttonStyle(.plain)
        // Hard drop shadow (0 blur)
        .shadow(color: .black, radius: 0, x: isPressed ? 0 : neoShadow, y: isPressed ? 0 : neoShadow)
        // Translate the button physically when pressed to cover the shadow
        .offset(x: isPressed ? neoShadow : 0, y: isPressed ? neoShadow : 0)
        .simultaneousGesture(
            DragGesture(minimumDistance: 0)
                .onChanged { _ in isPressed = true }
                .onEnded { _ in isPressed = false }
        )
        // Instant pop, no smooth animation
        .animation(.none, value: isPressed)
    }
}
```
- `.shadow(radius: 0)` is the secret. Set an offset (e.g. `x: 6, y: 6`).
- For interactions, remove the shadow and translate the element by the same offset amounts using `.offset()`.
- Ensure `.animation(.none)` — Neo-brutalism interactions should be instant, snapping like physical switches.

### Flutter
```dart
class NeoCard extends StatefulWidget {
  @override
  State<NeoCard> createState() => _NeoCardState();
}

class _NeoCardState extends State<NeoCard> {
  bool _isPressed = false;
  final double neoOffset = 6.0;

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTapDown: (_) => setState(() => _isPressed = true),
      onTapUp: (_) => setState(() => _isPressed = false),
      onTapCancel: () => setState(() => _isPressed = false),
      child: Transform.translate(
        // Move the container when pressed
        offset: Offset(_isPressed ? neoOffset : 0, _isPressed ? neoOffset : 0),
        child: Container(
          padding: const EdgeInsets.all(24),
          decoration: BoxDecoration(
            color: const Color(0xFFFF3366), // Bright coral
            border: Border.all(color: Colors.black, width: 3),
            // Sharp shadow disappears on press
            boxShadow: _isPressed ? [] : [
              BoxShadow(
                color: Colors.black,
                blurRadius: 0,     // Critical: 0 blur
                spreadRadius: 0,
                off
