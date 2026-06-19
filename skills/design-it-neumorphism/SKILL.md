---
name: neumorphism
description: Web and App implementation guide for Neumorphism (Soft UI). Trigger when user wants soft shadows, extruded appearance, and light source simulation. 
category: Creative & Media
source: antigravity
tags: [react, ai, design, image, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/neumorphism
---


# Neumorphism (Soft UI)

> "Elements extruded from the background material itself, shaped by a singular, persistent light source."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Unified Surface Color**: The background and the elements MUST share the exact same base color.
2. **Dual Shadows**: Elements are shaped by two shadows: a light shadow (highlight) on the side facing the light source, and a dark shadow on the opposite side.
3. **No Borders**: The shape is entirely defined by the shadows.

## Visual DNA
- **Colors**: Works best with mid-tone neutrals. **Desert Mirage**, **Earth-Grounded Elegance**, or **Sophisticated Neutral** are perfect. Avoid pure white or pure black (shadows/highlights won't show).
- **Typography**: Soft, rounded sans-serifs (e.g., `Nunito`, `Quicksand`).
- **Shapes**: Pill shapes, rounded rectangles. Sharp corners break the illusion of extruded material.

## Web Implementation
- The magic is entirely in `box-shadow` manipulating light and dark variants of the base color.
- **CSS Example**:
```css
:root {
  --base-color: #E6E2DD; /* From Sophisticated Neutral */
  --highlight: #ffffff;
  --shadow: #c4c0bc;
}

body {
  background-color: var(--base-color);
}

.neu-element {
  background-color: var(--base-color);
  border-radius: 20px;
  /* Top-left highlight, Bottom-right shadow */
  box-shadow:  9px 9px 18px var(--shadow),
              -9px -9px 18px var(--highlight);
  padding: 32px;
}

.neu-pressed {
  /* Inset shadows for pressed/active state */
  border-radius: 20px;
  background: var(--base-color);
  box-shadow: inset 9px 9px 18px var(--shadow),
              inset -9px -9px 18px var(--highlight);
}
```

## App Implementation

### SwiftUI
```swift
struct NeuCard: View {
    let baseColor = Color(red: 0.90, green: 0.89, blue: 0.87) // #E6E2DD
    
    var body: some View {
        VStack(spacing: 24) {
            Text("Neumorphic Card")
                .font(.system(size: 20, weight: .semibold, design: .rounded))
            
            Text("Extruded from the surface itself.")
                .font(.system(size: 15, design: .rounded))
                .foregroundColor(.secondary)
        }
        .padding(32)
        .background(baseColor)
        .cornerRadius(20)
        // Light shadow (top-left)
        .shadow(color: Color.white.opacity(0.7), radius: 10, x: -8, y: -8)
        // Dark shadow (bottom-right)
        .shadow(color: Color.black.opacity(0.15), radius: 10, x: 8, y: 8)
    }
}

// Pressed / inset neumorphic button
struct NeuButton: View {
    @State private var isPressed = false
    let baseColor = Color(red: 0.90, green: 0.89, blue: 0.87)
    
    var body: some View {
        Button(action: {}) {
            Text("Press Me")
                .font(.system(size: 16, weight: .semibold, design: .rounded))
                .foregroundColor(.primary)
                .padding(.horizontal, 32)
                .padding(.vertical, 16)
        }
        .background(
            Group {
                if isPressed {
                    // Inset effect using inner shadow (ZStack trick)
                    RoundedRectangle(cornerRadius: 16)
                        .fill(baseColor)
                        .overlay(
                            RoundedRectangle(cornerRadius: 16)
                                .stroke(baseColor, lineWidth: 4)
                                .shadow(color: Color.black.opacity(0.2), radius: 4, x: 4, y: 4)
                                .clipShape(RoundedRectangle(cornerRadius: 16))
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: 16)
                                .stroke(baseColor, lineWidth: 4)
                                .shadow(color: Color.white.opacity(0.7), radius: 4, x: -4, y: -4)
                                .clipShape(RoundedRectangle(cornerRadius: 16))
                        )
                } else {
                    RoundedRectangle(cornerRadius: 16)
                        .fill(baseColor)
                        .shadow(color: Color.white.opacity(0.7), radius: 10, x: -8, y: -8)
                        .shadow(color: Color.black.opacity(0.15), radius: 10, x: 8, y: 8)
                }
            }
        )
        .buttonStyle(.plain)
        .simultaneousGesture(
            DragGesture(minimumDistance: 0)
                .onChanged { _ in isPressed = true }
                .onEnded { _ in isPressed = false }
        )
    }
}
```
- The key trick: two `.shadow()` modifiers — one white (top-left), one dark (bottom-right).
- Inner shadow (pressed state) requires a ZStack/overlay hack since SwiftUI doesn't have native `inset` shadows. Clip stroked shapes to simulate.
- The view's background color MUST match its parent's background exactly.

### Flutter
```dart
class NeuCard extend
