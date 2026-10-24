---
name: dark-mode
description: Web and App implementation guide for Dark Mode Design. Trigger when user wants dark surfaces, reduced eye strain, and premium sleek aesthetics. 
category: Creative & Media
source: antigravity
tags: [react, ai, llm, design, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/dark-mode
---


# Dark Mode Design

> "Not just inverted colors. A carefully constructed hierarchy of light on dark."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Choose Surface Colors**: Black and dark grey are both valid. OLED artifacts depend on the display; comfort depends on the user and lighting. Offer theme choice and test contrast.
2. **Elevation via Lightness**: Lighter surfaces and borders can clarify layers when shadows are subtle. Shadows are not universally invisible in dark mode.
3. **Test Accents**: Choose accent saturation for readable text and clear state indicators; avoid universal claims about discomfort.

## Visual DNA
- **Colors**: **Midnight Luxury** or **Minimalist Slate** (inverted). Background `#121212`. Elevated cards `#1E1E1E`, `#252525`. Primary text `#E1E1E1` (not `#FFFFFF`).
- **Typography**: Standard highly readable sans-serifs, but often dropped down one font weight compared to light mode, as light text on dark backgrounds appears optically thicker.
- **Shadows**: Pure black shadows, but with much lower opacity, mostly to separate slightly different shades of grey.

## Web Implementation
- **CSS Example**:
```css
:root {
  --bg-base: #121212;
  --bg-elevated-1: #1E1E1E;
  --bg-elevated-2: #242424;
  --text-high-emphasis: rgba(255, 255, 255, 0.87);
  --text-medium-emphasis: rgba(255, 255, 255, 0.60);
  
  /* Accent color: Desaturated purple instead of bright purple */
  --accent-color: #BB86FC; 
}

body {
  background-color: var(--bg-base);
  color: var(--text-high-emphasis);
  font-weight: 400; /* Preserve readable body weight; test with users. */
}

.dark-card {
  background-color: var(--bg-elevated-1);
  border-radius: 8px;
  padding: 24px;
  
  /* Very subtle border can help separate dark surfaces */
  border: 1px solid rgba(255, 255, 255, 0.05);
}

.dark-card:hover {
  /* On hover, the element moves closer to the user, so it gets lighter */
  background-color: var(--bg-elevated-2);
}

.dark-btn {
  background-color: var(--accent-color);
  color: #000; /* Dark text on light accent is highly readable */
  font-weight: 600;
  border: none;
  padding: 12px 24px;
  border-radius: 4px;
}
```

## App Implementation

### SwiftUI
```swift
struct DarkModeView: View {
    // Force Dark Mode on this specific view (or use system settings)
    @Environment(\.colorScheme) var colorScheme
    
    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // Primary elevated card
                VStack(alignment: .leading, spacing: 12) {
                    Text("Elevation via Lightness")
                        .font(.headline)
                        .foregroundColor(.primary) // Auto-adapts
                    Text("In dark mode, elevated surfaces are lighter grey, not shadowed.")
                        .font(.subheadline)
                        .foregroundColor(.secondary) // Auto-adapts
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
                // Use native semantic colors. .secondarySystemBackground is lighter than .systemBackground
                .background(Color(UIColor.secondarySystemBackground))
                .cornerRadius(12)
                
                // Desaturated Accent Button
                Button(action: {}) {
                    Text("Desaturated Accent")
                        .fontWeight(.semibold)
                        .foregroundColor(.black) // Dark text on light accent
                        .padding()
                        .frame(maxWidth: .infinity)
                        .background(Color(red: 0.73, green: 0.52, blue: 0.98)) // #BB86FC (Desaturated purple)
                        .cornerRadius(8)
                }
            }
            .padding()
        }
        // Semantic systemBackground follows platform appearance; dark iOS may use black.
        .background(Color(UIColor.systemBackground))
    }
}
// .preferredColorScheme(.dark) to force
```
- **Rely on Semantics**: SwiftUI's `Color.primary`, `Color.secondary`, `Color(UIColor.systemBackground)` and `Color(UIColor.secondarySystemBackground)` adapt to platform appearance; verify custom combinations and increased-contrast settings.
- Avoid forcing explicit hex codes for backgrounds unless you are building a custom-themed app.

### Flutter
```dart
import 'package:flutter/material.dart';

class DarkModeApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      // Configure the Dark Theme
      themeMode: ThemeMode.dark,
      darkTheme: ThemeData.dark().copyWith(
        scaffoldBackgroundColor: const Color(0xFF121212), // Standard dark background
        cardColor: const Color(0xFF1E1E1E), // Elevated surface
        colorScheme: const ColorScheme.dark().copyWith(
          prim
