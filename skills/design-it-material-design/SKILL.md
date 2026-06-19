---
name: material-design
description: Web and App implementation guide for Material Design. Trigger when user wants Google's aesthetic, elevation, motion, and consistent components. 
category: Creative & Media
source: antigravity
tags: [react, ai, llm, design, image, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/material-design
---


# Material Design

> "Digital paper and ink. Interfaces built on the physical properties of stacked material."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Z-Axis Elevation**: Everything exists on a specific layer. Shadows communicate hierarchy and state.
2. **Meaningful Motion**: Animations are continuous, guiding the user's focus from one state to the next (e.g., ripple effects, shared element transitions).
3. **Structured Layout**: Strict adherence to an 8dp baseline grid and specific component anatomies (cards, FABs, app bars).

## Visual DNA
- **Colors**: Works excellently with **Desert Mirage** or **Minimalist Slate**. Utilize primary, secondary, surface, and error semantic mapping.
- **Typography**: `Roboto` or `Google Sans` (or equivalent clean geometric sans). Stick strictly to the Material Type Scale (H1-H6, Subtitle, Body, Caption, Overline).
- **Shapes**: Moderately rounded corners (4px to 16px).

## Web Implementation
- Do not reinvent the wheel: mimic standard Material elevations.
- **CSS Example**:
```css
.material-card {
  background: var(--bg-surface);
  border-radius: 8px;
  padding: 16px;
  /* Material Elevation 2 */
  box-shadow: 0 3px 1px -2px rgba(0,0,0,0.2), 
              0 2px 2px 0 rgba(0,0,0,0.14), 
              0 1px 5px 0 rgba(0,0,0,0.12);
  transition: box-shadow 0.28s cubic-bezier(0.4, 0, 0.2, 1);
}

.material-btn {
  text-transform: uppercase;
  font-weight: 500;
  letter-spacing: 1.25px;
  padding: 0 16px;
  height: 36px;
  border-radius: 4px;
  background: var(--cta-highlight);
  color: #fff;
  border: none;
  /* Ripple effect is usually handled via JS, but structure is key */
}
```

## App Implementation

### SwiftUI
```swift
struct MaterialCard: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Material Card")
                .font(.system(size: 20, weight: .medium))
            Text("Digital paper and ink. Shadows communicate where this surface sits.")
                .font(.system(size: 14))
                .foregroundColor(.secondary)
            HStack {
                Spacer()
                Button("ACTION") {}
                    .font(.system(size: 14, weight: .medium))
                    .foregroundColor(.accentColor)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
            }
        }
        .padding(16)
        .background(Color(.systemBackground))
        .cornerRadius(8)
        // Material Elevation 2 equivalent
        .shadow(color: Color.black.opacity(0.12), radius: 3, x: 0, y: 1)
        .shadow(color: Color.black.opacity(0.08), radius: 2, x: 0, y: 2)
    }
}

// Material FAB
struct MaterialFAB: View {
    var body: some View {
        Button(action: {}) {
            Image(systemName: "plus")
                .font(.system(size: 24))
                .foregroundColor(.white)
                .frame(width: 56, height: 56)
                .background(Color.accentColor)
                .cornerRadius(16)
                .shadow(color: Color.black.opacity(0.2), radius: 6, x: 0, y: 3)
                .shadow(color: Color.black.opacity(0.14), radius: 4, x: 0, y: 2)
        }
    }
}
```
- Emulate Material elevation levels by stacking multiple `.shadow()` modifiers at different blur/offset values.
- Use `.cornerRadius(8...16)` — Material Design 3 uses more rounded shapes than M2.
- Animate shadow changes using `.animation(.easeInOut(duration: 0.28))` — Material uses 280ms transitions.

### Flutter
```dart
// Flutter IS Material Design — use it natively
class MaterialScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      theme: ThemeData(
        useMaterial3: true,
        colorSchemeSeed: const Color(0xFF6750A4), // Material You seed
        // Map your universal palette here
      ),
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Material Design'),
          // M3 appbar elevation is 0 by default, scrolled = 3
        ),
        body: Padding(
          padding: const EdgeInsets.all(16),
          child: Card(
            elevation: 2,
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text('Material Card',
                    style: Theme.of(context).textTheme.titleLarge),
                  const SizedBox(height: 8),
                  Text('Digital paper and ink.',
                    style: Theme.of(context).textTheme.bodyMedium),
                  const SizedBox(height: 16),
                  Align(
                
