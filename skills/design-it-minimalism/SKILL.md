---
name: minimalism
description: Web and App implementation guide for the Minimalism design style. Trigger when the user wants simple layouts, lots of whitespace, few colors, and clear hierarchy. 
category: Creative & Media
source: antigravity
tags: [react, ai, llm, design, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/minimalism
---


# Minimalism

> "Less is more. Remove until nothing is left but the essential."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Extreme Whitespace**: Margins and padding should be double what you initially think is appropriate.
2. **Strict Typography**: Rely on font weights and sizes to establish hierarchy, not colors or boxes.
3. **Absence of Decor**: No borders, no drop shadows, no background textures.

## Visual DNA
- **Colors**: Best paired with **Minimalist Slate** or **Modern Editorial** palettes. Backgrounds must be absolute (pure or off-white/black).
- **Typography**: Sans-serif, geometric. (e.g., `Inter`, `Helvetica Neue`, `SF Pro`). Use extreme contrast in weights (Thin vs Black).
- **Spacing**: Use a generous baseline grid (e.g., multiples of 8px, heavily favoring 48px to 120px padding).

## Web Implementation
- Use Flexbox/Grid with large `gap` properties.
- **CSS Example**:
```css
.minimal-container {
  max-width: 800px;
  margin: 0 auto;
  padding: 120px 24px;
  background-color: var(--bg-primary);
}
.minimal-title {
  font-size: 3rem;
  font-weight: 300;
  letter-spacing: -0.02em;
  margin-bottom: 48px;
}
.minimal-btn {
  background: transparent;
  border: 1px solid var(--text-primary);
  padding: 16px 32px;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  transition: all 0.3s ease;
}
```

## App Implementation

### SwiftUI
```swift
struct MinimalView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 48) {
                Text("Headline")
                    .font(.system(size: 34, weight: .light))
                    .tracking(-0.5)
                
                Text("Body text sits quietly with generous space around it. Let the content breathe.")
                    .font(.system(size: 17, weight: .regular))
                    .foregroundColor(.secondary)
                    .lineSpacing(6)
                
                // Minimal button — just a thin border, no fill
                Button(action: {}) {
                    Text("Continue")
                        .font(.system(size: 14, weight: .medium))
                        .tracking(1.5)
                        .textCase(.uppercase)
                        .padding(.horizontal, 32)
                        .padding(.vertical, 16)
                        .overlay(
                            RoundedRectangle(cornerRadius: 0)
                                .stroke(Color.primary, lineWidth: 1)
                        )
                }
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 80)
        }
        .background(Color(.systemBackground))
    }
}
```
- Use `VStack(spacing: 40...64)` for generous separation between elements.
- Never use `.shadow()` or `Card`-like containers. Let whitespace define grouping.
- Use `Divider()` sparingly — only when two adjacent sections need separation.

### Flutter
```dart
class MinimalScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.white,
      body: SingleChildScrollView(
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 80),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Headline',
              style: TextStyle(
                fontSize: 34,
                fontWeight: FontWeight.w300,
                letterSpacing: -0.5,
                color: Colors.black87,
              ),
            ),
            const SizedBox(height: 48),
            Text(
              'Body text sits quietly with generous space around it.',
              style: TextStyle(
                fontSize: 17,
                fontWeight: FontWeight.w400,
                height: 1.6,
                color: Colors.black54,
              ),
            ),
            const SizedBox(height: 48),
            // Minimal button — outlined, no elevation
            OutlinedButton(
              onPressed: () {},
              style: OutlinedButton.styleFrom(
                side: const BorderSide(color: Colors.black87, width: 1),
                shape: const RoundedRectangleBorder(borderRadius: BorderRadius.zero),
                padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 16),
              ),
              child: Text(
                'CONTINUE',
                style: TextStyle(
                  fontSize: 14,
                  fontWeight: FontWeight.w500,
                  letterSpacing: 1.5,
                  color: Colors.black87,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
```
- Set `elevation: 0` on **all** Material widgets (`AppBar`, `Card`, `FloatingActionButton`).
- Use `SizedBox(height: 48)` or lar
