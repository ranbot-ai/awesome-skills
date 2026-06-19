---
name: flat-design-2
description: Web and App implementation guide for Flat Design 2.0 (Semi-Flat). Trigger when the user wants flat design with subtle shadows and improved usability. 
category: Creative & Media
source: antigravity
tags: [react, ai, llm, design, seo, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/flat-design-2
---


# Flat Design 2.0 (Semi-Flat)

> "Flat aesthetics, but with subtle hints of physics to communicate interactability."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Mostly Flat**: The primary aesthetic remains 2D and solid.
2. **Subtle Elevation**: Use extremely soft, large-spread shadows strictly to indicate interactable elements (buttons, floating action buttons) or layers (modals).
3. **Micro-Gradients**: Occasional, barely noticeable linear gradients to prevent large surfaces from feeling dead.

## Visual DNA
- **Colors**: Pairs well with **Warm Tech** or **Earth-Grounded Elegance**.
- **Typography**: Clean, readable sans-serifs.
- **Shadows**: Shadows must be low opacity, high blur, and usually tinted with the background color, not pure black.

## Web Implementation
- **CSS Example**:
```css
:root {
  --shadow-color: rgba(43, 48, 58, 0.08); /* Tinted shadow */
}

.flat2-card {
  background-color: var(--bg-primary);
  border-radius: 8px;
  padding: 32px;
  /* Very subtle, diffuse shadow */
  box-shadow: 0 10px 30px var(--shadow-color);
  transition: transform 0.3s ease, box-shadow 0.3s ease;
}

.flat2-card:hover {
  transform: translateY(-4px);
  box-shadow: 0 20px 40px rgba(43, 48, 58, 0.12);
}

.flat2-btn {
  background: var(--cta-highlight);
  border-radius: 4px;
  padding: 12px 24px;
  color: white;
  border: none;
  box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}
```

## App Implementation

### SwiftUI
```swift
struct SemiFlatCard: View {
    @State private var isPressed = false
    
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Semi-Flat Card")
                .font(.system(size: 18, weight: .semibold))
            Text("Flat aesthetic with just enough depth to hint at interactivity.")
                .font(.system(size: 15))
                .foregroundColor(.secondary)
        }
        .padding(24)
        .background(Color(.systemBackground))
        .cornerRadius(8)
        // The key: very soft, tinted shadow — NOT harsh black
        .shadow(color: Color.black.opacity(0.06), radius: 12, x: 0, y: 4)
        .scaleEffect(isPressed ? 0.98 : 1.0)
        .animation(.easeOut(duration: 0.2), value: isPressed)
        .onLongPressGesture(minimumDuration: .infinity, pressing: { pressing in
            isPressed = pressing
        }, perform: {})
    }
}

struct SemiFlatButton: View {
    var body: some View {
        Button(action: {}) {
            Text("Continue")
                .font(.system(size: 15, weight: .semibold))
                .foregroundColor(.white)
                .padding(.horizontal, 24)
                .padding(.vertical, 12)
                .background(Color.accentColor)
                .cornerRadius(4)
                // Subtle button shadow
                .shadow(color: Color.accentColor.opacity(0.25), radius: 8, x: 0, y: 4)
        }
        .buttonStyle(.plain)
    }
}
```
- Shadow color should be tinted (e.g., `Color.accentColor.opacity(0.15)`), never pure black.
- Use `radius: 10...16` with `opacity: 0.05...0.08` — if you can immediately see the shadow, it's too heavy.
- Add subtle `scaleEffect` on press to hint at physical feedback.

### Flutter
```dart
class SemiFlatCard extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(8),
        // Very soft, tinted shadow
        boxShadow: [
          BoxShadow(
            color: const Color(0xFF2B303A).withOpacity(0.08),
            blurRadius: 24,
            offset: const Offset(0, 8),
            spreadRadius: 0,
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text('Semi-Flat Card',
            style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600)),
          const SizedBox(height: 16),
          const Text('Flat aesthetic with just enough depth to hint at interactivity.',
            style: TextStyle(fontSize: 15, color: Colors.black54)),
          const SizedBox(height: 20),
          ElevatedButton(
            onPressed: () {},
            style: ElevatedButton.styleFrom(
              elevation: 2,  // Very low — just enough to feel clickable
              shadowColor: Theme.of(context).primaryColor.withOpacity(0.3),
              backgroundColor: Theme.of(context).primaryColor,
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(4)),
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
            ),
            child: const Text('Continue', style: TextStyle(fontWeight: FontWeight.w600)),
          ),
        ],
      ),
    );
  }
}
```
- Use `elevation: 1` to `e
