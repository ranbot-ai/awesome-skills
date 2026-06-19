---
name: skeuomorphism
description: Web and App implementation guide for Skeuomorphism. Trigger when user wants UI to mimic real-world objects, realistic textures, or physical metaphors. 
category: Creative & Media
source: antigravity
tags: [react, ai, design, image, rag, seo]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/skeuomorphism
---


# Skeuomorphism

> "Digital interfaces that look and behave like their physical counterparts."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Realistic Textures**: Leather, brushed metal, wood grain, paper. The UI should feel like a physical object you can touch.
2. **Physical Lighting & Depth**: Intense attention to specular highlights, drop shadows, inner shadows, bevels, and ambient occlusion.
3. **Real-world Metaphors**: Switches that look like hardware toggles, dials with physical notches, notepads with binding rings.

## Visual DNA
- **Colors**: Highly dependent on the material being simulated. For rich, classic skeuomorphism, use the **Industrial Chic** (for metal/hardware) or **Monochromatic Brown** (for wood/leather) palettes.
- **Typography**: Fonts that match the physical object (e.g., typewriter fonts for paper, LCD fonts for digital screens, embossed sans-serifs for hardware buttons).
- **Details**: Screws, stitching, glare, and gradients are your primary tools.

## Web Implementation
- Heavy use of layered background images (textures), complex gradients, and multiple box-shadows.
- **CSS Example**:
```css
.skeuo-button {
  /* Brushed metal effect */
  background: linear-gradient(180deg, #e0e0e0 0%, #a0a0a0 100%),
              url('brushed-metal-texture.png');
  background-blend-mode: overlay;
  
  border: 1px solid #7a7a7a;
  border-radius: 50%;
  width: 80px;
  height: 80px;
  
  /* Bevel, inner highlight, and drop shadow */
  box-shadow: 
    inset 0 2px 4px rgba(255,255,255,0.8), /* Top highlight */
    inset 0 -2px 4px rgba(0,0,0,0.4),      /* Bottom shading */
    0 4px 6px rgba(0,0,0,0.5),             /* Drop shadow */
    0 1px 1px rgba(0,0,0,0.2);
}

.skeuo-button:active {
  /* Pressing the physical button */
  box-shadow: 
    inset 0 4px 8px rgba(0,0,0,0.6),
    inset 0 -1px 2px rgba(255,255,255,0.4),
    0 1px 1px rgba(0,0,0,0.2);
  transform: translateY(2px);
}
```

## App Implementation

### SwiftUI
```swift
struct SkeuoButton: View {
    @State private var isPressed = false
    
    var body: some View {
        Button(action: {}) {
            Text("POWER")
                .font(.system(size: 14, weight: .bold))
                .foregroundColor(.white)
                .textCase(.uppercase)
        }
        .frame(width: 80, height: 80)
        .background(
            ZStack {
                // Brushed metal base
                Circle()
                    .fill(
                        LinearGradient(
                            colors: [Color(white: 0.88), Color(white: 0.63)],
                            startPoint: .top,
                            endPoint: .bottom
                        )
                    )
                // Inner highlight (top bevel)
                Circle()
                    .stroke(
                        LinearGradient(
                            colors: [.white.opacity(0.8), .clear],
                            startPoint: .top,
                            endPoint: .center
                        ),
                        lineWidth: 2
                    )
                    .padding(1)
            }
        )
        .clipShape(Circle())
        // Outer bezel ring
        .overlay(Circle().stroke(Color(white: 0.5), lineWidth: 1))
        // Physical drop shadow
        .shadow(color: .black.opacity(isPressed ? 0.2 : 0.5), radius: isPressed ? 2 : 6,
                x: 0, y: isPressed ? 1 : 4)
        .scaleEffect(isPressed ? 0.96 : 1.0)
        .animation(.easeOut(duration: 0.1), value: isPressed)
        .simultaneousGesture(
            DragGesture(minimumDistance: 0)
                .onChanged { _ in isPressed = true }
                .onEnded { _ in isPressed = false }
        )
    }
}
```
- Stack multiple shapes (`Circle`, `RoundedRectangle`) with different gradients to build up realistic depth.
- Use `.overlay()` with stroked shapes for highlight bezels along the edges.
- The pressed state should reduce shadow AND scale — simulating a physical push.

### Flutter
```dart
class SkeuoButton extends StatefulWidget {
  @override
  State<SkeuoButton> createState() => _SkeuoButtonState();
}

class _SkeuoButtonState extends State<SkeuoButton> {
  bool _isPressed = false;

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTapDown: (_) => setState(() => _isPressed = true),
      onTapUp: (_) => setState(() => _isPressed = false),
      onTapCancel: () => setState(() => _isPressed = false),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 100),
        width: 80,
        height: 80,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          // Brushed metal gradient
          gradient: LinearGradient(
            colors: [Colors.grey[300]!, Colors.grey[600]!],
            begin: Align
