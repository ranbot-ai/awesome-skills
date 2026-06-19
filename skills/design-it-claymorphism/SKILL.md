---
name: claymorphism
description: Web and App implementation guide for Claymorphism. Trigger when user wants soft 3D elements, rounded shapes, and a playful, tactile appearance. 
category: Creative & Media
source: antigravity
tags: [react, ai, design, image, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/claymorphism
---


# Claymorphism

> "Like interacting with a pristine, digital claymation set. Soft, bubbly, and incredibly approachable."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Fluffy 3D Volume**: Elements look like inflated balloons or soft clay blocks.
2. **Double Inner Shadows**: The signature of claymorphism is an inset light shadow on the top-left and an inset dark shadow on the bottom-right, giving 3D volume to a solid shape.
3. **Continuous Curves**: Maximum border-radius. No sharp edges exist in this universe.

## Visual DNA
- **Colors**: Thrives on pastels and bright, friendly hues. **Desert Mirage**, **Earth-Grounded Elegance**, or custom pastel palettes work best.
- **Typography**: Playful, thick, rounded fonts (e.g., `Sniglet`, `Fredoka One`, `Nunito`).
- **Shapes**: 'Squicles' (squares with heavily rounded, continuous corners) and perfect circles.

## Web Implementation
- Distinct from Neumorphism: Claymorphism elements detach from the background (they have drop shadows) and use inner shadows to create volume, often using colors that contrast with the background.
- **CSS Example**:
```css
.clay-card {
  background-color: #F8B4A6; /* Soft coral */
  border-radius: 32px;
  padding: 40px;
  
  /* 
    1. Outer drop shadow (detaches from background)
    2. Inner top-left highlight (volume)
    3. Inner bottom-right shadow (volume)
  */
  box-shadow: 
    8px 8px 24px rgba(0, 0, 0, 0.15),           /* Outer */
    inset -8px -8px 16px rgba(0, 0, 0, 0.1),    /* Inner dark */
    inset 8px 8px 16px rgba(255, 255, 255, 0.4); /* Inner light */
    
  transition: transform 0.2s cubic-bezier(0.34, 1.56, 0.64, 1); /* Bouncy */
}

.clay-card:hover {
  transform: translateY(-5px) scale(1.02);
}
```

## App Implementation

### SwiftUI
```swift
struct ClayCard: View {
    @State private var isPressed = false
    
    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "cloud.sun.fill")
                .font(.system(size: 48))
                .foregroundColor(.white)
            Text("Claymorphic Card")
                .font(.system(size: 20, weight: .bold, design: .rounded))
                .foregroundColor(.white)
        }
        .padding(40)
        .background(Color(red: 0.97, green: 0.71, blue: 0.65)) // Soft coral
        .cornerRadius(32)
        // Outer shadow — detaches from background
        .shadow(color: .black.opacity(0.15), radius: 12, x: 8, y: 8)
        // Inner highlight (top-left) — faked with overlay
        .overlay(
            RoundedRectangle(cornerRadius: 32)
                .stroke(
                    LinearGradient(
                        colors: [.white.opacity(0.5), .clear, .black.opacity(0.1)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ),
                    lineWidth: 3
                )
        )
        // Bouncy spring animation on tap
        .scaleEffect(isPressed ? 0.95 : 1.0)
        .animation(.interpolatingSpring(stiffness: 300, damping: 10), value: isPressed)
        .onTapGesture { }
        .simultaneousGesture(
            DragGesture(minimumDistance: 0)
                .onChanged { _ in isPressed = true }
                .onEnded { _ in isPressed = false }
        )
    }
}
```
- The "clay" volume comes from a gradient stroke overlay: white on top-left, dark on bottom-right.
- Use `.interpolatingSpring(stiffness: 300, damping: 10)` for the bouncy feel — critical for clay aesthetics.
- Background color should be pastel/bright but NOT the same as the parent (unlike neumorphism).

### Flutter
```dart
class ClayCard extends StatefulWidget {
  @override
  State<ClayCard> createState() => _ClayCardState();
}

class _ClayCardState extends State<ClayCard> with SingleTickerProviderStateMixin {
  double _scale = 1.0;

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTapDown: (_) => setState(() => _scale = 0.95),
      onTapUp: (_) => setState(() => _scale = 1.0),
      onTapCancel: () => setState(() => _scale = 1.0),
      child: AnimatedScale(
        scale: _scale,
        duration: const Duration(milliseconds: 200),
        curve: Curves.elasticOut,  // Bouncy clay feel
        child: Container(
          padding: const EdgeInsets.all(40),
          decoration: BoxDecoration(
            color: const Color(0xFFF8B4A6), // Soft coral
            borderRadius: BorderRadius.circular(32),
            boxShadow: [
              // Outer shadow
              BoxShadow(
                color: Colors.black.withOpacity(0.15),
                offset: const Offset(8, 8),
                blurRadius: 24,
              ),
            ],
            // Gradient border for the clay volume effect
            border: GradientBorder(
              gradient: LinearGradient(
            
