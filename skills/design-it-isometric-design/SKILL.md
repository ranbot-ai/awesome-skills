---
name: isometric-design
description: Web and App implementation guide for Isometric Design. Trigger when user wants angled 3D appearances without vanishing points, often used for technical illustrations. 
category: Creative & Media
source: antigravity
tags: [react, ai, llm, design]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/isometric-design
---


# Isometric Design

> "The architect's view. A parallel projection where depth is constant and parallel lines never converge."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Parallel Lines**: Isometric projection is an orthographic 3D projection with equal axis foreshortening; its projected axes are 120 degrees apart. Perspective is not required.
2. **Top-Down, Angled View**: The classic "SimCity" perspective.
3. **Blocky Architecture**: UI elements often look like city blocks or stacked tiles.

## Visual DNA
- **Colors**: **Warm Tech** or **Earth-Grounded Elegance**. Isometric designs often look like physical models, so slightly muted, realistic colors work well.
- **Typography**: Keep text flat to the screen, or map it perfectly to the isometric planes (top, left, right).
- **Shadows**: Hard, long drop shadows cast at an exact angle (usually -45 or 45 degrees).

## Web Implementation
- CSS transforms are perfect for this. The 60°/−45° examples below are stylized oblique tiles, not exact mathematical isometric projections. An orthographic camera aligned to (1,1,1) gives equal axis foreshortening.
- **CSS Example**:
```css
.isometric-grid {
  /* The foundation */
  transform-style: preserve-3d;
  transform: rotateX(60deg) rotateZ(-45deg);
}

.iso-block {
  width: 100px;
  height: 100px;
  background-color: var(--secondary-base);
  position: relative;
  transition: transform 0.3s;
}

/* Creating the 3D block with pseudo-elements */
.iso-block::before {
  content: '';
  position: absolute;
  width: 20px; /* Depth */
  height: 100%;
  background-color: var(--primary-text); /* Darker shade for side */
  right: 100%;
  transform-origin: right;
  transform: skewY(-45deg);
}

.iso-block::after {
  content: '';
  position: absolute;
  width: 100%;
  height: 20px; /* Depth */
  background-color: var(--cta-highlight); /* Lightest shade for top/bottom */
  top: 100%;
  transform-origin: top;
  transform: skewX(-45deg);
}

.iso-block:hover {
  transform: translateZ(20px) translate(-10px, -10px);
}
```

## App Implementation

### SwiftUI
```swift
struct IsometricView: View {
    var body: some View {
        ZStack {
            Color.white.ignoresSafeArea()
            
            // Isometric Stack
            VStack(spacing: 0) {
                // Top layer
                Rectangle()
                    .fill(Color.blue)
                    .frame(width: 150, height: 150)
                    .overlay(Text("TOP").foregroundColor(.white))
                
                // Shadow simulation
                Rectangle()
                    .fill(Color.black.opacity(0.2))
                    .frame(width: 150, height: 20)
            }
            // Stylized oblique transform, not exact isometric projection
            .rotationEffect(.degrees(-45))
            .rotation3DEffect(.degrees(60), axis: (x: 1, y: 0, z: 0))
        }
    }
}
```
- SwiftUI's `.rotation3DEffect` can produce a stylized tile; its default perspective must be disabled when strict parallel projection is needed. Rotate Z by -45 degrees first (via `.rotationEffect`), then rotate X by 60 degrees.
- You can stack multiple views along the Z-axis (or simulate it with Y offsets before the 3D rotation) to create towering isometric city blocks.

### Flutter
```dart
import 'dart:math';

class IsometricScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.white,
      body: Center(
        child: Transform(
          // The Isometric Matrix Math
          alignment: FractionalOffset.center,
          transform: Matrix4.identity()
            // No perspective term for parallel projection.
            ..rotateX(pi / 3) // 60 degrees
            ..rotateZ(-pi / 4), // -45 degrees
          child: Container(
            width: 150,
            height: 150,
            decoration: BoxDecoration(
              color: Colors.blue,
              boxShadow: [
                // Hard isometric drop shadow
                BoxShadow(
                  color: Colors.black.withOpacity(0.3),
                  offset: const Offset(20, 20),
                  blurRadius: 0, // No blur for isometric
                ),
              ],
            ),
            child: const Center(child: Text('ISO BLOCK', style: TextStyle(color: Colors.white))),
          ),
        ),
      ),
    );
  }
}
```
- `Transform` with `Matrix4` is required in Flutter. Applying `rotateX` and `rotateZ` produces the stylized tile shown here.
- Isometric shadows are usually completely hard (0 `blurRadius`) and offset perfectly along the grid axes.

### React Native
```jsx
const IsometricScreen = () => {
  return (
    <View style={{ flex: 1, backgroundColor: '#FFF', justifyContent: 'center', alignItems: 'center' }}>
      
      <View style={{
        
