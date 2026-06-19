---
name: 3d-ui
description: Web and App implementation guide for 3D UI. Trigger when user wants actual 3D objects, perspective effects, and spatial depth. 
category: Creative & Media
source: antigravity
tags: [react, ai, agent, design, rag, seo]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/3d-ui
---


# 3D UI

> "Breaking the plane. Interfaces that exist in a three-dimensional, rotatable space."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **True Depth (Z-Axis Translation)**: Elements don't just have shadows; they physically move closer to or further from the camera.
2. **Perspective**: Use CSS perspective or WebGL to create realistic vanishing points.
3. **Interactive Rotation**: Elements should respond to mouse movement or device gyroscope by tilting or rotating in 3D space.

## Visual DNA
- **Colors**: Bold, striking palettes like **Midnight Luxury** or **Industrial Chic**. 3D elements need high contrast to show their geometry.
- **Typography**: Bold, blocky, or extruded text.
- **Graphics**: Instead of flat icons, use rendered 3D assets (.glb, .gltf, or high-res PNGs of 3D objects).

## Web Implementation
- Rely heavily on `perspective`, `transform-style: preserve-3d`, and `rotateX`/`rotateY`.
- **CSS Example**:
```css
.perspective-container {
  perspective: 1000px;
  display: flex;
  justify-content: center;
  align-items: center;
}

.card-3d {
  width: 300px;
  height: 400px;
  transform-style: preserve-3d;
  transition: transform 0.5s ease;
  
  /* Initial slight rotation */
  transform: rotateX(15deg) rotateY(-15deg);
}

.card-3d:hover {
  /* Straighten out on hover */
  transform: rotateX(0) rotateY(0) translateZ(50px);
}

/* Inner elements popping out */
.card-content {
  transform: translateZ(30px); /* Pushes content 30px closer to viewer */
}
```

## App Implementation

### SwiftUI
```swift
struct Card3D: View {
    @State private var dragOffset = CGSize.zero
    
    var body: some View {
        VStack {
            Text("3D Card")
                .font(.largeTitle.bold())
                .foregroundColor(.white)
        }
        .frame(width: 300, height: 400)
        .background(
            LinearGradient(colors: [.blue, .purple], startPoint: .topLeading, endPoint: .bottomTrailing)
        )
        .cornerRadius(24)
        .shadow(radius: 20)
        // Magic 3D effect based on drag gesture
        .rotation3DEffect(
            .degrees(Double(dragOffset.width / 10)),
            axis: (x: 0, y: 1, z: 0),
            perspective: 0.5
        )
        .rotation3DEffect(
            .degrees(Double(-dragOffset.height / 10)),
            axis: (x: 1, y: 0, z: 0),
            perspective: 0.5
        )
        .gesture(
            DragGesture()
                .onChanged { value in
                    withAnimation(.interactiveSpring()) {
                        dragOffset = value.translation
                    }
                }
                .onEnded { _ in
                    withAnimation(.spring()) {
                        dragOffset = .zero
                    }
                }
        )
    }
}
```
- SwiftUI makes this incredibly easy with `.rotation3DEffect()`.
- Use the `perspective` parameter (default 1/6, higher = more distorted) to control the camera distance.
- Link the rotation axes (`x`, `y`) to drag gestures or CoreMotion (gyroscope) for interactive 3D UI.

### Flutter
```dart
class Card3D extends StatefulWidget {
  @override
  State<Card3D> createState() => _Card3DState();
}

class _Card3DState extends State<Card3D> {
  Offset _offset = Offset.zero;

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onPanUpdate: (details) {
        setState(() => _offset += details.delta);
      },
      onPanEnd: (_) {
        setState(() => _offset = Offset.zero); // Snap back
      },
      child: TweenAnimationBuilder(
        tween: Tween<Offset>(begin: Offset.zero, end: _offset),
        duration: const Duration(milliseconds: 200),
        curve: Curves.easeOut,
        builder: (context, Offset offset, child) {
          // Perspective Matrix
          final transform = Matrix4.identity()
            ..setEntry(3, 2, 0.001) // perspective
            ..rotateX(-offset.dy * 0.01)
            ..rotateY(offset.dx * 0.01);

          return Transform(
            transform: transform,
            alignment: FractionalOffset.center,
            child: Container(
              width: 300,
              height: 400,
              decoration: BoxDecoration(
                gradient: const LinearGradient(colors: [Colors.blue, Colors.purple]),
                borderRadius: BorderRadius.circular(24),
                boxShadow: const [BoxShadow(color: Colors.black45, blurRadius: 20)],
              ),
              alignment: Alignment.center,
              child: const Text('3D Card', 
                style: TextStyle(color: Colors.white, fontSize: 32, fontWeight: FontWeight.bold)),
            ),
          );
        },
      ),
    );
  }
}
```
- The secret to perspective in Flutter is `Matrix4.identity()..setEntry(3, 2, 0.001)`.
- Wrap the target container in a `Transform` wid
