---
name: aurora-ui
description: Web and App implementation guide for Aurora UI. Trigger when user wants gradient glows, color blobs, and atmospheric lighting effects. 
category: Creative & Media
source: antigravity
tags: [react, api, ai, agent, llm, design, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/aurora-ui
---


# Aurora UI

> "Ethereal, shifting lights. Like the Northern Lights trapped beneath a pane of frosted glass."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Blurred Color Orbs**: Large, out-of-focus, highly saturated color blobs floating in the background.
2. **Glassy Overlays**: Foreground elements are often semi-transparent (glassmorphism) to let the aurora effect shine through.
3. **Fluid Motion**: The background color orbs should slowly drift, expand, and contract.

## Visual DNA
- **Colors**: Requires dark, deep backgrounds with vibrant, luminous accents. **Midnight Luxury** or **Yacht Club** (modified to dark mode) work well, injecting bright cyan, magenta, or lime green as the glowing orbs.
- **Typography**: Thin, elegant sans-serifs or sophisticated serif fonts. High contrast white text.
- **Layout**: Keep foreground UI elements minimal to let the background remain the star.

## Web Implementation
- Best achieved with absolute-positioned, heavily blurred `div`s behind the main content.
- **CSS Example**:
```css
body {
  background-color: #0A0A0A;
  overflow-x: hidden;
  position: relative;
}

/* The Glowing Orb */
.aurora-blob {
  position: absolute;
  width: 400px;
  height: 400px;
  background: radial-gradient(circle, rgba(181,154,95,0.8) 0%, rgba(181,154,95,0) 70%);
  border-radius: 50%;
  filter: blur(80px);
  z-index: -1;
  animation: float 20s infinite ease-in-out alternate;
}

.aurora-blob.blue {
  background: radial-gradient(circle, rgba(92,107,115,0.8) 0%, rgba(0,0,0,0) 70%);
  top: 20%;
  left: 60%;
  animation-delay: -5s;
}

@keyframes float {
  0% { transform: translate(0, 0) scale(1); }
  50% { transform: translate(-50px, 100px) scale(1.2); }
  100% { transform: translate(100px, -50px) scale(0.9); }
}

/* Foreground content should be glassmorphic */
.aurora-card {
  background: rgba(255,255,255,0.03);
  backdrop-filter: blur(20px);
  border: 1px solid rgba(255,255,255,0.05);
  border-radius: 24px;
}
```

## App Implementation

### SwiftUI
```swift
struct AuroraView: View {
    @State private var animate = false
    
    var body: some View {
        ZStack {
            // Dark background
            Color.black.ignoresSafeArea()
            
            // Animated Orbs
            Circle()
                .fill(Color(red: 0.71, green: 0.60, blue: 0.37)) // #B59A5F
                .blur(radius: 80)
                .frame(width: 300, height: 300)
                .offset(x: animate ? -50 : 50, y: animate ? -100 : 0)
            
            Circle()
                .fill(Color(red: 0.36, green: 0.42, blue: 0.45)) // #5C6B73
                .blur(radius: 80)
                .frame(width: 300, height: 300)
                .offset(x: animate ? 100 : -50, y: animate ? 100 : -50)
            
            // Glassy Foreground content
            VStack {
                Text("Aurora Interface")
                    .font(.largeTitle.bold())
                    .foregroundColor(.white)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(.ultraThinMaterial)
        }
        .onAppear {
            withAnimation(.easeInOut(duration: 10).repeatForever(autoreverses: true)) {
                animate = true
            }
        }
    }
}
```
- Use `Circle().blur(radius: 80...120)` in a `ZStack` underneath the main content.
- Animate the `.offset()` with a very long `duration (10-20 seconds)`.
- Use `.background(.ultraThinMaterial)` on foreground containers to let the colored light bleed through nicely.

### Flutter
```dart
import 'dart:ui';

class AuroraView extends StatefulWidget {
  @override
  State<AuroraView> createState() => _AuroraViewState();
}

class _AuroraViewState extends State<AuroraView> with SingleTickerProviderStateMixin {
  late AnimationController _controller;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(vsync: this, duration: const Duration(seconds: 10))..repeat(reverse: true);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      body: Stack(
        children: [
          // Animated orb
          AnimatedBuilder(
            animation: _controller,
            builder: (context, child) {
              return Positioned(
                top: 100 + (_controller.value * 100),
                left: -50 + (_controller.value * 100),
                child: Container(
                  width: 300,
                  height: 300,
                  decoration: const BoxDecoration(
                    shape: BoxShape.circle,
                    color: Color(0xFFB59A5F),
                  ),
                ),
              );
            },
          ),
          // Massive blur
