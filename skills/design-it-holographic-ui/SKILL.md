---
name: holographic-ui
description: Web and App implementation guide for Holographic UI. Trigger when user wants light-based appearance, projected interfaces, and transparent floating elements. 
category: Creative & Media
source: antigravity
tags: [react, ai, llm, design, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/holographic-ui
---


# Holographic UI

> "Made of light. Interfaces projected into thin air, visible but completely translucent."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Zero Opacity Backgrounds**: Elements are never fully solid. Everything is semi-transparent, allowing the background to show through.
2. **Scanlines and Interference**: The illusion of a projection is sold by horizontal scanlines, slight chromatic aberration, or flickering.
3. **Luminous Edges**: The borders of elements are brighter than the centers, mimicking how lasers or light projections focus at the edges.

## Visual DNA
- **Colors**: Almost exclusively monochrome Cyan, Blue, or Green, with white core highlights.
- **Typography**: Thin, technical sans-serifs. Must have a glowing `text-shadow`.
- **Styling**: Intensive use of `rgba()`, `mix-blend-mode: screen` or `add`, and CSS filters.

## Web Implementation
- **CSS Example**:
```css
body {
  background-color: #020202; /* Must be dark for holograms to show */
  background-image: url('dark-lab-background.jpg');
  background-size: cover;
  color: #88ffff;
}

.hologram-panel {
  background: rgba(0, 200, 255, 0.05); /* Extremely sheer */
  border: 1px solid rgba(136, 255, 255, 0.5);
  border-radius: 4px;
  padding: 30px;
  
  /* The glowing edge */
  box-shadow: 
    inset 0 0 20px rgba(0, 200, 255, 0.2),
    0 0 15px rgba(0, 200, 255, 0.3);
    
  /* Scanline effect */
  background-image: linear-gradient(
    rgba(136, 255, 255, 0.1) 1px, 
    transparent 1px
  );
  background-size: 100% 4px;
}

.holo-text {
  font-family: 'Rajdhani', sans-serif;
  text-transform: uppercase;
  text-shadow: 0 0 8px rgba(136, 255, 255, 0.8);
  mix-blend-mode: screen;
}

/* Subtle flicker */
.holo-flicker {
  animation: hologramFlicker 4s infinite;
}

@keyframes hologramFlicker {
  0%, 100% { opacity: 1; }
  92% { opacity: 1; }
  93% { opacity: 0.4; }
  94% { opacity: 0.9; }
  96% { opacity: 0.2; }
  98% { opacity: 1; }
}
```

## App Implementation

### SwiftUI
```swift
struct HolographicUIView: View {
    @State private var isFlickering = false
    
    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            
            VStack {
                Text("HOLOGRAM ACTIVE")
                    .font(.custom("Courier", size: 24))
                    .foregroundColor(Color(hex: "88FFFF"))
                    .shadow(color: Color(hex: "88FFFF"), radius: 10)
                    .blendMode(.screen) // Critical for light UI
                
                Spacer().frame(height: 40)
                
                VStack {
                    Text("SYSTEM DIAGNOSTICS")
                        .foregroundColor(Color(hex: "88FFFF"))
                }
                .padding(30)
                .frame(maxWidth: .infinity)
                .background(Color(hex: "88FFFF").opacity(0.05))
                .border(Color(hex: "88FFFF").opacity(0.5), width: 1)
                // The glowing edge effect
                .shadow(color: Color(hex: "88FFFF").opacity(0.5), radius: 15)
                .blendMode(.screen)
                .opacity(isFlickering ? 0.4 : 1.0)
            }
            .padding()
            
            // Scanline Overlay
            LinearGradient(
                stops: [
                    .init(color: Color(hex: "88FFFF").opacity(0.1), location: 0),
                    .init(color: .clear, location: 0.5)
                ],
                startPoint: .top, endPoint: .bottom
            )
            .frame(height: 4)
            .background(Color.clear)
            // You would tile this in a real app using an Image or custom shape
            .blendMode(.screen)
        }
        .onAppear {
            // Simulate flicker
            Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { _ in
                if Int.random(in: 1...100) > 95 {
                    isFlickering.toggle()
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
                        isFlickering = false
                    }
                }
            }
        }
    }
}
```
- `.blendMode(.screen)` is absolutely critical. It makes elements act like projected light.
- Stack multiple `.shadow()` modifiers to create a bloom effect around text and borders.

### Flutter
```dart
class HolographicScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black, // Dark lab background
      body: Stack(
        children: [
          Padding(
            padding: const EdgeInsets.all(24.0),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                // Glowing Text
                const Text(
                  'HOLOGRAM ACTIVE',
                  style: TextStyle(
   
