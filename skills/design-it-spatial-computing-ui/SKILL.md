---
name: spatial-computing-ui
description: Web and App implementation guide for Spatial Computing UI. Trigger when user wants floating elements, environmental awareness, and Apple Vision Pro style. 
category: Creative & Media
source: antigravity
tags: [react, ai, llm, design, image, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/spatial-computing-ui
---


# Spatial Computing UI

> "A step beyond Spatial Design. Fully 3D windows floating in augmented reality."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Z-Space Hierarchy**: Not just drop shadows, but actual 3D distance. Modals float 10px *in front of* the main window.
2. **Gaze-Based Interaction Cues**: Elements highlight vividly when hovered, anticipating eye-tracking or precise pointer control.
3. **Glass and Light**: Windows are thick sheets of frosted glass that bend light and cast soft shadows onto the physical environment.

## Visual DNA
- **Colors**: Relies entirely on the background environment. Uses purely translucent whites (`rgba(255,255,255,0.x)`) and blacks. 
- **Typography**: `SF Pro`. Heavy use of varied font weights (Regular, Semibold, Bold) to create hierarchy.
- **Shapes**: High border radii (`24px`-`32px`). Everything is a rounded rectangle or a perfect circle.

## Web Implementation
- Best emulated using CSS 3D transforms to simulate the user's perspective.
- **CSS Example**:
```css
body {
  /* Simulate the physical room */
  background: url('living-room.jpg') center/cover;
  perspective: 1200px;
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100vh;
}

.spatial-window {
  width: 800px;
  height: 600px;
  border-radius: 32px;
  
  /* The Glass Material */
  background: rgba(255, 255, 255, 0.15);
  backdrop-filter: blur(50px) saturate(200%);
  -webkit-backdrop-filter: blur(50px) saturate(200%);
  
  /* Specular Highlights */
  border: 1px solid rgba(255, 255, 255, 0.4);
  box-shadow: 
    inset 0 1px 2px rgba(255, 255, 255, 0.8),
    0 30px 60px rgba(0, 0, 0, 0.3);
    
  /* 3D Positioning */
  transform: translateZ(-100px);
  transform-style: preserve-3d;
}

.spatial-modal {
  /* Floating in front of the main window */
  position: absolute;
  top: 50%; left: 50%;
  transform: translate(-50%, -50%) translateZ(50px);
  
  background: rgba(255, 255, 255, 0.6); /* More opaque */
  backdrop-filter: blur(30px);
  border-radius: 24px;
  padding: 30px;
  box-shadow: 0 20px 40px rgba(0, 0, 0, 0.2);
}

.spatial-btn {
  /* Gaze/Hover interaction */
  background: rgba(0,0,0,0.05);
  transition: all 0.2s cubic-bezier(0.2, 0.8, 0.2, 1);
}
.spatial-btn:hover {
  background: rgba(255,255,255,0.4);
  transform: translateZ(10px) scale(1.05);
  box-shadow: 0 10px 20px rgba(0,0,0,0.1);
}
```

## App Implementation

### SwiftUI (visionOS Native / iOS emulation)
```swift
struct SpatialComputingView: View {
    var body: some View {
        ZStack {
            // Simulated room environment
            Image("living-room")
                .resizable()
                .aspectRatio(contentMode: .fill)
                .ignoresSafeArea()
            
            // Spatial Window
            VStack(spacing: 24) {
                Text("Spatial Window")
                    .font(.title).fontWeight(.bold)
                    .foregroundColor(.white)
                
                // Gaze-reactive button
                Button(action: {}) {
                    Text("Focus Me")
                        .fontWeight(.semibold)
                        .foregroundColor(.white)
                        .padding(.horizontal, 32)
                        .padding(.vertical, 16)
                        // .hoverEffect() is magic on visionOS/iPadOS
                        // .hoverEffect(.highlight)
                }
                .background(Color.black.opacity(0.2))
                .clipShape(Capsule())
            }
            .padding(60)
            // The magic glass material
            .background(.ultraThinMaterial)
            .cornerRadius(32)
            // Specular edge highlight
            .overlay(
                RoundedRectangle(cornerRadius: 32)
                    .stroke(Color.white.opacity(0.4), lineWidth: 1)
            )
            // Environmental shadow
            .shadow(color: .black.opacity(0.3), radius: 40, y: 30)
            
            // Z-Space Modal simulation (if on iOS)
            // On visionOS, this would be a separate window volume
            Text("Floating Modal")
                .foregroundColor(.white)
                .padding(30)
                .background(.thinMaterial)
                .cornerRadius(24)
                .shadow(color: .black.opacity(0.4), radius: 30, y: 20)
                .offset(x: 100, y: 100)
        }
    }
}
```
- Use `.ultraThinMaterial` for the base windows and `.thinMaterial` for floating popovers so they feel more opaque as they get closer to the eye.
- Use `.hoverEffect()` extensively if targeting iPadOS or visionOS.

### Flutter
```dart
import 'dart:ui';

class SpatialComputingScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Stack(
        fit: StackFit.expand,
        children: [
  
