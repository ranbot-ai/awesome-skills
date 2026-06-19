---
name: spatial-design
description: Web and App implementation guide for Spatial Design. Trigger when user wants environment-aware layouts, Apple Vision Pro inspiration, and mixed reality aesthetics. 
category: Creative & Media
source: antigravity
tags: [react, ai, llm, design, image, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/spatial-design
---


# Spatial Design

> "UI that belongs in the room with you. Transparent, glass-like panels that react to the lighting of the physical space."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Environmental Transparency**: The UI acts like a glass pane. It is deeply reliant on background blur, but specifically aims to let the environment (or a simulated environment image) dictate the mood.
2. **Dynamic Lighting**: Elements respond to cursor position as if a flashlight is shining on them.
3. **Subtle Volume**: Not flat, but not extremely 3D. Elements have a very thin rim of light around the edge (specular highlight).

## Visual DNA
- **Colors**: Almost exclusively uses `rgba()` white or black. The actual color comes entirely from the background environment.
- **Typography**: Extremely sharp, high legibility. Often uses varying font weights to establish hierarchy without relying on color. Apple's `SF Pro` is the gold standard here.
- **Icons**: Outlined, high-legibility glyphs.

## Web Implementation
- **CSS Example**:
```css
body {
  /* Needs a complex background to look right */
  background: url('room-environment.jpg') cover;
}

.spatial-panel {
  /* The core material */
  background: rgba(255, 255, 255, 0.2); /* Very sheer */
  backdrop-filter: blur(40px) saturate(150%);
  -webkit-backdrop-filter: blur(40px) saturate(150%);
  
  border-radius: 32px;
  padding: 40px;
  
  /* The specular rim light */
  box-shadow: 
    inset 0 1px 1px rgba(255,255,255,0.6),
    inset 0 0 1px 1px rgba(255,255,255,0.2),
    0 24px 48px rgba(0,0,0,0.1);
}

.spatial-btn {
  background: rgba(0,0,0,0.1);
  color: white;
  border-radius: 20px;
  padding: 12px 24px;
  backdrop-filter: blur(10px);
  transition: all 0.2s;
}

.spatial-btn:hover {
  background: rgba(255,255,255,0.2);
  /* Highlight effect */
  box-shadow: inset 0 0 20px rgba(255,255,255,0.4);
}
```

## App Implementation

### SwiftUI
```swift
struct SpatialDesignView: View {
    var body: some View {
        ZStack {
            // Environment background
            Image("room-environment")
                .resizable()
                .aspectRatio(contentMode: .fill)
                .ignoresSafeArea()
            
            // Spatial Panel
            VStack(spacing: 24) {
                Text("Environmental UI")
                    .font(.title).fontWeight(.bold)
                    .foregroundColor(.white)
                
                Button(action: {}) {
                    Text("Interact")
                        .foregroundColor(.white)
                        .padding(.horizontal, 32)
                        .padding(.vertical, 16)
                }
                .background(.ultraThinMaterial)
                .clipShape(Capsule())
                .overlay(Capsule().stroke(Color.white.opacity(0.3), lineWidth: 1))
            }
            .padding(40)
            .background(.ultraThinMaterial) // The core spatial material
            .cornerRadius(32)
            // Specular rim light
            .overlay(
                RoundedRectangle(cornerRadius: 32)
                    .stroke(
                        LinearGradient(
                            colors: [.white.opacity(0.6), .white.opacity(0.1)],
                            startPoint: .topLeading, endPoint: .bottomTrailing
                        ), 
                        lineWidth: 1
                    )
            )
            // Very soft, diffuse shadow
            .shadow(color: .black.opacity(0.1), radius: 40, y: 20)
        }
    }
}
```
- `.background(.ultraThinMaterial)` is exactly what Apple uses for this aesthetic.
- The specular highlight is critical. Use an `.overlay` with a `LinearGradient` stroke to simulate a light source hitting the top-left edge of the glass.

### Flutter
```dart
import 'dart:ui';

class SpatialDesignScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Stack(
        fit: StackFit.expand,
        children: [
          Image.asset('assets/room-environment.jpg', fit: BoxFit.cover),
          
          Center(
            child: ClipRRect(
              borderRadius: BorderRadius.circular(32),
              child: BackdropFilter(
                filter: ImageFilter.blur(sigmaX: 30.0, sigmaY: 30.0),
                child: Container(
                  width: 350,
                  padding: const EdgeInsets.all(40),
                  decoration: BoxDecoration(
                    color: Colors.white.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(32),
                    // Specular rim light
                    border: Border.all(color: Colors.white.withOpacity(0.4), width: 1),
                  ),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    child
