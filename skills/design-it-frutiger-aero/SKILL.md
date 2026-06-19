---
name: frutiger-aero
description: Web and App implementation guide for Frutiger Aero. Trigger when user wants glossy gradients, early 2000s nature-inspired tech, glass, and water motifs. 
category: Creative & Media
source: antigravity
tags: [react, ai, llm, design, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/frutiger-aero
---


# Frutiger Aero

> "The aesthetic of mid-2000s optimism. Glossy plastic, clear water, blue skies, and eco-friendly technology."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Hyper-Glossy Textures**: Buttons look like polished glass or wet plastic. Extensive use of convex gradients and specular highlights.
2. **Skeuomorphic Nature**: Motifs of green grass, blue skies, water droplets, and bubbles intersecting with sleek glass technology (think Windows Aero or early iOS).
3. **Translucency**: Frosted glass effects, but much more saturated and reflective than modern glassmorphism.

## Visual DNA
- **Colors**: Cyan, sky blue, lime green, and pure white. Avoid dark themes entirely.
- **Typography**: Clean, highly legible humanist sans-serifs (like the font *Frutiger*, `Segoe UI`, or `Myriad Pro`).
- **Styling**: Drop shadows are deep. Highlights are bright, sharp white lines at the top of buttons.

## Web Implementation
- Use multiple box-shadows (inset for the gloss, outset for depth) and linear-gradients.
- **CSS Example**:
```css
body {
  /* Classic blue sky / green grass gradient */
  background: linear-gradient(to bottom, #87CEEB 0%, #E0F6FF 60%, #98FB98 100%);
  font-family: 'Segoe UI', Tahoma, sans-serif;
}

.aero-btn {
  background: linear-gradient(to bottom, #73c8f8 0%, #1583d7 50%, #0361a3 50%, #299eef 100%);
  color: white;
  border: 1px solid #024b7f;
  border-radius: 20px;
  padding: 12px 32px;
  font-weight: 600;
  text-shadow: 0 -1px 1px rgba(0,0,0,0.5);
  
  /* The Glossy Highlight and Depth */
  box-shadow: 
    inset 0 1px 1px rgba(255,255,255,0.8), /* Top edge highlight */
    inset 0 15px 15px rgba(255,255,255,0.3), /* Convex plastic shine */
    0 4px 6px rgba(0,0,0,0.2); /* Drop shadow */
}

.aero-panel {
  /* Windows Vista/7 Aero Glass */
  background: rgba(255, 255, 255, 0.4);
  backdrop-filter: blur(10px);
  border: 1px solid rgba(255, 255, 255, 0.8);
  border-top-color: #ffffff; /* Brighter top edge */
  border-radius: 8px;
  box-shadow: 0 10px 20px rgba(0,0,0,0.1);
}
```

## App Implementation

### SwiftUI
```swift
struct FrutigerAeroView: View {
    var body: some View {
        ZStack {
            // Classic sky to grass gradient
            LinearGradient(
                colors: [Color(hex: "87CEEB"), Color(hex: "E0F6FF"), Color(hex: "98FB98")],
                startPoint: .top, endPoint: .bottom
            ).ignoresSafeArea()
            
            // Glossy Button
            Button(action: {}) {
                Text("Windows Vista")
                    .font(.headline)
                    .foregroundColor(.white)
                    .shadow(color: .black.opacity(0.5), radius: 1, y: -1) // Inset text shadow effect
                    .padding(.horizontal, 40)
                    .padding(.vertical, 16)
                    .background(
                        // Base gradient
                        LinearGradient(
                            stops: [
                                .init(color: Color(hex: "73c8f8"), location: 0.0),
                                .init(color: Color(hex: "1583d7"), location: 0.5),
                                .init(color: Color(hex: "0361a3"), location: 0.5), // Sharp color stop
                                .init(color: Color(hex: "299eef"), location: 1.0)
                            ],
                            startPoint: .top, endPoint: .bottom
                        )
                    )
                    .cornerRadius(25)
                    .overlay(
                        // Top white specular highlight
                        RoundedRectangle(cornerRadius: 25)
                            .stroke(
                                LinearGradient(colors: [.white, .clear], startPoint: .top, endPoint: .bottom),
                                lineWidth: 1.5
                            )
                    )
                    .shadow(color: .black.opacity(0.3), radius: 5, y: 4)
            }
        }
    }
}
// Note: Color(hex:) requires a custom extension in SwiftUI.
```
- The signature Frutiger Aero "gel" look requires a sharp color transition right in the middle. Set two gradient stops at `0.5` with different colors.
- An `.overlay` with a top-down white-to-clear gradient stroke creates the glass highlight edge.

### Flutter
```dart
class FrutigerAeroScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        // Sky/Grass background
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter, end: Alignment.bottomCenter,
            colors: [Color(0xFF87CEEB), Color(0xFFE0F6FF), Color(0xFF98FB98)],
          ),
        ),
        child: Center(
          child: Container(
            decoration: BoxDecoration(
             
