---
name: cyber-y2k
description: Web and App implementation guide for Cyber Y2K. Trigger when user wants modern Y2K, holographic visuals, and glitch aesthetics. 
category: Creative & Media
source: antigravity
tags: [react, node, ai, agent, llm, design, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/cyber-y2k
---


# Cyber Y2K

> "Y2K, but seen through a distorted, modern lens. Darker, glitchier, and highly holographic."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Holographic Gradients**: Iridescent, oil-slick color palettes that shift as you move.
2. **Glitch Art**: Text or images that appear corrupted, split into RGB channels, or stutter.
3. **Tribal & Tribal-Tech Vectors**: Sharp, aggressive vector graphics (think early 2000s tribal tattoos mixed with circuit boards).

## Visual DNA
- **Colors**: Deep black background. Highlights are holographic (purple, cyan, lime green, hot pink all mixed into fluid gradients).
- **Typography**: Extremely bold, stretched fonts, or highly technical monospace fonts.
- **Visuals**: CD-ROM reflections, barbed wire graphics, and heavy chromatic aberration.

## Web Implementation
- Use CSS animations for glitching and animated background gradients.
- **CSS Example**:
```css
body {
  background-color: #050505;
  color: #fff;
}

/* Holographic button */
.cyber-y2k-btn {
  background: linear-gradient(124deg, #ff2400, #e81d1d, #e8b71d, #e3e81d, #1de840, #1ddde8, #2b1de8, #dd00f3, #dd00f3);
  background-size: 1800% 1800%;
  animation: rainbow 18s ease infinite;
  
  color: #fff;
  font-weight: 900;
  text-transform: uppercase;
  border: 1px solid rgba(255,255,255,0.5);
  border-radius: 30px;
  padding: 16px 32px;
  mix-blend-mode: screen; /* Makes it interact with background */
}

@keyframes rainbow { 
  0%{background-position:0% 82%}
  50%{background-position:100% 19%}
  100%{background-position:0% 82%}
}

/* RGB Split text effect */
.glitch-text {
  position: relative;
  font-family: 'Courier New', monospace;
  font-size: 3rem;
  font-weight: bold;
}
.glitch-text::before, .glitch-text::after {
  content: attr(data-text);
  position: absolute;
  top: 0; left: 0;
  opacity: 0.8;
}
.glitch-text::before {
  color: #0ff;
  z-index: -1;
  transform: translate(-3px, 2px);
}
.glitch-text::after {
  color: #f0f;
  z-index: -2;
  transform: translate(3px, -2px);
}
```

## App Implementation

### SwiftUI
```swift
struct CyberY2KView: View {
    @State private var rotation: Double = 0
    
    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            
            VStack(spacing: 40) {
                // Glitch Text
                ZStack {
                    Text("SYSTEM.ERROR")
                        .font(.custom("Courier New", size: 40).bold())
                        .foregroundColor(.cyan)
                        .offset(x: -3, y: 2) // RGB split channel 1
                    
                    Text("SYSTEM.ERROR")
                        .font(.custom("Courier New", size: 40).bold())
                        .foregroundColor(.pink)
                        .offset(x: 3, y: -2) // RGB split channel 2
                    
                    Text("SYSTEM.ERROR")
                        .font(.custom("Courier New", size: 40).bold())
                        .foregroundColor(.white)
                }
                
                // Holographic Button
                Button(action: {}) {
                    Text("ENTER MATRIX")
                        .font(.headline.weight(.black))
                        .foregroundColor(.white)
                        .padding(.horizontal, 32)
                        .padding(.vertical, 16)
                        .background(
                            AngularGradient(
                                gradient: Gradient(colors: [.red, .yellow, .green, .cyan, .blue, .purple, .red]),
                                center: .center,
                                angle: .degrees(rotation)
                            )
                        )
                        .cornerRadius(30)
                        .overlay(RoundedRectangle(cornerRadius: 30).stroke(Color.white.opacity(0.5), lineWidth: 1))
                }
                .onAppear {
                    withAnimation(.linear(duration: 5).repeatForever(autoreverses: false)) {
                        rotation = 360
                    }
                }
            }
        }
    }
}
```
- The RGB Glitch effect is incredibly simple in SwiftUI: stack three identical `Text` views in a `ZStack`. Give the bottom ones `.cyan` and `.pink` colors and slightly `.offset()` them.
- Use an `AngularGradient` bound to a rotating `@State` variable to achieve the iridescent CD-ROM holographic effect.

### Flutter
```dart
class CyberY2KScreen extends StatefulWidget {
  @override
  State<CyberY2KScreen> createState() => _CyberY2KScreenState();
}

class _CyberY2KScreenState extends State<CyberY2KScreen> with SingleTickerProviderStateMixin {
  late AnimationController _controller;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(vsync: this, duration: const Duration(
