---
name: sci-fi-interface
description: Web and App implementation guide for Sci-Fi Interface Design. Trigger when user wants HUDs, spacecraft dashboards, or tactical military readouts. 
category: Creative & Media
source: antigravity
tags: [react, ai, llm, design]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/sci-fi-interface
---


# Sci-Fi Interface Design (HUD)

> "Heads-Up Display. Tactical, precise, and highly analytical."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Wireframe and Outlines**: Interfaces are built almost entirely out of thin strokes rather than solid filled boxes.
2. **Circular Arrays & Radars**: Heavy use of concentric circles, radar sweeps, and curved progress bars.
3. **Monochrome + Warning**: Often entirely monochromatic (just blue, or just green) with a secondary color (red) used exclusively for alerts.

## Visual DNA
- **Colors**: Midnight background. UI is pure Cyan, Emerald Green, or Amber (like classic monochrome monitors). **Minimalist Slate** works if made dark.
- **Typography**: Strict, technical monospace fonts (`Share Tech Mono`, `VT323`, `Space Mono`). All caps.
- **Styling**: Tiny UI chroming details (target brackets `[ ]`, framing lines, precise pixel coordinates).

## Web Implementation
- Heavy use of SVG for circular dials, and CSS borders for the layout.
- **CSS Example**:
```css
body {
  background-color: #000b18; /* Deep space navy */
  color: #4df; /* Holographic cyan */
  font-family: 'Share Tech Mono', monospace;
  text-transform: uppercase;
}

/* The HUD Frame */
.hud-container {
  border: 1px solid rgba(68, 221, 255, 0.3);
  position: relative;
  padding: 30px;
}

/* Corner brackets */
.hud-container::before {
  content: '';
  position: absolute;
  top: -2px; left: -2px;
  width: 20px; height: 20px;
  border-top: 2px solid #4df;
  border-left: 2px solid #4df;
}
.hud-container::after {
  content: '';
  position: absolute;
  bottom: -2px; right: -2px;
  width: 20px; height: 20px;
  border-bottom: 2px solid #4df;
  border-right: 2px solid #4df;
}

.hud-value {
  font-size: 3rem;
  text-shadow: 0 0 10px rgba(68, 221, 255, 0.8);
}

.hud-warning {
  color: #ff3333;
  text-shadow: 0 0 10px rgba(255, 51, 51, 0.8);
  animation: blink 1s step-end infinite;
}

@keyframes blink { 50% { opacity: 0; } }
```

## App Implementation

### SwiftUI
```swift
struct SciFiHUDView: View {
    @State private var bootUp = false
    
    var body: some View {
        ZStack {
            Color(hex: "000b18").ignoresSafeArea() // Deep space navy
            
            VStack {
                // Circular Radar/Dial
                ZStack {
                    Circle()
                        .stroke(Color(hex: "4df").opacity(0.3), lineWidth: 1)
                    
                    Circle()
                        .trim(from: 0.0, to: bootUp ? 0.75 : 0.0)
                        .stroke(Color(hex: "4df"), style: StrokeStyle(lineWidth: 4, lineCap: .round))
                        .rotationEffect(.degrees(-90))
                    
                    Text("SYS.OK")
                        .font(.custom("Space Mono", size: 24))
                        .foregroundColor(Color(hex: "4df"))
                        .shadow(color: Color(hex: "4df"), radius: 5)
                }
                .frame(width: 200, height: 200)
                .padding(.bottom, 40)
                
                // HUD Data Frame
                HStack {
                    Text("COORD: 45.22, 12.8")
                    Spacer()
                    Text("[ LOCK ]")
                }
                .font(.custom("Space Mono", size: 16))
                .foregroundColor(Color(hex: "4df"))
                .padding()
                .border(Color(hex: "4df").opacity(0.5), width: 1)
                .overlay(
                    // Corner bracket accents
                    Path { path in
                        path.move(to: CGPoint(x: 0, y: 15)); path.addLine(to: CGPoint(x: 0, y: 0)); path.addLine(to: CGPoint(x: 15, y: 0))
                        path.move(to: CGPoint(x: 300, y: 15)); path.addLine(to: CGPoint(x: 300, y: 0)); path.addLine(to: CGPoint(x: 285, y: 0))
                    }
                    .stroke(Color(hex: "4df"), lineWidth: 2)
                )
            }
            .padding()
        }
        .onAppear {
            withAnimation(.easeInOut(duration: 2.0)) { bootUp = true }
        }
    }
}
```
- SwiftUI is uniquely fantastic for Sci-Fi HUDs. `Circle().trim(from: to:)` lets you build complex sweeping circular progress rings.
- Use `Path` overlays to draw the exact 90-degree corner brackets (`[ ]`) that define the HUD look.

### Flutter
```dart
class SciFiHUDScreen extends StatefulWidget {
  @override
  State<SciFiHUDScreen> createState() => _SciFiHUDScreenState();
}

class _SciFiHUDScreenState extends State<SciFiHUDScreen> with SingleTickerProviderStateMixin {
  late AnimationController _ctrl;

  @override
  void initState() {
    super.initState();
    _ctrl = AnimationController(vsync: this, duration: const Duration(seconds: 2))..forward();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: co
