---
name: vaporwave
description: Web and App implementation guide for Vaporwave. Trigger when user wants neon colors, retro digital aesthetics, 90s OS elements, and Roman statues. 
category: Creative & Media
source: antigravity
tags: [react, ai, agent, llm, design, aws, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/vaporwave
---


# Vaporwave

> "A surreal, nostalgic dream of 90s computing and pastel neon."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Windows 95 / Mac OS 9 Motifs**: UI elements designed to look explicitly like 1990s operating systems (grey boxes, hard bevels, blue title bars).
2. **Surreal Pastels & Neons**: A mix of soft pinks, cyans, and harsh neon overlays.
3. **Collage Aesthetic**: Mixing classical art (Roman busts), early 3D renders (checkerboard floors), and Japanese text (Kanji/Katakana).

## Visual DNA
- **Colors**: Cyan (`#00FFFF`), Magenta (`#FF00FF`), Lavender (`#E6E6FA`), and classic Windows Grey (`#C0C0C0`).
- **Typography**: `MS Sans Serif`, `Tahoma`, or pixel fonts. Fullwidth characters (ＡＥＳＴＨＥＴＩＣ) are highly encouraged for headers.
- **Styling**: Hard, 1px outsets and insets to simulate 90s 3D buttons.

## Web Implementation
- Use standard CSS borders to create the classic 90s button look.
- **CSS Example**:
```css
body {
  background: linear-gradient(180deg, #ff99cc 0%, #99ccff 100%);
  color: #000;
  font-family: 'Tahoma', sans-serif;
  min-height: 100vh;
}

/* Windows 95 Style Window */
.vapor-window {
  background-color: #C0C0C0;
  border: 2px outset #fff;
  border-right-color: #808080;
  border-bottom-color: #808080;
  width: 400px;
  padding: 2px;
}

.vapor-titlebar {
  background: linear-gradient(90deg, #000080, #1084d0);
  color: white;
  font-weight: bold;
  padding: 4px 8px;
  display: flex;
  justify-content: space-between;
}

.vapor-button {
  background-color: #C0C0C0;
  border: 2px outset #fff;
  border-right-color: #808080;
  border-bottom-color: #808080;
  padding: 4px 12px;
}
.vapor-button:active {
  border-style: inset;
}

/* The iconic vaporwave sun/grid */
.vapor-sun {
  width: 200px; height: 200px;
  background: linear-gradient(to bottom, #ff00ff, #ffff00);
  border-radius: 50%;
  box-shadow: 0 0 20px #ff00ff;
}
```

## App Implementation

### SwiftUI
```swift
struct VaporwaveView: View {
    var body: some View {
        ZStack {
            // Neon Gradient Background
            LinearGradient(colors: [Color(hex: "ff99cc"), Color(hex: "99ccff")], startPoint: .top, endPoint: .bottom)
                .ignoresSafeArea()
            
            // Win95 Window
            VStack(spacing: 0) {
                // Title Bar
                HStack {
                    Text("ＡＥＳＴＨＥＴＩＣ.exe")
                        .font(.system(size: 14, weight: .bold, design: .monospaced))
                        .foregroundColor(.white)
                    Spacer()
                    Text("X")
                        .font(.system(size: 12, weight: .bold))
                        .padding(.horizontal, 6)
                        .background(Color(hex: "C0C0C0"))
                        .border(.white, width: 1) // Faux 3D
                }
                .padding(4)
                .background(LinearGradient(colors: [Color(hex: "000080"), Color(hex: "1084d0")], startPoint: .leading, endPoint: .trailing))
                
                // Content
                VStack {
                    Text("It's all in your head.")
                        .font(.custom("Tahoma", size: 16))
                        .padding()
                    
                    // Win95 Button
                    Button(action: {}) {
                        Text("ＯＫ")
                            .foregroundColor(.black)
                            .padding(.horizontal, 24)
                            .padding(.vertical, 8)
                    }
                    .background(Color(hex: "C0C0C0"))
                    // Complex borders to simulate Outset
                    .overlay(
                        Rectangle().stroke(Color.black, lineWidth: 1) // Outer bottom/right
                    )
                    .overlay(
                        Rectangle().stroke(Color.white, lineWidth: 1).padding(1) // Inner top/left
                    )
                }
                .frame(maxWidth: .infinity)
                .padding(16)
                .background(Color(hex: "C0C0C0"))
            }
            .frame(width: 300)
            // Outset border for window
            .border(Color(hex: "808080"), width: 2)
            .padding()
        }
    }
}
```
- You cannot use `.cornerRadius()` anywhere in Vaporwave design.
- The Win95 3D bevel is achieved by stacking `.border()` and `.overlay(Rectangle().stroke())` with different colors (white for top/left, dark gray for bottom/right).

### Flutter
```dart
class VaporwaveScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(begin: Alignment.topCenter, end: Alignment.bottomCenter, colors: [Color(0xFFFF99CC), Color(0xFF99CCFF)]),
        ),
        child:
