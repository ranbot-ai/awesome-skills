---
name: vibrant-maximalism
description: Web and App implementation guide for Vibrant Maximalism. Trigger when user wants rich colors, dense layouts, extreme sensory input, and "more is more". 
category: Creative & Media
source: antigravity
tags: [react, ai, llm, design, image, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/vibrant-maximalism
---


# Vibrant Maximalism

> "More is more. An explosion of color, pattern, and typography."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Sensory Overload**: Every pixel is doing something. Patterns on top of gradients on top of photos.
2. **Clashing Colors**: Forget the standard rules of color harmony. Pair neon green with hot pink, or bright orange with electric blue.
3. **Multiple Fonts**: Mix 3 or 4 completely different typefaces in the same layout.

## Visual DNA
- **Colors**: All of them. Highly saturated, unmuted hues. No calm neutrals allowed.
- **Typography**: A chaotic mix. A massive serif headline, a bubble-letter subhead, and a monospace body text.
- **Visuals**: Stickers, repeating patterns, emojis, 3D renders, and marquee scrolling text.

## Web Implementation
- **CSS Example**:
```css
body {
  /* Complex clashing background */
  background: 
    radial-gradient(circle at 20% 30%, #FF00FF 0%, transparent 40%),
    radial-gradient(circle at 80% 70%, #00FFFF 0%, transparent 40%),
    url('checkerboard-pattern.png') repeat;
  background-color: #FFFF00;
  color: #000;
  overflow-x: hidden;
}

.max-headline {
  font-family: 'Anton', sans-serif;
  font-size: 8rem;
  text-transform: uppercase;
  line-height: 0.8;
  color: #FF0000;
  /* Crazy shadow effect */
  text-shadow: 
    4px 4px 0px #000,
    8px 8px 0px #00FFFF,
    12px 12px 0px #FF00FF;
  transform: rotate(-3deg);
}

.max-sticker {
  position: absolute;
  background: #000;
  color: #00FF00;
  font-family: monospace;
  padding: 10px;
  border-radius: 50%;
  width: 100px;
  height: 100px;
  display: flex;
  align-items: center;
  justify-content: center;
  text-align: center;
  border: 4px dashed #FF00FF;
  animation: spin 10s linear infinite;
}

@keyframes spin { 100% { transform: rotate(360deg); } }

.max-card {
  background: rgba(255, 255, 255, 0.9);
  border: 5px solid #000;
  box-shadow: 10px 10px 0px #0000FF;
  padding: 40px;
  border-radius: 0 40px 0 40px; /* Weird asymmetrical corners */
}
```

## App Implementation

### SwiftUI
```swift
struct VibrantMaximalismView: View {
    var body: some View {
        ScrollView {
            ZStack {
                // Chaotic Layered Background
                Color(hex: "FFFF00").ignoresSafeArea() // Pure Yellow
                
                Circle()
                    .fill(RadialGradient(colors: [Color(hex: "FF00FF"), .clear], center: .center, startRadius: 0, endRadius: 200))
                    .frame(width: 400, height: 400)
                    .offset(x: -100, y: -200)
                
                Circle()
                    .fill(RadialGradient(colors: [Color(hex: "00FFFF"), .clear], center: .center, startRadius: 0, endRadius: 200))
                    .frame(width: 400, height: 400)
                    .offset(x: 150, y: 200)
                
                // Content
                VStack(spacing: 40) {
                    Text("OVERLOAD")
                        .font(.custom("Anton", size: 80))
                        .foregroundColor(Color(hex: "FF0000"))
                        .shadow(color: .black, radius: 0, x: 4, y: 4)
                        .shadow(color: Color(hex: "00FFFF"), radius: 0, x: 8, y: 8)
                        .rotationEffect(.degrees(-3))
                    
                    // Weird shaped card
                    VStack {
                        Text("More is more.")
                            .font(.system(size: 24, weight: .black, design: .monospaced))
                    }
                    .padding(40)
                    .background(Color.white.opacity(0.9))
                    .border(.black, width: 5)
                    .cornerRadius(40, corners: [.topRight, .bottomLeft]) // Custom corner radius extension needed
                    .shadow(color: Color(hex: "0000FF"), radius: 0, x: 10, y: 10)
                }
            }
        }
    }
}
```
- Layer multiple `RadialGradient`s in a `ZStack` behind the content to create the complex, clashing color blobs.
- Use multiple hard drop shadows (radius 0, but large X/Y offsets) in clashing colors to build the loud text effect.

### Flutter
```dart
class VibrantMaximalismScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Stack(
        children: [
          // Background Color
          Container(color: const Color(0xFFFFFF00)),
          // Gradient Blob 1
          Positioned(
            top: -100, left: -100,
            child: Container(
              width: 400, height: 400,
              decoration: const BoxDecoration(
                shape: BoxShape.circle,
                gradient: RadialGradient(colors: [Color(0xFFFF00FF), Colors.transparent]),
              ),
            ),
          ),
          
          Center(
            child: Column(
     
