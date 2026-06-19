---
name: cyberpunk-ui
description: Web and App implementation guide for Cyberpunk UI. Trigger when user wants neon colors, dark backgrounds, high-tech dystopian aesthetics, and hacking interfaces. 
category: Creative & Media
source: antigravity
tags: [react, ai, design, image, hacking, stripe, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/cyberpunk-ui
---


# Cyberpunk UI

> "High tech, low life. Neon signs cutting through the smog of a dystopian megacity."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Neon on Black**: The foundation is absolute black (`#000000`) or deep charcoal, cut by searingly bright neon accents.
2. **Angled Geometries**: Clipped corners (chamfers) rather than rounded corners. UI elements often look like they were cut from metal plates.
3. **Glitch and Data**: Random streams of hexadecimal data, barcode accents, and intentional visual tearing.

## Visual DNA
- **Colors**: Acid Yellow (`#FCE205`), Cyan (`#00FFFF`), Hot Pink (`#FF003C`), against Black. 
- **Typography**: Industrial, squared-off sans-serifs (like `Rajdhani`, `Blender Pro`, or `Teko`), mixed with small monospace fonts for data.
- **Styling**: Diagonal stripes, warning tape patterns, and heavy outer glows.

## Web Implementation
- Rely on `clip-path` for the angled cuts.
- **CSS Example**:
```css
body {
  background-color: #050505;
  color: #00FFFF;
  font-family: 'Rajdhani', sans-serif;
  background-image: repeating-linear-gradient(
    45deg,
    #050505,
    #050505 10px,
    #0a0a0a 10px,
    #0a0a0a 20px
  );
}

.cyberpunk-button {
  background-color: #FF003C; /* Cyberpunk Red/Pink */
  color: #FFF;
  font-size: 1.5rem;
  font-weight: bold;
  text-transform: uppercase;
  border: none;
  padding: 16px 32px;
  
  /* The signature clipped corner */
  clip-path: polygon(
    0 0, 
    calc(100% - 15px) 0, 
    100% 15px, 
    100% 100%, 
    15px 100%, 
    0 calc(100% - 15px)
  );
  
  position: relative;
  transition: all 0.2s ease;
}

/* The glitch/shadow effect */
.cyberpunk-button:hover {
  background-color: #FCE205; /* Acid Yellow */
  color: #000;
  box-shadow: 
    -4px 0 0 #00FFFF,
    4px 0 0 #FF003C;
}

.data-stream {
  font-family: monospace;
  font-size: 0.8rem;
  color: rgba(0, 255, 255, 0.5);
}
```

## App Implementation

### SwiftUI
```swift
struct CyberpunkShape: Shape {
    let cutSize: CGFloat = 15
    func path(in rect: CGRect) -> Path {
        var path = Path()
        // Top left
        path.move(to: CGPoint(x: 0, y: 0))
        // Top right (cut)
        path.addLine(to: CGPoint(x: rect.maxX - cutSize, y: 0))
        path.addLine(to: CGPoint(x: rect.maxX, y: cutSize))
        // Bottom right
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY))
        // Bottom left (cut)
        path.addLine(to: CGPoint(x: cutSize, y: rect.maxY))
        path.addLine(to: CGPoint(x: 0, y: rect.maxY - cutSize))
        path.closeSubpath()
        return path
    }
}

struct CyberButton: View {
    var body: some View {
        Button(action: {}) {
            Text("SYS.OVERRIDE")
                .font(.custom("Rajdhani", size: 24))
                .fontWeight(.bold)
                .foregroundColor(.white)
                .padding(.horizontal, 32)
                .padding(.vertical, 16)
        }
        .background(Color(red: 1.0, green: 0.0, blue: 0.24)) // Cyberpunk Red
        .clipShape(CyberpunkShape())
        .overlay(
            CyberpunkShape()
                .stroke(Color(red: 0.0, green: 1.0, blue: 1.0), lineWidth: 2) // Cyan border
        )
    }
}
```
- Define a custom `Shape` that physically cuts off the corners, bypassing standard `cornerRadius`.
- Use `.clipShape()` for the background, and `.overlay()` with `.stroke()` for high-tech borders.

### Flutter
```dart
class CyberpunkClipper extends CustomClipper<Path> {
  final double cutSize = 15.0;

  @override
  Path getClip(Size size) {
    Path path = Path();
    path.lineTo(size.width - cutSize, 0); // Top right cut start
    path.lineTo(size.width, cutSize);     // Top right cut end
    path.lineTo(size.width, size.height);
    path.lineTo(cutSize, size.height);    // Bottom left cut start
    path.lineTo(0, size.height - cutSize);// Bottom left cut end
    path.close();
    return path;
  }

  @override
  bool shouldReclip(CustomClipper<Path> oldClipper) => false;
}

class CyberButton extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return ClipPath(
      clipper: CyberpunkClipper(),
      child: Container(
        color: const Color(0xFFFF003C), // Cyberpunk Red
        padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 16),
        child: const Text(
          'SYS.OVERRIDE',
          style: TextStyle(
            color: Colors.white,
            fontSize: 24,
            fontWeight: FontWeight.bold,
            fontFamily: 'Rajdhani',
          ),
        ),
      ),
    );
  }
}
```
- Extend `CustomClipper<Path>` to calculate the precise angular cuts.
- Wrap your containers in `ClipPath`. 
- For borders, you must use a `CustomPaint` with a `CustomPainter` that traces the exact same path.

### React Native
```jsx
import Svg, { Polygon } from 'react-native-svg';

const Cybe
