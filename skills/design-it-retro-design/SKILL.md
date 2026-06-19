---
name: retro-design
description: Web and App implementation guide for Retro Design (60s-80s). Trigger when user wants vintage aesthetics, warm muted colors, and nostalgic layouts. 
category: Creative & Media
source: antigravity
tags: [react, ai, llm, design, image, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/retro-design
---


# Retro Design

> "A warm, analog feeling. Nostalgia through muted tones, grain, and classic typography."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Warm, Analog Color Palettes**: Colors look faded by the sun or printed on aged paper.
2. **Texture and Noise**: A slight grain overlay to simulate film or old print media.
3. **Classic Typography Pairings**: Heavy, groovy display fonts paired with typewriter or classic serif body copy.

## Visual DNA
- **Colors**: **Monochromatic Brown** or warm, faded palettes (mustard yellow, burnt orange, sage green, off-white).
- **Typography**: Display fonts like `Cooper Black`, `Garamond`, or `Courier`.
- **Styling**: Badges, stamps, wavy borders, and halftone patterns.

## Web Implementation
- Use CSS filters and background noise images to create texture.
- **CSS Example**:
```css
body {
  background-color: #F4E8D1; /* Aged paper */
  color: #3E2723; /* Deep brown ink */
  font-family: 'Georgia', serif;
  
  /* Apply a subtle noise overlay using a pseudo-element or background image */
  background-image: url('noise-texture.png');
  background-blend-mode: multiply;
}

.retro-header {
  font-family: 'Cooper Black', serif;
  font-size: 4rem;
  color: #D35400; /* Burnt orange */
  text-shadow: 2px 2px 0px #F1C40F; /* Mustard yellow drop shadow */
  letter-spacing: -1px;
}

.retro-card {
  background-color: #FFF3E0;
  border: 2px solid #3E2723;
  border-radius: 12px;
  padding: 24px;
  
  /* Vintage offset shadow */
  box-shadow: 8px 8px 0px #795548;
}

.retro-badge {
  display: inline-block;
  background-color: #E74C3C;
  color: #F4E8D1;
  font-family: monospace;
  font-weight: bold;
  padding: 8px 16px;
  border-radius: 50%; /* Make it look like a sticker */
  transform: rotate(-10deg);
}
```

## App Implementation

### SwiftUI
```swift
struct RetroCard: View {
    let paperColor = Color(red: 0.96, green: 0.91, blue: 0.82) // #F4E8D1
    let inkColor = Color(red: 0.24, green: 0.15, blue: 0.14) // #3E2723
    
    var body: some View {
        ZStack {
            paperColor.ignoresSafeArea()
            
            // Optional: Noise texture
            Image("film_grain")
                .resizable()
                .blendMode(.multiply)
                .opacity(0.3)
                .ignoresSafeArea()
            
            VStack(alignment: .leading, spacing: 24) {
                Text("RETRO DESIGN")
                    .font(.custom("Cooper Black", size: 36))
                    .foregroundColor(Color(red: 0.83, green: 0.33, blue: 0.0)) // #D35400
                    .shadow(color: Color(red: 0.95, green: 0.77, blue: 0.06), radius: 0, x: 2, y: 2)
                
                Text("Analog warmth and classic typography.")
                    .font(.custom("Georgia", size: 18))
                    .foregroundColor(inkColor)
            }
            .padding(32)
            .background(Color(red: 1.0, green: 0.95, blue: 0.88))
            .cornerRadius(12)
            .overlay(
                RoundedRectangle(cornerRadius: 12)
                    .stroke(inkColor, lineWidth: 2)
            )
            // Vintage solid offset shadow
            .shadow(color: Color(red: 0.47, green: 0.33, blue: 0.28), radius: 0, x: 8, y: 8)
        }
    }
}
```
- A grain texture image can be overlaid using `.blendMode(.multiply)`. Be aware of memory usage with full-screen textures.
- Use `.shadow(radius: 0)` to create the hard offset shadows typical of 70s print media.
- Custom fonts like Cooper Black are absolutely required.

### Flutter
```dart
class RetroCard extends StatelessWidget {
  final Color paperColor = const Color(0xFFF4E8D1);
  final Color inkColor = const Color(0xFF3E2723);

  @override
  Widget build(BuildContext context) {
    return Container(
      color: paperColor,
      child: Stack(
        fit: StackFit.expand,
        children: [
          // Noise texture
          Opacity(
            opacity: 0.3,
            child: Image.asset('assets/film_grain.png', 
              fit: BoxFit.cover, 
              colorBlendMode: BlendMode.multiply),
          ),
          Center(
            child: Container(
              padding: const EdgeInsets.all(32),
              decoration: BoxDecoration(
                color: const Color(0xFFFFF3E0),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: inkColor, width: 2),
                boxShadow: const [
                  BoxShadow(
                    color: Color(0xFF795548),
                    blurRadius: 0, // Hard offset shadow
                    offset: Offset(8, 8),
                  ),
                ],
              ),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
      
