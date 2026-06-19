---
name: typography-first
description: Web and App implementation guide for Typography First Design. Trigger when user wants text as the absolute main visual element, with minimal UI chroming. 
category: Creative & Media
source: antigravity
tags: [react, ai, llm, design, aws, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/typography-first
---


# Typography First Design

> "The words are the interface. No distractions, just beautiful text."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Hyper-Sized Typography**: The main headline is so large it becomes an abstract graphic element.
2. **Minimal UI Chroming**: Buttons are just text. Navigation is just text. No boxes, no backgrounds.
3. **Kinetic Typography**: Text that moves, scrolls, or reacts to the user's cursor.

## Visual DNA
- **Colors**: Extreme high contrast. Pure black and white, or a very dark background with a single neon accent color. **Midnight Luxury** works well.
- **Typography**: Display fonts with extreme character. Try `Oswald`, `Anton`, or `Bebas Neue` for impact, or a massive serif.
- **Layout**: Often centers the massive text perfectly in the viewport, cutting off at the edges.

## Web Implementation
- Rely on `vw` and `vh` units for font sizing so the text perfectly fills the screen.
- **CSS Example**:
```css
body {
  background-color: #0A0A0A;
  color: #F5F5F0;
  overflow-x: hidden;
  margin: 0;
}

.hero-type {
  font-family: 'Anton', sans-serif;
  font-size: 25vw; /* Fills the width of the screen */
  text-transform: uppercase;
  line-height: 0.8;
  white-space: nowrap;
  
  /* Outline effect */
  color: transparent;
  -webkit-text-stroke: 2px #F5F5F0;
  transition: color 0.3s;
}

.hero-type:hover {
  color: var(--cta-highlight);
  -webkit-text-stroke: 0;
}

.nav-text-btn {
  background: none;
  border: none;
  color: #F5F5F0;
  font-size: 2rem;
  font-family: 'Helvetica Neue', sans-serif;
  text-decoration: underline;
  text-underline-offset: 8px;
  cursor: pointer;
}
```

## App Implementation

### SwiftUI
```swift
struct TypographyFirstView: View {
    var body: some View {
        ZStack {
            Color(hex: "0A0A0A").ignoresSafeArea()
            
            VStack {
                // Massive Typography Bleeding Off Edge
                Text("THE WORDS ARE THE INTERFACE")
                    .font(.custom("Anton", size: 200)) // Absurdly large
                    .foregroundColor(Color(hex: "F5F5F0"))
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false) // Force no wrapping
                    .minimumScaleFactor(1.0) // Prevent auto-shrinking
                
                // Outlined variant
                Text("NO CHROMING")
                    .font(.custom("Anton", size: 150))
                    .foregroundColor(.clear)
                    .overlay(
                        Text("NO CHROMING")
                            .font(.custom("Anton", size: 150))
                            .foregroundColor(Color(hex: "0A0A0A"))
                            // Hack for text stroke in SwiftUI
                            .shadow(color: Color(hex: "F5F5F0"), radius: 1)
                    )
                    .lineLimit(1)
                    .fixedSize()
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.leading, -20) // Intentionally cut off
        }
    }
}
```
- Use `.fixedSize(horizontal: true, vertical: false)` and `.lineLimit(1)` to force massive fonts to bleed off the edge of the screen rather than wrapping into a paragraph.
- Native text-stroke is difficult in SwiftUI; overlapping a masked text or using thin shadows is the common workaround.

### Flutter
```dart
class TypographyFirstScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0A0A0A),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Auto-scaling hero text
            FittedBox(
              fit: BoxFit.cover,
              child: Text(
                'THE WORDS ARE',
                style: TextStyle(fontFamily: 'Anton', color: const Color(0xFFF5F5F0), height: 0.8),
              ),
            ),
            
            // Outlined text
            FittedBox(
              fit: BoxFit.cover,
              child: Stack(
                children: [
                  // Outline
                  Text(
                    'THE INTERFACE',
                    style: TextStyle(
                      fontFamily: 'Anton', height: 0.8,
                      foreground: Paint()..style = PaintingStyle.stroke..strokeWidth = 2..color = const Color(0xFFF5F5F0),
                    ),
                  ),
                  // Solid fill (transparent)
                  const Text('THE INTERFACE', style: TextStyle(fontFamily: 'Anton', height: 0.8, color: Colors.transparent)),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
```
- `FittedBox` with `BoxFit.cover` is your best f
