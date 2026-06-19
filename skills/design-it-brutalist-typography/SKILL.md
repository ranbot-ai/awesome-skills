---
name: brutalist-typography
description: Web and App implementation guide for Brutalist Typography. Trigger when user wants huge fonts, raw presentation, and aggressive layout decisions. 
category: Creative & Media
source: antigravity
tags: [react, ai, llm, design, presentation, aws, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/brutalist-typography
---


# Brutalist Typography

> "Aggressive, unpolished, and unapologetic. Text that demands attention by breaking the rules."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Rule Breaking**: Text that overlaps, ignores margins, or deliberately clips off the edge of the screen.
2. **Anti-Design**: Intentional use of system fonts or "ugly" fonts (Times New Roman, Courier) in massive sizes.
3. **Harsh Contrast**: Clashing colors or stark monochrome.

## Visual DNA
- **Colors**: **Industrial Chic** (Black, White, Red) or aggressive neon clashing (e.g., pure blue on pure red).
- **Typography**: System default fonts (`Times New Roman`, `Arial`, `Courier New`) blown up to 150px.
- **Styling**: Marquees, blinking text, underlines that cut through descenders.

## Web Implementation
- Break the grid. Use absolute positioning or negative margins.
- **CSS Example**:
```css
body {
  background-color: #fff;
  color: #000;
  font-family: 'Times New Roman', serif;
}

.brutalist-headline {
  font-size: 15vw;
  line-height: 0.7;
  letter-spacing: -5px;
  margin-left: -10px; /* Bleeds off screen intentionally */
  word-wrap: break-word; /* Let words break awkwardly */
}

.brutalist-highlight {
  background-color: #ff0000;
  color: #fff;
  padding: 0 10px;
}

.marquee-container {
  border-top: 5px solid #000;
  border-bottom: 5px solid #000;
  overflow: hidden;
  white-space: nowrap;
  font-family: 'Courier New', monospace;
  font-size: 2rem;
  font-weight: bold;
  padding: 10px 0;
}

/* A nod to early 90s web */
.brutalist-link {
  color: #0000ee;
  text-decoration: underline;
  text-transform: uppercase;
}
.brutalist-link:hover {
  background-color: #0000ee;
  color: #fff;
}
```

## App Implementation

### SwiftUI
```swift
struct BrutalistTypeView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: -20) {
                // Bleeds off the edge intentionally
                Text("BREAK")
                    .font(.custom("Times New Roman", size: 120))
                    .padding(.leading, -20) 
                
                Text("THE")
                    .font(.custom("Arial", size: 140))
                    .fontWeight(.black)
                    .foregroundColor(.clear)
                    .overlay(
                        Text("THE").stroke(Color.red, lineWidth: 3)
                    )
                    .offset(x: 40)
                
                Text("GRID.")
                    .font(.custom("Courier New", size: 100))
                    .background(Color.blue)
                    .foregroundColor(.white)
                    .rotationEffect(.degrees(-5))
                    .offset(y: -40)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 50)
        }
        .ignoresSafeArea() // Critical for Brutalist type
        .background(Color.white)
    }
}
```
- `.ignoresSafeArea()` is mandatory. Text must be allowed to clip into the notch and status bar.
- Use negative `spacing` in `VStack` or explicit negative `.offset()` to force text elements to overlap each other aggressively.
- Outline text is achieved by setting `.foregroundColor(.clear)` and overlaying a `.stroke()`.

### Flutter
```dart
class BrutalistTypeScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    // Scaffold without SafeArea
    return Scaffold(
      backgroundColor: Colors.white,
      body: Stack(
        children: [
          Positioned(
            top: -20,
            left: -20,
            child: const Text(
              'BREAK',
              style: TextStyle(
                fontFamily: 'Times New Roman',
                fontSize: 150,
                height: 0.8, // Negative line-spacing
                color: Colors.black,
              ),
            ),
          ),
          Positioned(
            top: 100,
            left: 40,
            child: Text(
              'THE',
              style: TextStyle(
                fontFamily: 'Arial',
                fontSize: 140,
                fontWeight: FontWeight.w900,
                foreground: Paint()
                  ..style = PaintingStyle.stroke
                  ..strokeWidth = 3
                  ..color = Colors.red,
              ),
            ),
          ),
          Positioned(
            top: 220,
            left: 10,
            child: Transform.rotate(
              angle: -0.1,
              child: Container(
                color: Colors.blue,
                child: const Text(
                  'GRID.',
                  style: TextStyle(
                    fontFamily: 'Courier',
                    fontSize: 120,
                    color: Colors.white,
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
   
