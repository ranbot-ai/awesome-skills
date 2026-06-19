---
name: tile-design
description: Web and App implementation guide for Tile Design. Trigger when user wants Microsoft Metro style, sharp square information units, and horizontal scrolling grids. 
category: Creative & Media
source: antigravity
tags: [react, ai, agent, llm, template, design, image, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/tile-design
---


# Tile Design (Metro UI)

> "Authentically digital. Clean, sharp squares relying purely on typography and flat color."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Sharp Corners**: Absolutely no border-radius. Everything is a perfect square or sharp rectangle.
2. **Live Data**: Tiles flip, scroll, or fade internally to show live updates without the user interacting.
3. **Horizontal Panning**: The grid often expands infinitely to the right, encouraging horizontal scrolling.

## Visual DNA
- **Colors**: High saturation, flat colors. A dark background (pure black) with bright cyan, magenta, orange, and green tiles.
- **Typography**: Extremely clean, light sans-serifs (like `Segoe UI Light`). Text is almost always pure white.
- **Icons**: Simple, wireframe, monochromatic glyphs placed centrally or in the corner.

## Web Implementation
- **CSS Example**:
```css
body {
  background-color: #111;
  color: #fff;
  font-family: 'Segoe UI', sans-serif;
  overflow-x: auto; /* Horizontal scroll */
}

.tile-group {
  display: grid;
  grid-template-columns: repeat(4, 150px);
  grid-auto-rows: 150px;
  gap: 8px;
  padding: 40px;
}

.tile {
  background-color: #0078D7; /* Classic Windows Blue */
  padding: 12px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  cursor: pointer;
  
  /* The "tilt" click effect */
  transition: transform 0.1s;
  transform-origin: center;
}

.tile:active {
  transform: scale(0.95);
}

.tile-wide { grid-column: span 2; }
.tile-large { grid-column: span 2; grid-row: span 2; }

/* Live Tile Animation */
.tile-live-content {
  animation: slideUp 5s infinite;
}

@keyframes slideUp {
  0%, 45% { transform: translateY(0); }
  50%, 95% { transform: translateY(-100%); } /* Slides up to reveal next item */
  100% { transform: translateY(0); }
}
```

## App Implementation

### SwiftUI
```swift
struct TileDesignView: View {
    let rows = [GridItem(.fixed(150), spacing: 8), GridItem(.fixed(150), spacing: 8)]
    
    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            LazyHGrid(rows: rows, spacing: 8) {
                TileView(title: "Mail", color: Color(hex: "0078D7"), icon: "envelope")
                TileView(title: "Photos", color: Color(hex: "00CC6A"), icon: "photo", isLarge: true)
                TileView(title: "Weather", color: Color(hex: "2D7D9A"), icon: "cloud.sun")
                TileView(title: "Calendar", color: Color(hex: "D13438"), icon: "calendar")
            }
            .padding(40)
        }
        .background(Color(hex: "111111").ignoresSafeArea())
    }
}

struct TileView: View {
    let title: String
    let color: Color
    let icon: String
    var isLarge: Bool = false
    
    @State private var isPressed = false
    
    var body: some View {
        VStack(alignment: .leading) {
            Image(systemName: icon)
                .font(.system(size: 32, weight: .light))
                .foregroundColor(.white)
            Spacer()
            Text(title)
                .font(.custom("Segoe UI", size: 16))
                .foregroundColor(.white)
        }
        .padding(16)
        // Sharp corners are mandatory
        .frame(width: isLarge ? 308 : 150, height: isLarge ? 308 : 150, alignment: .leading)
        .background(color)
        .scaleEffect(isPressed ? 0.95 : 1.0)
        .animation(.spring(response: 0.2, dampingFraction: 0.5), value: isPressed)
        .onLongPressGesture(minimumDuration: .infinity, maximumDistance: .infinity, pressing: { pressing in
            isPressed = pressing
        }, perform: {})
    }
}
```
- A `LazyHGrid` inside a horizontal `ScrollView` perfectly replicates the Windows Phone / Windows 8 start screen.
- Absolutely NO corner radius.
- The `isPressed` state triggering a `.scaleEffect(0.95)` replicates the physical "tilt" interaction of Metro tiles.

### Flutter
```dart
class TileDesignScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF111111),
      body: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        padding: const EdgeInsets.all(40),
        child: SizedBox(
          height: 308, // Two rows of 150px + 8px spacing
          child: Wrap(
            direction: Axis.vertical,
            spacing: 8,
            runSpacing: 8,
            children: [
              _buildTile('Mail', const Color(0xFF0078D7), Icons.mail_outline),
              _buildTile('Weather', const Color(0xFF2D7D9A), Icons.cloud_outlined),
              _buildTile('Photos', const Color(0xFF00CC6A), Icons.photo_outlined, isLarge: true),
              _buildTile('Calendar', const Color(0xFFD13438), Icons.calendar_today),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildTile(String tit
