---
name: retro-futurism
description: Web and App implementation guide for Retro Futurism. Trigger when user wants vintage future concepts, 1950s space age aesthetics, or atompunk vibes. 
category: Creative & Media
source: antigravity
tags: [react, ai, design, stripe, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/retro-futurism
---


# Retro Futurism

> "The future as imagined in the 1950s and 60s. Rockets, atoms, and sleek, aerodynamic chrome."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Aerodynamic Shapes**: Lots of sweeping curves, teardrop shapes, and swooping lines. Nothing is a perfect square.
2. **Space-Age Motifs**: Stars, atoms, orbits, and fins (like a 1950s Cadillac).
3. **Mid-Century Colors mixed with Chrome**: Classic 50s pastels paired with shiny, reflective metals.

## Visual DNA
- **Colors**: Turquoise (`#40E0D0`), Atomic Tangerine (`#FF9966`), Mint Green (`#98FF98`), paired with Silver/Chrome and deep Space Black.
- **Typography**: Googie architecture fonts, bold cursive scripts, or clean mid-century geometric sans-serifs (like `Futura`).
- **Styling**: Sleek bezels, dramatic drop shadows, and offset overlapping shapes.

## Web Implementation
- **CSS Example**:
```css
body {
  background-color: #FDF5E6; /* Old paper / cream */
  color: #2F4F4F;
  font-family: 'Futura', 'Trebuchet MS', sans-serif;
  overflow-x: hidden;
}

/* Googie-style sweeping background element */
.retro-future-swoop {
  position: absolute;
  top: 0; right: -10%;
  width: 120%; height: 300px;
  background-color: #40E0D0; /* Turquoise */
  border-radius: 0 0 50% 50%;
  transform: rotate(-5deg);
  z-index: -1;
  border-bottom: 8px solid #FF9966; /* Atomic tangerine stripe */
}

.atompunk-card {
  background-color: #fff;
  border: 4px solid #Silver;
  border-radius: 40px 10px 40px 10px; /* Sweeping, aerodynamic corners */
  padding: 32px;
  box-shadow: 15px 15px 0px rgba(0,0,0,0.1);
  position: relative;
}

/* Classic starburst motif */
.starburst {
  position: absolute;
  top: -20px; left: -20px;
  width: 40px; height: 40px;
  background-color: #FF9966;
  clip-path: polygon(50% 0%, 61% 35%, 98% 35%, 68% 57%, 79% 91%, 50% 70%, 21% 91%, 32% 57%, 2% 35%, 39% 35%);
}
```

## App Implementation

### SwiftUI
```swift
struct AtompunkShape: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()
        // Sweeping aerodynamic curves (large radius top-left, bottom-right)
        path.addRoundedRect(
            in: rect,
            cornerSize: CGSize(width: 40, height: 40),
            style: .continuous
        )
        // To be perfectly authentic, use Path to draw teardrop curves
        return path
    }
}

struct RetroFutureCard: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("ATOMPUNK")
                .font(.custom("Futura", size: 28))
                .fontWeight(.bold)
                .foregroundColor(Color(red: 0.18, green: 0.31, blue: 0.31))
            
            Text("Sleek chrome and sweeping curves.")
                .font(.custom("Futura", size: 16))
        }
        .padding(32)
        .background(Color.white)
        // Asymmetric corners: large top-left/bottom-right, small top-right/bottom-left
        .cornerRadius(40, corners: [.topLeft, .bottomRight])
        .cornerRadius(10, corners: [.topRight, .bottomLeft])
        .overlay(
            // Chrome-like border
            RoundedRectangle(cornerRadius: 10) // Simplified overlay for demo
                .stroke(
                    LinearGradient(colors: [.gray, .white, .gray], startPoint: .top, endPoint: .bottom),
                    lineWidth: 4
                )
        )
        .shadow(color: .black.opacity(0.1), radius: 0, x: 15, y: 15)
    }
}
// Note: Asymmetric corners require a custom ViewModifier in SwiftUI.
```
- Rely on asymmetrical corner radii to create the aerodynamic, teardrop aesthetic.
- Metallic/Chrome borders are faked by using a `LinearGradient` of grays and whites.

### Flutter
```dart
class RetroFutureCard extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(32),
      decoration: BoxDecoration(
        color: Colors.white,
        // Asymmetric "aerodynamic" shape
        borderRadius: const BorderRadius.only(
          topLeft: Radius.circular(40),
          bottomRight: Radius.circular(40),
          topRight: Radius.circular(10),
          bottomLeft: Radius.circular(10),
        ),
        // Chrome border simulation
        border: Border.all(
          width: 4,
          color: Colors.transparent, // Requires custom painter for gradient border
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.1),
            offset: const Offset(15, 15),
            blurRadius: 0, // Hard shadow
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: const [
          Text('ATOMPUNK',
            style: TextStyle(fontFamily: 'Futura', fontSize: 28, fontWeight: FontWeight.bold, color: Colo
