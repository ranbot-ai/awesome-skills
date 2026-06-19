---
name: monochromatic-ui
description: Web and App implementation guide for Monochromatic UI. Trigger when user wants a single-color palette, high elegance, and strict color discipline. 
category: Creative & Media
source: antigravity
tags: [react, ai, llm, design, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/monochromatic-ui
---


# Monochromatic UI

> "Elegance through constraint. A single hue, explored through all its tints, tones, and shades."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Single Hue**: Choose one base color (e.g., deep blue). The entire UI is built using lighter (tints) and darker (shades) versions of that exact hue.
2. **High Contrast for Legibility**: The darkest shade and the lightest tint must have enough contrast to pass accessibility standards when placed together.
3. **Texture over Color**: Since color is restricted, use subtle textures, patterns, or varying opacities to differentiate sections.

## Visual DNA
- **Colors**: **Monochromatic Brown** or pick one dominant hue from **Earth-Grounded Elegance** and extrapolate it.
- **Typography**: Clean and unobtrusive. The layout relies heavily on font weights to establish hierarchy since color cannot.
- **Shadows**: Shadows must be tinted with the base hue, never pure black.

## Web Implementation
- Use HSL (Hue, Saturation, Lightness) heavily in CSS to make building the palette easy.
- **CSS Example**:
```css
:root {
  /* Base Hue: Deep Blue (210) */
  --mono-900: hsl(210, 80%, 10%); /* Very dark */
  --mono-700: hsl(210, 70%, 30%); /* Dark */
  --mono-500: hsl(210, 60%, 50%); /* Base */
  --mono-300: hsl(210, 50%, 80%); /* Light */
  --mono-100: hsl(210, 40%, 95%); /* Very light background */
}

body {
  background-color: var(--mono-100);
  color: var(--mono-900);
  font-family: 'Inter', sans-serif;
}

.mono-card {
  background-color: #ffffff; /* Or mono-100 */
  border: 1px solid var(--mono-300);
  border-radius: 8px;
  padding: 32px;
  /* Tinted shadow */
  box-shadow: 0 10px 25px hsla(210, 80%, 10%, 0.05);
}

.mono-btn {
  background-color: var(--mono-500);
  color: #ffffff;
  border: none;
  border-radius: 4px;
  padding: 12px 24px;
  transition: background-color 0.2s;
}

.mono-btn:hover {
  background-color: var(--mono-700);
}

.mono-subtext {
  color: var(--mono-500); /* Use mid-tones for secondary text */
  font-weight: 500;
}
```

## App Implementation

### SwiftUI
```swift
struct MonochromaticView: View {
    // Base Hue: Deep Blue (210 in 360-degree HSB/HSL)
    // In SwiftUI, hue is 0.0 to 1.0 (210/360 = 0.58)
    let mono900 = Color(hue: 0.58, saturation: 0.80, brightness: 0.10)
    let mono700 = Color(hue: 0.58, saturation: 0.70, brightness: 0.30)
    let mono500 = Color(hue: 0.58, saturation: 0.60, brightness: 0.50)
    let mono300 = Color(hue: 0.58, saturation: 0.50, brightness: 0.80)
    let mono100 = Color(hue: 0.58, saturation: 0.40, brightness: 0.95)
    
    var body: some View {
        VStack(spacing: 24) {
            // Card
            VStack(alignment: .leading, spacing: 12) {
                Text("Monochromatic Elegance")
                    .font(.title2).fontWeight(.semibold)
                    .foregroundColor(mono900)
                
                Text("Using only variations in saturation and brightness of a single hue.")
                    .foregroundColor(mono500)
            }
            .padding(32)
            .background(Color.white)
            .border(mono300, width: 1)
            .shadow(color: mono900.opacity(0.1), radius: 15, y: 5) // Tinted shadow
            
            // Button
            Button(action: {}) {
                Text("Primary Action")
                    .fontWeight(.bold)
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(mono500)
                    .cornerRadius(8)
            }
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(mono100)
    }
}
```
- Define your colors using `Color(hue: saturation: brightness:)`. This ensures math-perfect monochromatic harmony.
- *Always* tint your drop shadows with your `mono900` color. Pure black shadows look dirty in a strict monochromatic UI.

### Flutter
```dart
class MonochromaticScreen extends StatelessWidget {
  // Base Hue: Deep Blue (210)
  // Flutter HSVColor uses Hue 0-360, Saturation 0.0-1.0, Value 0.0-1.0
  final Color mono900 = const HSVColor.fromAHSV(1.0, 210, 0.80, 0.10).toColor();
  final Color mono500 = const HSVColor.fromAHSV(1.0, 210, 0.60, 0.50).toColor();
  final Color mono300 = const HSVColor.fromAHSV(1.0, 210, 0.50, 0.80).toColor();
  final Color mono100 = const HSVColor.fromAHSV(1.0, 210, 0.40, 0.95).toColor();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: mono100,
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              // Card
              Container(
                width: double.infinity,
          
