---
name: high-contrast
description: Web and App implementation guide for High Contrast Design. Trigger when user wants accessibility-focused design, extreme legibility, or stark visual impact. 
category: Creative & Media
source: antigravity
tags: [react, ai, llm, design, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/high-contrast
---


# High Contrast Design

> "Maximum legibility. Stark, powerful, and universally accessible."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **WCAG AAA Compliance**: Every color pairing must exceed a 7:1 contrast ratio.
2. **Clear Boundaries**: Interactive elements have highly visible borders and focus states.
3. **No Ambiguity**: Avoid subtle greys, low-opacity text, or purely decorative elements that distract from the core content.

## Visual DNA
- **Colors**: **Industrial Chic** (Black and White) or **Modern Editorial**. Often uses a single, highly luminous accent color (like pure Yellow `#FFFF00` or Cyan `#00FFFF`) against black.
- **Typography**: Highly legible, robust sans-serifs (`Atkinson Hyperlegible`, `Inter`, `Roboto`). Large base font sizes (18px+).
- **Styling**: Solid 2px borders around cards and buttons. Avoid drop shadows as they reduce edge clarity.

## Web Implementation
- Focus heavily on focus states (`:focus-visible`) and clear active states.
- **CSS Example**:
```css
:root {
  --hc-bg: #ffffff;
  --hc-text: #000000;
  --hc-accent: #0000FF; /* Pure blue */
  --hc-focus: #FF00FF; /* High visibility focus ring */
}

body {
  background-color: var(--hc-bg);
  color: var(--hc-text);
  font-family: 'Atkinson Hyperlegible', sans-serif;
  font-size: 18px; /* Larger default */
}

.hc-card {
  background-color: #ffffff;
  border: 3px solid #000000; /* Unmissable boundary */
  padding: 32px;
  border-radius: 8px;
}

.hc-btn {
  background-color: var(--hc-accent);
  color: #ffffff;
  border: 3px solid transparent; /* Reserve space for focus */
  border-radius: 4px;
  padding: 16px 32px;
  font-weight: 700;
  font-size: 1.1rem;
  cursor: pointer;
}

/* Crucial for high contrast / accessibility */
.hc-btn:focus-visible, a:focus-visible {
  outline: 4px solid var(--hc-focus);
  outline-offset: 4px;
}

a {
  color: var(--hc-accent);
  text-decoration: underline;
  text-decoration-thickness: 2px;
}
```

## App Implementation

### SwiftUI
```swift
struct HighContrastView: View {
    var body: some View {
        VStack(spacing: 32) {
            // High Contrast Card
            VStack(alignment: .leading, spacing: 16) {
                Text("Maximum Legibility")
                    .font(.custom("Atkinson Hyperlegible", size: 24))
                    .fontWeight(.bold)
                    .foregroundColor(.black)
                
                Text("Content is king. Borders are stark. Contrast ratios exceed 7:1.")
                    .font(.custom("Atkinson Hyperlegible", size: 18))
                    .foregroundColor(.black)
            }
            .padding(32)
            .background(Color.white)
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(Color.black, lineWidth: 3)
            )
            
            // High Contrast Action Button
            Button(action: {}) {
                Text("CONFIRM ACTION")
                    .font(.custom("Atkinson Hyperlegible", size: 18))
                    .fontWeight(.black)
                    .foregroundColor(.white)
                    .padding(.vertical, 16)
                    .padding(.horizontal, 32)
                    .background(Color.blue) // Must be a high-contrast blue, e.g., #0000FF
                    .cornerRadius(4)
            }
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.white)
    }
}
```
- Rely on thick `.stroke(Color.black, lineWidth: 3)` overlays.
- Ensure text is pure `.black` on pure `.white`. Do not use `.secondary` colors if they drop below a 7:1 contrast ratio.
- Use fonts specifically designed for legibility, like Atkinson Hyperlegible.

### Flutter
```dart
class HighContrastScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.white,
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              // High Contrast Card
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(32),
                decoration: BoxDecoration(
                  color: Colors.white,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: Colors.black, width: 3), // Unmissable boundary
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: const [
                    Text('Maximum Legibility', 
                      style: TextStyle(fontFamily: 'Atkinson', fontSize: 24, fontWeight: FontWeight.bold, color: Colors.black)),
                    SizedBox(height:
