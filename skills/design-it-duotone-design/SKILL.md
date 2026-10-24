---
name: duotone-design
description: Web and App implementation guide for Duotone Design. Trigger when user wants two-color schemes, striking imagery, and Spotify-like playlist aesthetics. 
category: Creative & Media
source: antigravity
tags: [react, api, ai, llm, design, image, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/duotone-design
---


# Duotone Design

> "Striking contrast. Photography and UI stripped down to exactly two clashing or complementary colors."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Two Colors Only**: The entire design is mapped to a dark color (replacing blacks/shadows) and a light color (replacing whites/highlights).
2. **Treated Imagery**: All photos MUST be processed into the duotone palette.
3. **Bold, Flat Typography**: Text is usually massive, solid, and uses one of the two colors.

## Visual DNA
- **Colors**: Very high contrast pairs. Navy and Peach, Deep Purple and Neon Green, Crimson and Cream. Look at **Industrial Chic** for inspiration.
- **Typography**: Heavy, condensed sans-serifs (e.g., `League Gothic`, `Oswald`).
- **Imagery**: High-contrast, gritty photography works best when mapped to duotone.

## Web Implementation
- Modern CSS can achieve image duotone effects without Photoshop, using `mix-blend-mode` and filters.
- **CSS Example**:
```css
:root {
  --duo-dark: #1E0045; /* Deep Purple */
  --duo-light: #CCFF00; /* Neon Lime */
}

body {
  background-color: var(--duo-dark);
  color: var(--duo-light);
}

/* CSS Duotone Image Effect */
.duotone-container {
  position: relative;
  width: 100%;
  height: 400px;
  background-color: var(--duo-light); /* Base color */
}

.duotone-container img {
  width: 100%;
  height: 100%;
  object-fit: cover;
  /* Convert image to grayscale, increase contrast */
  filter: grayscale(100%) contrast(1.5); 
  /* Multiply the grayscale image against the light background */
  mix-blend-mode: multiply;
}

.duotone-container::after {
  /* Approximate dark overlay; multiply/screen is not exact endpoint interpolation. */
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0; bottom: 0;
  background-color: var(--duo-dark);
  mix-blend-mode: screen;
}

.duotone-btn {
  background: var(--duo-light);
  color: var(--duo-dark);
  border: none;
  font-weight: 900;
  text-transform: uppercase;
  padding: 16px 32px;
}
```

## App Implementation

### SwiftUI
```swift
struct DuotoneImage: View {
    let duoDark = Color(red: 0.12, green: 0.0, blue: 0.27)  // #1E0045
    let duoLight = Color(red: 0.8, green: 1.0, blue: 0.0)   // #CCFF00
    
    var body: some View {
        ZStack {
            // Background base color
            duoLight.ignoresSafeArea()
            
            // Image processing
            Image("sample_photo")
                .resizable()
                .scaledToFill()
                .grayscale(1.0)
                .contrast(1.5)
                .colorMultiply(duoLight) // Multiplies the light color into the grays
            
            // Dark color overlay
            duoDark
                .blendMode(.screen) // Equivalent to CSS screen blend mode
                .allowsHitTesting(false)
        }
        .frame(height: 400)
        .clipped()
    }
}
```
- Real-time image processing is easy in SwiftUI.
- Convert to `.grayscale()`, boost `.contrast()`, then use `.colorMultiply()` and `.blendMode(.screen)` layers to approximate a multiply/screen effect. This does not map exactly to arbitrary endpoint colors; use a luminance matrix when exact endpoints matter.

### Flutter
A luminance-to-endpoints matrix avoids the incorrect assumption that a filter on a transparent sibling modifies the image beneath it. `ColorFiltered` filters only its child.

```dart
class DuotoneImage extends StatelessWidget {
  const DuotoneImage({super.key});

  @override
  Widget build(BuildContext context) {
    // Output = dark + luminance * (light - dark), RGB values in 0..255.
    const dark = [30.0, 0.0, 69.0];
    const light = [204.0, 255.0, 0.0];
    const luminance = [0.2126, 0.7152, 0.0722];
    final matrix = <double>[];
    for (var channel = 0; channel < 3; channel++) {
      final delta = light[channel] - dark[channel];
      matrix.addAll([
        for (final weight in luminance) delta * weight / 255.0,
        0.0, dark[channel],
      ]);
    }
    matrix.addAll([0.0, 0.0, 0.0, 1.0, 0.0]);
    return ColorFiltered(
      colorFilter: ColorFilter.matrix(matrix),
      child: Image.asset('assets/sample_photo.jpg', fit: BoxFit.cover),
    );
  }
}
```
The image asset must exist. This is an RGB luminance approximation; verify color-space behavior and accessibility in the target renderer.

### React Native
```jsx
// Real-time CSS-like blend modes do NOT exist natively in React Native.
// You must use react-native-skia or pre-process images.

import { Canvas, Image, useImage, ColorMatrix } from "@shopify/react-native-skia";

const DuotoneImage = () => {
  const image = useImage(require('./sample_photo.jpg'));
  
  if (!image) return null;

  // Skia allows custom SVG/CSS style color matrices.
  // Building a true duotone matrix requires math mapping black to duoDark
  // and white to duoLight.
  
 
