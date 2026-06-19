---
name: color-blocking
description: Web and App implementation guide for Color Blocking. Trigger when user wants large color sections, striking layout divisions, and Mondrian-style grids. 
category: Creative & Media
source: antigravity
tags: [react, ai, llm, template, design]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/color-blocking
---


# Color Blocking

> "The grid made visible. Large, solid swaths of contrasting color defining the layout."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Geometric Division**: The viewport is divided into large rectangles or squares, each filled with a solid, distinct color.
2. **No Margins Between Blocks**: Blocks touch each other directly, often separated only by a stark, 1px or 2px black line (or no line at all, letting the colors clash).
3. **Typography as Texture**: Text is placed precisely within these blocks to balance the visual weight of the colors.

## Visual DNA
- **Colors**: Highly contrasting, bold pairings. Use 3 to 4 strong colors from palettes like **Industrial Chic** (Red, Black, Grey, White) or custom bold pairings (Yellow, Navy, Pink).
- **Typography**: Very clean, bold sans-serifs that can hold their own against massive blocks of color.
- **Borders**: Often uses thick black borders (`2px solid #000`) between blocks to emphasize the grid, reminiscent of Mondrian paintings.

## Web Implementation
- CSS Grid is the only way to effectively build this.
- **CSS Example**:
```css
body {
  margin: 0;
  font-family: 'Space Grotesk', sans-serif;
  color: #000;
}

.color-block-grid {
  display: grid;
  grid-template-columns: 1fr 2fr 1fr;
  grid-template-rows: 60vh 40vh;
  /* Thick black lines between blocks */
  gap: 4px;
  background-color: #000; 
  border: 4px solid #000;
  min-height: 100vh;
}

.block {
  padding: 40px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
}

.block-yellow { background-color: #FACC15; }
.block-white  { background-color: #FFFFFF; }
.block-blue   { background-color: #2563EB; color: #FFF; }
.block-red    { background-color: #EF4444; }

.block-title {
  font-size: 3rem;
  font-weight: 900;
  text-transform: uppercase;
  margin: 0;
}
```

## App Implementation

### SwiftUI
```swift
struct ColorBlockingView: View {
    let gridSpacing: CGFloat = 4 // Thickness of the black lines
    
    var body: some View {
        // Black background acts as the grid lines between blocks
        VStack(spacing: gridSpacing) {
            // Top Row
            HStack(spacing: gridSpacing) {
                ColorBlock(color: .yellow, text: "CREATE", textColor: .black)
                ColorBlock(color: .blue, text: "VISION", textColor: .white)
            }
            .frame(height: 300)
            
            // Bottom Row
            HStack(spacing: gridSpacing) {
                ColorBlock(color: .red, text: "BOLD", textColor: .white)
                    .frame(width: 120) // Fixed narrow block
                ColorBlock(color: .white, text: "MINIMAL", textColor: .black)
            }
        }
        .background(Color.black) // The grid lines
        .border(Color.black, width: gridSpacing) // Outer border
        .ignoresSafeArea()
    }
}

struct ColorBlock: View {
    let color: Color
    let text: String
    let textColor: Color
    var body: some View {
        color
            .overlay(
                Text(text)
                    .font(.system(size: 32, weight: .black))
                    .foregroundColor(textColor)
                    .padding(),
                alignment: .bottomLeading
            )
    }
}
```
- In SwiftUI, the easiest way to create Mondrian-style thick black grid lines is to set `.background(Color.black)` on the parent stack and use `spacing: 4`. The background peeks through the gaps.
- `.ignoresSafeArea()` allows the blocks to bleed to the edge of the physical device.

### Flutter
```dart
class ColorBlockingScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      // Black background creates the grid lines
      backgroundColor: Colors.black,
      body: SafeArea(
        bottom: false,
        child: Column(
          children: [
            // Top Row
            Expanded(
              flex: 3, // 3/5 of vertical space
              child: Row(
                children: [
                  Expanded(flex: 1, child: ColorBlock(color: const Color(0xFFFACC15), text: 'CREATE', textColor: Colors.black)),
                  const SizedBox(width: 4), // Grid line
                  Expanded(flex: 2, child: ColorBlock(color: const Color(0xFF2563EB), text: 'VISION', textColor: Colors.white)),
                ],
              ),
            ),
            const SizedBox(height: 4), // Horizontal grid line
            // Bottom Row
            Expanded(
              flex: 2, // 2/5 of vertical space
              child: Row(
                children: [
                  Expanded(flex: 1, child: ColorBlock(color: const Color(0xFFEF4444), text: 'BOLD', textColor: Colors.white)),
                  const SizedBox(width: 4),
                  Expanded(flex: 2, child: ColorBlock(color: Colors.white, text: 'MINIMAL'
