---
name: swiss-design
description: Web and App implementation guide for Swiss Design (International Typographic Style). Trigger when user wants strict grid systems, strong typography, and clean, asymmetrical alignment. 
category: Document Processing
source: antigravity
tags: [react, ai, llm, template, design, document, image, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/swiss-design
---


# Swiss Design (International Typographic Style)

> "Form follows function. The grid is absolute. Typography is the primary visual element."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Mathematical Grids**: Everything aligns to a strict underlying grid. Asymmetry is preferred over centered text.
2. **Sans-Serif Typography**: Helvetica is the king, but any clean, neutral sans-serif works. Flush left, ragged right text alignment.
3. **Objective Photography**: If images are used, they should be objective, documentary-style photos, not stylized illustrations.

## Visual DNA
- **Colors**: Very limited. Usually just black, white, and ONE highly saturated accent color (often primary red, blue, or yellow). The **Industrial Chic** palette works perfectly.
- **Typography**: `Helvetica Neue`, `Inter`, or `Roboto`. Huge contrast in font sizes (e.g., massive 6rem headers paired with 1rem body text).
- **Layout**: Do NOT center text. Ever.

## Web Implementation
- Use CSS Grid extensively. Let columns dictate the layout.
- **CSS Example**:
```css
body {
  background-color: #f4f4f4;
  color: #111;
  font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
  line-height: 1.4;
}

.swiss-grid {
  display: grid;
  grid-template-columns: repeat(12, 1fr);
  gap: 20px;
  padding: 40px;
}

.swiss-header {
  grid-column: 1 / 11; /* spans across multiple columns, leaving right side empty */
  font-size: 6vw;
  font-weight: 700;
  text-transform: lowercase; /* Optional, but common in brutalist/swiss */
  margin-bottom: 2rem;
  line-height: 0.9;
  letter-spacing: -0.04em;
}

.swiss-content {
  grid-column: 4 / 9; /* Indented alignment */
  font-size: 1.25rem;
  text-align: left; /* Flush left, ragged right */
}

.swiss-accent {
  color: #E2001A; /* Classic Swiss Red */
}
```

## App Implementation

### SwiftUI
```swift
struct SwissDesignView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                // Header Block
                VStack(alignment: .leading, spacing: 8) {
                    Text("the grid")
                        .font(.custom("Helvetica Neue", size: 60))
                        .fontWeight(.heavy)
                        .tracking(-2) // Tight letter spacing
                    Text("is absolute.")
                        .font(.custom("Helvetica Neue", size: 60))
                        .fontWeight(.heavy)
                        .tracking(-2)
                        .foregroundColor(Color(hex: "E2001A")) // Swiss Red
                }
                .padding(.horizontal, 24)
                .padding(.top, 60)
                .padding(.bottom, 40)
                
                Divider().background(Color.black)
                
                // Asymmetrical Content Block
                HStack(alignment: .top, spacing: 20) {
                    // Empty left column (negative space is structural)
                    Spacer().frame(width: 40)
                    
                    VStack(alignment: .leading, spacing: 16) {
                        Text("Form follows function.")
                            .font(.custom("Helvetica Neue", size: 24))
                            .fontWeight(.bold)
                        
                        Text("Typography is the primary visual element. Everything aligns to a strict underlying grid. Asymmetry is preferred over centered text.")
                            .font(.custom("Helvetica Neue", size: 16))
                            .lineSpacing(6)
                    }
                    .padding(.vertical, 40)
                    .padding(.trailing, 24)
                }
                
                Divider().background(Color.black)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Color(white: 0.96))
        .foregroundColor(.black)
    }
}
```
- Strict `alignment: .leading` everywhere. Never use `.center`.
- Use `Spacer().frame(width: X)` in `HStack`s to intentionally push content off the left margin, creating the classic Swiss indented asymmetrical grid.

### Flutter
```dart
class SwissDesignScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFFF4F4F4),
      body: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const SizedBox(height: 80),
            // Header
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: const [
                  Text('the grid', style: TextStyle(fontFamily: 'Helvetica', fontSize: 60, fontWeight: FontWeight.w90
