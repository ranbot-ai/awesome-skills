---
name: brutalism
description: Web and App implementation guide for Brutalism. Trigger when user wants a raw appearance, intentionally unfinished look, and rejection of standard design conventions. 
category: Creative & Media
source: antigravity
tags: [react, ai, llm, design, image, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/brutalism
---


# Brutalism

> "Raw materials exposed. An intentional rejection of polish, gradients, and soft shadows."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Unstyled Components**: Default browser styling for buttons, inputs, and links is celebrated.
2. **Exposed Structure**: Grid lines, tables with visible borders, and stark boundaries are used instead of whitespace to separate content.
3. **Anti-Aesthetic**: Intentional awkwardness. Elements might slightly overlap in a way that feels broken, or use system default fonts.

## Visual DNA
- **Colors**: High contrast, often clashing. Pure `#0000FF` blue for links, `#FF0000` red for accents, on stark white or `#C0C0C0` grey backgrounds. **Industrial Chic** palette fits best.
- **Typography**: Courier New, Times New Roman, Comic Sans, or default sans-serifs. No web fonts.
- **Visuals**: Dithered images, pixelated graphics, or heavily compressed jpegs.

## Web Implementation
- Use standard HTML tags without overriding their default appearance whenever possible.
- **CSS Example**:
```css
body {
  background-color: #ffffff;
  color: #000000;
  font-family: monospace;
}

/* Expose the structure */
.brutalist-container {
  border: 1px solid #000;
  padding: 10px;
}

.brutalist-section {
  border-bottom: 2px dashed #000;
  margin-bottom: 20px;
  padding-bottom: 20px;
}

/* Default-looking button but massive */
.brutalist-btn {
  background-color: #c0c0c0;
  border: 2px outset #ffffff;
  border-right-color: #000000;
  border-bottom-color: #000000;
  color: #000000;
  font-family: sans-serif;
  font-size: 24px;
  padding: 10px 20px;
  cursor: pointer;
}

.brutalist-btn:active {
  border-style: inset;
}

/* System link blue */
a {
  color: #0000FF;
  text-decoration: underline;
}
```

## App Implementation

### SwiftUI
```swift
struct BrutalistView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("BRUTALISM")
                .font(.custom("Courier New", size: 32))
                .foregroundColor(.black)
                .padding(10)
                .border(Color.black, width: 2)
            
            Divider().background(Color.black).padding(.vertical, 20)
            
            Button(action: {}) {
                Text("CLICK_HERE")
                    .font(.custom("Courier New", size: 24))
                    .foregroundColor(.blue)
                    .underline()
            }
            .padding(10)
            
            // Raw structural container
            VStack(alignment: .leading) {
                Text("System Status: RAW").font(.custom("Courier New", size: 14))
            }
            .padding()
            .border(Color.black, width: 1)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Color.white)
    }
}
```
- Avoid all native `ButtonStyle` components. Use `Text` with `.underline()` mapped to system blue.
- Use `.border(Color.black, width: 1)` instead of backgrounds or shadows.
- Force monospace fonts like Courier New or Menlo.

### Flutter
```dart
class BrutalistScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    // DO NOT use MaterialApp theme or Scaffold if possible,
    // or strip them down completely.
    return Scaffold(
      backgroundColor: Colors.white,
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  border: Border.all(color: Colors.black, width: 2),
                ),
                child: const Text(
                  'BRUTALISM',
                  style: TextStyle(
                    fontFamily: 'Courier',
                    fontSize: 32,
                    color: Colors.black,
                  ),
                ),
              ),
              const Padding(
                padding: EdgeInsets.symmetric(vertical: 20),
                child: Divider(color: Colors.black, thickness: 2),
              ),
              GestureDetector(
                onTap: () {},
                child: const Text(
                  'CLICK_HERE',
                  style: TextStyle(
                    fontFamily: 'Courier',
                    fontSize: 24,
                    color: Colors.blue,
                    decoration: TextDecoration.underline,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
```
- Avoid `ElevatedButton`, `Card`, or `AppBar`.
- Build UI out of raw `Container`s with `Border.all(color: Colors.black)` and `Text` widgets.
- Use `TextDecorati
