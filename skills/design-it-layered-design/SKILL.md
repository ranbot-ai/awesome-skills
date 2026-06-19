---
name: layered-design
description: Web and App implementation guide for Layered Design. Trigger when user wants multiple depth levels, floating panels, and overlapping content. 
category: Creative & Media
source: antigravity
tags: [react, ai, llm, design, image, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/layered-design
---


# Layered Design

> "Stacking context. Interfaces built from overlapping, independent layers."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Explicit Overlap**: Elements intentionally overlap each other to break the grid and show depth.
2. **Clear Stratification**: Every layer must be visually distinct via shadow, border, or contrasting color.
3. **Parallax Scrolling**: Background layers move slower than foreground layers during interaction/scrolling.

## Visual DNA
- **Colors**: **Monochromatic Brown** or **Sophisticated Neutral**. Layering works best when the background is distinct from the floating elements.
- **Typography**: Often large, overlapping text that spans across image and background layers.
- **Spacing**: Negative space is required around overlapping elements so they don't feel cluttered.

## Web Implementation
- Heavy use of `position: absolute`, negative margins, and `z-index`.
- **CSS Example**:
```css
.layer-container {
  position: relative;
  padding: 100px;
}

.layer-bg-image {
  position: absolute;
  top: 0; right: 0;
  width: 60%;
  height: 400px;
  object-fit: cover;
  z-index: 1;
}

.layer-text-box {
  position: relative;
  z-index: 2; /* Sits above the image */
  background: white;
  padding: 40px;
  width: 50%;
  margin-top: 200px; /* Pulls it down over the image */
  box-shadow: 0 20px 40px rgba(0,0,0,0.1);
  /* Optional: border to define edge */
  border-left: 4px solid var(--cta-highlight);
}
```

## App Implementation

### SwiftUI
```swift
struct LayeredDesignView: View {
    var body: some View {
        ScrollView {
            ZStack(alignment: .top) {
                // Background Image Layer (Back)
                Image("architectural-bg")
                    .resizable()
                    .aspectRatio(contentMode: .fill)
                    .frame(height: 400)
                    .offset(x: 40, y: 0) // Shifted right
                    .zIndex(1)
                
                // Content Card Layer (Front)
                VStack(alignment: .leading, spacing: 16) {
                    Text("Stacking Context")
                        .font(.largeTitle).bold()
                    Text("This card intentionally overlaps the background image to create depth without relying on a grid.")
                        .foregroundColor(.secondary)
                }
                .padding(40)
                .background(Color.white)
                .shadow(color: Color.black.opacity(0.1), radius: 30, y: 20)
                .offset(x: -40, y: 200) // Shifted left and pulled down
                .zIndex(2)
            }
            .padding(.bottom, 200) // Account for the offset
        }
    }
}
```
- `ZStack` is the foundation of layered design in SwiftUI.
- Use `.offset()` to intentionally break the alignment and create overlapping compositions.
- Explicitly set `.zIndex()` if your offsets might cause unexpected paint orders.

### Flutter
```dart
class LayeredDesignScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SingleChildScrollView(
        child: SizedBox(
          height: 600, // Fixed height stack or use constraints
          child: Stack(
            children: [
              // Background Image Layer
              Positioned(
                top: 0,
                right: -40, // Shifted offscreen right
                width: MediaQuery.of(context).size.width * 0.8,
                height: 400,
                child: Image.asset('assets/architectural-bg.jpg', fit: BoxFit.cover),
              ),
              
              // Content Card Layer
              Positioned(
                top: 250, // Overlaps the bottom of the image
                left: 20, // Overlaps the left of the image
                width: MediaQuery.of(context).size.width * 0.7,
                child: Container(
                  padding: const EdgeInsets.all(40),
                  decoration: BoxDecoration(
                    color: Colors.white,
                    boxShadow: [
                      BoxShadow(color: Colors.black.withOpacity(0.1), blurRadius: 30, offset: const Offset(0, 20))
                    ],
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: const [
                      Text('Stacking Context', style: TextStyle(fontSize: 32, fontWeight: FontWeight.bold)),
                      SizedBox(height: 16),
                      Text('This card intentionally overlaps the background image.', style: TextStyle(color: Colors.grey)),
                    ],
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
- The `Stack` widget with `Positioned` children is required.
- You can use n
