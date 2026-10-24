---
name: widget-based-design
description: Web and App implementation guide for Widget-Based Design. Trigger when user wants modular blocks, iOS Home Screen aesthetics, and customizable mini-apps. 
category: Creative & Media
source: antigravity
tags: [react, ai, llm, template, design, image, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/widget-based-design
---


# Widget-Based Design

> "Miniature applications. Small, highly functional blocks of UI designed to be rearranged."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Strict Aspect Ratios**: Widgets usually follow strict sizes (1x1 square, 2x1 rectangle, 2x2 large square).
2. **Glanceability**: Widgets show the most important piece of data instantly. Deep interaction usually requires opening the full app.
3. **Corner Radius Match**: The inner content's border radius should perfectly nest within the widget's outer border radius.

## Visual DNA
- **Colors**: Widgets often use bright, solid color backgrounds or full-bleed photos to differentiate themselves.
- **Typography**: Large, bold numbers (like a clock or weather temp) paired with tiny sub-labels.
- **Layout**: Similar to Bento UI, but specifically focused on functional app-lets rather than just content layout.

## Web Implementation
- **CSS Example**:
```css
.widget-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  grid-auto-rows: 160px; /* Force squares */
  gap: 16px;
  padding: 32px;
}

.widget {
  background-color: #ffffff;
  border-radius: 24px; /* Classic iOS widget radius */
  box-shadow: 0 8px 24px rgba(0,0,0,0.08);
  padding: 16px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  overflow: hidden;
  position: relative;
}

/* Specific Sizes */
.widget-small { grid-column: span 1; grid-row: span 1; }
.widget-medium { grid-column: span 2; grid-row: span 1; }
.widget-large { grid-column: span 2; grid-row: span 2; }

/* Weather Widget Example */
.widget.weather {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #12313a;
}
.weather-temp { font-size: 3rem; font-weight: 300; }
.weather-icon { position: absolute; top: 16px; right: 16px; font-size: 2rem; }
```

## App Implementation

### SwiftUI
```swift
struct WidgetDesignView: View {
    let columns = [GridItem(.flexible(), spacing: 16), GridItem(.flexible(), spacing: 16)]
    
    var body: some View {
        ScrollView {
            LazyVGrid(columns: columns, spacing: 16) {
                // One column: LazyVGrid does not span WeatherWidget across two columns.
                WeatherWidget()
                    .frame(height: 160) // Base unit height
                
                // 1x1 Widget
                Text("Fitness") // Replace with a defined widget component.
                    .frame(height: 160)
                
                // 1x1 Widget
                Text("Music") // Replace with a defined widget component.
                    .frame(height: 160)
            }
            .padding(24)
        }
        .background(Color(white: 0.95))
    }
}

struct WeatherWidget: View {
    var body: some View {
        ZStack(alignment: .topTrailing) {
            LinearGradient(colors: [Color(hex: "4facfe"), Color(hex: "00f2fe")], startPoint: .topLeading, endPoint: .bottomTrailing)
            
            Image(systemName: "cloud.sun.fill")
                .foregroundColor(Color(red: 0.07, green: 0.19, blue: 0.23))
                .font(.system(size: 40))
                .padding()
            
            VStack(alignment: .leading) {
                Spacer()
                Text("72°")
                    .font(.system(size: 48, weight: .thin))
                    .foregroundColor(Color(red: 0.07, green: 0.19, blue: 0.23))
                Text("San Francisco")
                    .font(.subheadline)
                    .foregroundColor(Color(red: 0.07, green: 0.19, blue: 0.23))
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding()
        }
        .cornerRadius(24) // Classic iOS widget radius
        .shadow(color: .black.opacity(0.1), radius: 10, y: 5)
    }
}
```
- SwiftUI is perfect for this. The `LazyVGrid` handles the layout, and `cornerRadius(24)` matches Apple's default widget styling perfectly.
- Use `ZStack` as the root of the widget to easily overlay content on top of complex gradients or images.

### Flutter
```dart
class WidgetDesignScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFFF2F2F2),
      body: GridView.count(
        crossAxisCount: 2, // 2 columns for a typical phone
        padding: const EdgeInsets.all(24),
        mainAxisSpacing: 16,
        crossAxisSpacing: 16,
        childAspectRatio: 1.0, // 1x1 squares
        children: [
          // Note: Flutter GridView doesn't easily span rows/cols out of the box.
          // flutter_staggered_grid_view is highly recommended for real widget layouts.
          _buildWeatherWidget(),
          const Center(child: Text("Fitness")),
          const Center(child: Text("Music")),
        ],
      ),
    );
  }

  Widget _build
