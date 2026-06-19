---
name: gradient-design
description: Web and App implementation guide for Gradient Design. Trigger when user wants heavy gradient usage, vibrant transitions, and modern energetic feels. 
category: Creative & Media
source: antigravity
tags: [react, node, ai, llm, design]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/gradient-design
---


# Gradient Design

> "Color in motion. Fluid transitions that add energy and depth to flat surfaces."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Gradients are the Primary Visual**: Backgrounds, buttons, text, and borders all use gradients instead of solid colors.
2. **Analogous or Complementary Blends**: Gradients must be carefully chosen so the transition colors don't become muddy (e.g., blending red to green creates a muddy brown in the middle. Blend red to yellow to green instead).
3. **Subtle Animation**: Background gradients should slowly shift and rotate.

## Visual DNA
- **Colors**: **Warm Tech** (blues to oranges) or create custom vibrant pairs (e.g., Purple to Coral, Deep Blue to Cyan).
- **Typography**: Clean, heavy sans-serifs that can be easily masked with a gradient fill.
- **Layout**: Keep the UI structure minimal (glass panels or white/black cards) to let the gradients breathe.

## Web Implementation
- **CSS Example**:
```css
body {
  /* Complex mesh-like animated gradient */
  background: linear-gradient(-45deg, #ee7752, #e73c7e, #23a6d5, #23d5ab);
  background-size: 400% 400%;
  animation: gradientBG 15s ease infinite;
  color: #fff;
}

@keyframes gradientBG {
  0% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
}

.gradient-text {
  background: linear-gradient(90deg, #F9D423 0%, #FF4E50 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  font-size: 4rem;
  font-weight: 900;
}

.gradient-border-card {
  background: #ffffff;
  color: #333;
  padding: 32px;
  border-radius: 12px;
  position: relative;
  /* Use a pseudo-element for the gradient border */
}
.gradient-border-card::before {
  content: '';
  position: absolute;
  top: -3px; left: -3px; right: -3px; bottom: -3px;
  background: linear-gradient(90deg, #8A2387, #E94057, #F27121);
  z-index: -1;
  border-radius: 15px;
}
```

## App Implementation

### SwiftUI
```swift
struct GradientDesignView: View {
    @State private var animateGradient = false
    
    var body: some View {
        ZStack {
            // Animated Background Gradient
            LinearGradient(
                colors: [Color(hex: "ee7752"), Color(hex: "e73c7e"), Color(hex: "23a6d5"), Color(hex: "23d5ab")],
                startPoint: animateGradient ? .topLeading : .bottomLeading,
                endPoint: animateGradient ? .bottomTrailing : .topTrailing
            )
            .ignoresSafeArea()
            .onAppear {
                withAnimation(.linear(duration: 5.0).repeatForever(autoreverses: true)) {
                    animateGradient.toggle()
                }
            }
            
            VStack(spacing: 40) {
                // Gradient Text
                Text("VIBRANT")
                    .font(.system(size: 60, weight: .black))
                    .foregroundStyle(
                        LinearGradient(
                            colors: [Color(hex: "F9D423"), Color(hex: "FF4E50")],
                            startPoint: .leading,
                            endPoint: .trailing
                        )
                    )
                
                // Gradient Border Card
                Text("Gradient Border")
                    .padding()
                    .frame(width: 250, height: 150)
                    .background(Color.white)
                    .cornerRadius(12)
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .stroke(
                                LinearGradient(
                                    colors: [Color(hex: "8A2387"), Color(hex: "E94057"), Color(hex: "F27121")],
                                    startPoint: .leading, endPoint: .trailing
                                ),
                                lineWidth: 3
                            )
                    )
            }
        }
    }
}
```
- `.foregroundStyle(LinearGradient(...))` makes gradient text incredibly easy in modern SwiftUI.
- Use `.stroke(LinearGradient(...))` inside an `.overlay` to create gradient borders.

### Flutter
```dart
class GradientDesignScreen extends StatefulWidget {
  @override
  State<GradientDesignScreen> createState() => _GradientDesignScreenState();
}

class _GradientDesignScreenState extends State<GradientDesignScreen> with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<Alignment> _topAlignment;
  late Animation<Alignment> _bottomAlignment;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(vsync: this, duration: const Duration(seconds: 5))..repeat(reverse: true);
    _topAlignment = TweenSequence<Alignment>([
      TweenSequenceItem(tween: AlignmentTween(begin: Alignment.topLeft, end: Al
