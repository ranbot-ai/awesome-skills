---
name: ai-native-ui
description: Web and App implementation guide for AI Native UI. Trigger when user wants conversational interfaces, adaptive layouts, and generative AI aesthetics. 
category: Creative & Media
source: antigravity
tags: [react, ai, agent, design, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/ai-native-ui
---


# AI Native UI

> "Fluid, adaptive, and conversational. The interface morphs to serve the content."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Conversational First**: The chat input or voice prompt is the primary navigation method, not a sidebar of links.
2. **Generative States**: Loading states aren't spinners; they are shimmering text, morphing gradients, or skeletal layouts that resolve smoothly into content.
3. **Adaptive Components**: Cards and blocks size themselves dynamically based on the generated content length.

## Visual DNA
- **Colors**: **Minimalist Slate** combined with **Electric Indigo** or **Neon Pulse** gradients for the AI elements. The background is clean (white or dark grey), while the AI "presence" is represented by a shifting, iridescent gradient.
- **Typography**: Highly readable system fonts (`Inter`, `SF Pro`).
- **Styling**: Subtle glowing borders to indicate AI generation in progress.

## Web Implementation
- **CSS Example**:
```css
body {
  background-color: #FAFAFA;
  color: #1A1A1A;
  font-family: 'Inter', sans-serif;
}

/* The AI Chat Input */
.ai-prompt-box {
  background: #ffffff;
  border-radius: 24px;
  padding: 16px 24px;
  box-shadow: 0 8px 30px rgba(0,0,0,0.05);
  border: 1px solid transparent;
  
  /* AI Glow Border */
  background-clip: padding-box, border-box;
  background-origin: padding-box, border-box;
  background-image: 
    linear-gradient(#ffffff, #ffffff), 
    linear-gradient(90deg, #8A2387, #E94057, #F27121);
    
  transition: all 0.3s ease;
}

.ai-prompt-box:focus-within {
  box-shadow: 0 12px 40px rgba(233, 64, 87, 0.15);
}

/* Generative Shimmer Text */
.ai-generating-text {
  background: linear-gradient(90deg, #aaa 0%, #333 50%, #aaa 100%);
  background-size: 200% auto;
  color: transparent;
  -webkit-background-clip: text;
  animation: shine 1.5s linear infinite;
}

@keyframes shine {
  to { background-position: 200% center; }
}
```

## App Implementation

### SwiftUI
```swift
struct AINativeInput: View {
    @State private var isGenerating = true
    @State private var gradientOffset = 0.0
    
    var body: some View {
        VStack {
            // Generative Text Shimmer
            if isGenerating {
                Text("Synthesizing response...")
                    .font(.headline)
                    .foregroundStyle(
                        LinearGradient(
                            colors: [.gray.opacity(0.3), .gray, .gray.opacity(0.3)],
                            startPoint: UnitPoint(x: gradientOffset - 1, y: 0),
                            endPoint: UnitPoint(x: gradientOffset + 1, y: 0)
                        )
                    )
                    .onAppear {
                        withAnimation(.linear(duration: 1.5).repeatForever(autoreverses: false)) {
                            gradientOffset = 1.0
                        }
                    }
            }
            
            // AI Input Box
            HStack {
                TextField("Ask anything...", text: .constant(""))
                Image(systemName: "sparkles")
                    .foregroundColor(.purple)
            }
            .padding()
            .background(Color.white)
            .cornerRadius(24)
            .overlay(
                RoundedRectangle(cornerRadius: 24)
                    .stroke(
                        LinearGradient(colors: [.purple, .pink, .orange], startPoint: .topLeading, endPoint: .bottomTrailing),
                        lineWidth: 2
                    )
            )
            .shadow(color: .pink.opacity(0.15), radius: 20)
        }
        .padding()
    }
}
```
- A shifting `LinearGradient` mask over text creates a beautiful "thinking" state.
- Use a gradient `.stroke` on a `RoundedRectangle` overlay to create the signature AI glowing border around input fields.

### Flutter
```dart
import 'package:shimmer/shimmer.dart';

class AINativeInput extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(16.0),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // Generative Shimmer
          Shimmer.fromColors(
            baseColor: Colors.grey[300]!,
            highlightColor: Colors.grey[600]!,
            child: const Text('Synthesizing response...',
                style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
          ),
          const SizedBox(height: 16),
          // AI Input Box
          Container(
            decoration: BoxDecoration(
              color: Colors.white,
              borderRadius: BorderRadius.circular(24),
              boxShadow: [
                BoxShadow(color: Colors.pink.withOpacity(0.15), blurRadius: 20),
              ],
            ),
            child: Container(
        
