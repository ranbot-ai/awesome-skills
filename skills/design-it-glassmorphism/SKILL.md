---
name: glassmorphism
description: Web and App implementation guide for Glassmorphism. Trigger when user wants a frosted glass effect, blurred backgrounds, transparency, or a sleek MacOS-like feel. 
category: Creative & Media
source: antigravity
tags: [react, api, ai, llm, design, image, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/glassmorphism
---


# Glassmorphism

> "Looking through a frosted window. Interfaces that blend seamlessly with vibrant backgrounds."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Background Blur (Backdrop Filter)**: The defining characteristic. Elements blur whatever is underneath them.
2. **Semi-transparent White/Dark Backgrounds**: Panels use rgba() colors to let the background shine through.
3. **Subtle Light Borders**: A 1px semi-transparent white (or light) border to simulate the glass edge catching the light.

## Visual DNA
- **Colors**: Requires a vibrant or textured background to work (e.g., gradients, abstract meshes, or photos). Works beautifully over **Yacht Club** or **Earth-Grounded Elegance** if there is underlying visual texture.
- **Typography**: Clean, geometric sans-serifs. High contrast text (pure white or pure black) is required for legibility against the glass.
- **Shadows**: Soft, subtle drop shadows to detach the glass pane from the background.

## Web Implementation
- Rely heavily on `backdrop-filter: blur()`.
- **CSS Example**:
```css
body {
  /* Requires a complex background to see the glass effect */
  background: url('abstract-mesh.jpg') cover; 
}

.glass-panel {
  background: rgba(255, 255, 255, 0.15); /* Light glass */
  /* OR background: rgba(0, 0, 0, 0.25); for Dark glass */
  
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  
  border: 1px solid rgba(255, 255, 255, 0.3); /* The glass edge */
  border-radius: 16px;
  box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1);
  
  padding: 32px;
}
```

## App Implementation

### SwiftUI
```swift
struct GlassCard: View {
    var body: some View {
        ZStack {
            // Vibrant background required for glass to show
            LinearGradient(
                colors: [.purple, .blue, .cyan],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()
            
            // Glass panel
            VStack(alignment: .leading, spacing: 16) {
                Text("Glass Panel")
                    .font(.system(size: 22, weight: .semibold))
                    .foregroundColor(.white)
                Text("Content floating on frosted glass.")
                    .font(.system(size: 15))
                    .foregroundColor(.white.opacity(0.8))
                
                Button(action: {}) {
                    Text("Continue")
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundColor(.white)
                        .padding(.horizontal, 24)
                        .padding(.vertical, 12)
                        .background(.ultraThinMaterial)
                        .cornerRadius(8)
                }
            }
            .padding(24)
            .background(.ultraThinMaterial)  // Built-in frosted glass
            .cornerRadius(16)
            .overlay(
                RoundedRectangle(cornerRadius: 16)
                    .stroke(.white.opacity(0.3), lineWidth: 1) // Glass edge highlight
            )
            .shadow(color: .black.opacity(0.1), radius: 20, x: 0, y: 10)
            .padding(24)
        }
    }
}
```
- Use `.ultraThinMaterial`, `.thinMaterial`, `.regularMaterial`, `.thickMaterial` — Apple built glassmorphism natively.
- Add `.overlay(RoundedRectangle().stroke(.white.opacity(0.3)))` for the light edge catch.
- Glass only works if there's a vibrant background visible behind it.

### Flutter
```dart
class GlassCard extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Stack(
      children: [
        // Vibrant background
        Container(
          decoration: const BoxDecoration(
            gradient: LinearGradient(
              colors: [Colors.purple, Colors.blue, Colors.cyan],
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
            ),
          ),
        ),
        // Glass panel
        Center(
          child: ClipRRect(
            borderRadius: BorderRadius.circular(16),
            child: BackdropFilter(
              filter: ImageFilter.blur(sigmaX: 16, sigmaY: 16),
              child: Container(
                padding: const EdgeInsets.all(24),
                decoration: BoxDecoration(
                  color: Colors.white.withOpacity(0.15),
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(
                    color: Colors.white.withOpacity(0.3),
                    width: 1,
                  ),
                  boxShadow: [
                    BoxShadow(
                      color: Colors.black.withOpacity(0.1),
                      blurRadius: 20,
                      offset: const Offset(0, 10),
                    ),
                  ],
                ),
                
