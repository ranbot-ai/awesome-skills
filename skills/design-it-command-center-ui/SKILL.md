---
name: command-center-ui
description: Web and App implementation guide for Command Center UI. Trigger when user wants monitoring systems, enterprise dashboards, NOCs, and global maps. 
category: Creative & Media
source: antigravity
tags: [react, node, ai, llm, template, design, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/command-center-ui
---


# Command Center UI

> "Mission Control. Global monitoring, real-time alerts, and high-stakes data visualization."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Dark/Black Backgrounds**: Essential for a room full of glowing monitors (NOCs). It makes the data pop and reduces glare.
2. **Maps & Topologies**: The center of the UI is almost always a dark-mode geographical map or a node-based network topology.
3. **Alert Hierarchy**: 90% of the screen is calm and blue/grey. When a warning happens, it flashes bright amber or red to immediately draw the eye.

## Visual DNA
- **Colors**: Pure black (`#000000`) or deep navy (`#0B132B`). Accents are electric cyan (`#00FFFF`), amber (`#FFBF00`), and critical red (`#FF0000`).
- **Typography**: Clean, tech-focused sans-serifs (`Orbitron`, `Roboto`, `Share Tech`).
- **Styling**: Glowing borders, radar sweeps, and stark, data-driven charts.

## Web Implementation
- **CSS Example**:
```css
body {
  background-color: #030a16;
  color: #8ab4f8;
  font-family: 'Roboto', sans-serif;
  margin: 0;
  display: grid;
  grid-template-columns: 300px 1fr 300px;
  height: 100vh;
}

.panel {
  background-color: rgba(13, 27, 42, 0.8);
  border: 1px solid #1c355e;
  box-shadow: inset 0 0 20px rgba(0, 255, 255, 0.05);
  margin: 10px;
  display: flex;
  flex-direction: column;
}

.panel-header {
  background: linear-gradient(90deg, #1c355e, transparent);
  color: #00ffff;
  padding: 8px 16px;
  font-weight: bold;
  text-transform: uppercase;
  letter-spacing: 2px;
  border-bottom: 1px solid #00ffff;
}

/* The Map/Center view */
.main-view {
  /* Placeholder for a massive globe or map */
  background: radial-gradient(circle, #0d1b2a 0%, #030a16 100%);
  position: relative;
}

/* Critical Alert */
.alert-critical {
  background-color: rgba(255, 0, 0, 0.1);
  border: 1px solid #ff0000;
  color: #ff0000;
  box-shadow: 0 0 10px rgba(255, 0, 0, 0.5);
  animation: pulse-red 2s infinite;
}

@keyframes pulse-red {
  0% { box-shadow: 0 0 5px rgba(255, 0, 0, 0.2); }
  50% { box-shadow: 0 0 20px rgba(255, 0, 0, 0.8); }
  100% { box-shadow: 0 0 5px rgba(255, 0, 0, 0.2); }
}
```

## App Implementation

### SwiftUI
```swift
struct CommandCenterView: View {
    @State private var isAlerting = false
    
    var body: some View {
        VStack(spacing: 16) {
            // Header
            HStack {
                Text("GLOBAL_OPS // ALPHA")
                    .font(.custom("Orbitron", size: 20))
                    .foregroundColor(Color(red: 0.0, green: 1.0, blue: 1.0)) // Cyan
                Spacer()
                Text(Date(), style: .time).foregroundColor(.gray)
            }
            .padding()
            .border(Color(red: 0.0, green: 1.0, blue: 1.0), width: 1)
            
            // Map or main visual placeholder
            Circle()
                .strokeBorder(
                    LinearGradient(colors: [.cyan, .blue], startPoint: .top, endPoint: .bottom),
                    lineWidth: 2
                )
                .frame(height: 250)
                .overlay(Text("TOPOLOGY SCAN").foregroundColor(.cyan.opacity(0.5)))
            
            // Critical Alert Panel
            VStack(alignment: .leading) {
                Text("WARNING: SECTOR 7G")
                    .font(.headline)
                    .foregroundColor(.red)
                Text("Anomalous activity detected.")
                    .font(.subheadline)
                    .foregroundColor(.white)
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.red.opacity(0.1))
            .border(Color.red, width: 2)
            .shadow(color: isAlerting ? .red : .clear, radius: 10)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(red: 0.01, green: 0.04, blue: 0.09)) // Very dark navy
        .onAppear {
            withAnimation(.easeInOut(duration: 1.0).repeatForever()) {
                isAlerting.toggle()
            }
        }
    }
}
```
- Rely heavily on `.border()` and `.strokeBorder()` combined with gradients to create technical, glowing wireframes.
- Use `.shadow()` animated continuously for pulse alerts.

### Flutter
```dart
class CommandCenterScreen extends StatefulWidget {
  @override
  State<CommandCenterScreen> createState() => _CommandCenterScreenState();
}

class _CommandCenterScreenState extends State<CommandCenterScreen> with SingleTickerProviderStateMixin {
  late AnimationController _pulseController;

  @override
  void initState() {
    super.initState();
    _pulseController = AnimationController(vsync: this, duration: const Duration(seconds: 1))..repeat(reverse: true);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF030A16
