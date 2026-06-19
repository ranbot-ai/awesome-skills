---
name: bento-ui
description: Web and App implementation guide for Bento UI. Trigger when user wants modular grid cards, Apple-like dashboard style, or sections arranged like a bento box. 
category: Creative & Media
source: antigravity
tags: [react, ai, llm, template, design, image, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/bento-ui
---


# Bento UI

> "Everything in its right place. A highly structured, modular grid of distinct compartments."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Strict Grid Structure**: The entire UI is built on a responsive, multi-column grid (usually 3x3, 4x4, or irregular masonry).
2. **Rounded Compartments**: Every distinct piece of content lives inside a card (compartment) with consistent, usually large, border-radius.
3. **Equal Spacing**: The gap between compartments must be perfectly consistent everywhere.

## Visual DNA
- **Colors**: Highly adaptable, but looks incredibly premium with **Minimalist Slate** or **Yacht Club**. Often uses a slightly off-white or light gray background to make the white compartments pop.
- **Typography**: Apple-esque (e.g., `SF Pro`, `Inter`). Headlines are usually bold and placed at the top-left or bottom-left of each compartment.
- **Visuals**: Often relies on high-quality, edge-to-edge images or single, large 3D icons inside specific grid cells to break up text-heavy cards.

## Web Implementation
- CSS Grid is mandatory. Flexbox is too difficult to maintain the strict 2D structure.
- **CSS Example**:
```css
.bento-container {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  grid-auto-rows: 200px;
  gap: 24px;
  padding: 24px;
  background-color: var(--bg-primary); /* Slightly darker than cards */
}

.bento-card {
  background-color: #fff;
  border-radius: 32px; /* Very large border radius */
  padding: 32px;
  box-shadow: 0 4px 24px rgba(0,0,0,0.04);
  /* Optional: subtle 1px border for crispness */
  border: 1px solid rgba(0,0,0,0.05);
  
  display: flex;
  flex-direction: column;
  justify-content: space-between;
}

/* Creating spans for different bento sizes */
.bento-span-2 { grid-column: span 2; }
.bento-span-2-row { grid-row: span 2; }
.bento-large { grid-column: span 2; grid-row: span 2; }
```

## App Implementation

### SwiftUI
```swift
struct BentoGrid: View {
    let columns = [
        GridItem(.flexible(), spacing: 16),
        GridItem(.flexible(), spacing: 16)
    ]
    
    var body: some View {
        ScrollView {
            LazyVGrid(columns: columns, spacing: 16) {
                // 2x1 Span (Full width)
                BentoCard(title: "Hero", color: .blue)
                    .frame(height: 180)
                
                // 1x1 Spans
                BentoCard(title: "Stats", color: .green)
                    .frame(height: 180)
                BentoCard(title: "Graph", color: .purple)
                    .frame(height: 180)
                
                // 1x2 Span (Tall)
                BentoCard(title: "Activity", color: .orange)
                    .frame(height: 376) // (180 * 2) + 16 spacing
                
                // 1x1 Spans next to the tall one
                VStack(spacing: 16) {
                    BentoCard(title: "A", color: .pink).frame(height: 180)
                    BentoCard(title: "B", color: .cyan).frame(height: 180)
                }
            }
            .padding(16)
        }
        .background(Color(.systemGroupedBackground))
    }
}

struct BentoCard: View {
    let title: String
    let color: Color
    var body: some View {
        RoundedRectangle(cornerRadius: 24)
            .fill(Color(.secondarySystemGroupedBackground))
            .overlay(
                Text(title).font(.headline).foregroundColor(color),
                alignment: .topLeading
            )
            .padding(16)
            // Soft bento shadow
            .shadow(color: .black.opacity(0.04), radius: 12, x: 0, y: 4)
    }
}
```
- Use `LazyVGrid` for uniform grids.
- For complex irregular bento layouts (like 1x2 spans), you often have to mix `VStack` and `HStack` inside the grid cells to fake the spans.
- Maintain absolute consistency with `cornerRadius` (usually 24-32pt) and `spacing` (usually 16pt).

### Flutter
```dart
import 'package:flutter_staggered_grid_view/flutter_staggered_grid_view.dart';

class BentoScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.grey[100],
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: StaggeredGrid.count(
          crossAxisCount: 4, // 4 columns total
          mainAxisSpacing: 16,
          crossAxisSpacing: 16,
          children: const [
            // 2x1 (Full width in a 2-col layout, spans 4)
            StaggeredGridTile.count(
              crossAxisCellCount: 4,
              mainAxisCellCount: 2,
              child: BentoCard(title: 'Hero'),
            ),
            // 1x1
            StaggeredGridTile.count(
              crossAxisCellCount: 2,
              mainAxisCellCount: 2,
              child: BentoCard(title: 'Stats'),
            ),
            // 1x1
        
