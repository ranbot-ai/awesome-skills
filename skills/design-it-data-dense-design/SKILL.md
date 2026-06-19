---
name: data-dense-design
description: Web and App implementation guide for Data-Dense Design. Trigger when user wants professional tools, maximum information density, and expert interfaces (like Bloomberg terminals or IDEs). 
category: Document Processing
source: antigravity
tags: [react, ai, llm, design, spreadsheet, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/data-dense-design
---


# Data-Dense Design

> "Density is a feature. For expert users, reducing clicks is more important than whitespace."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Compact Layouts**: Extremely tight margins and padding (often 2px to 4px).
2. **Monospace & Tabular Data**: Numbers must align vertically perfectly. 
3. **High Utility**: Every pixel serves a functional purpose. Minimal purely decorative elements.

## Visual DNA
- **Colors**: **Industrial Chic** (high contrast) or **Minimalist Slate**. Avoid bright backgrounds. Dark themes are heavily preferred to reduce eye strain over 8-hour sessions.
- **Typography**: Small base sizes (`11px` - `13px`). Strict use of monospace fonts (`Fira Code`, `JetBrains Mono`) for data.
- **Borders**: Thin `1px` borders (`#333` or `#e0e0e0`) are used extensively to separate tiny cells of data.

## Web Implementation
- Tables, CSS Grid, and Flexbox with zero gap.
- **CSS Example**:
```css
body {
  background-color: #1e1e1e; /* IDE Dark */
  color: #cccccc;
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  font-size: 12px; /* Very small */
  margin: 0;
}

.dense-toolbar {
  display: flex;
  background-color: #2d2d2d;
  border-bottom: 1px solid #3c3c3c;
  padding: 2px 4px;
}

.dense-btn {
  background: transparent;
  color: #ccc;
  border: 1px solid transparent;
  padding: 2px 8px;
  border-radius: 2px;
  cursor: pointer;
}
.dense-btn:hover {
  background-color: #3c3c3c;
  border-color: #555;
}

/* Dense Data Table */
.data-table {
  width: 100%;
  border-collapse: collapse;
  font-family: 'JetBrains Mono', monospace;
}

.data-table th, .data-table td {
  padding: 4px 8px;
  border: 1px solid #3c3c3c;
  text-align: right; /* Numbers align right */
}

.data-table tr:nth-child(even) { background-color: #252526; }
.data-table tr:hover { background-color: #094771; color: #fff; } /* Selection highlight */
```

## App Implementation

### SwiftUI
```swift
struct DataDenseView: View {
    var body: some View {
        ScrollView([.horizontal, .vertical]) {
            Grid(horizontalSpacing: 0, verticalSpacing: 0) {
                // Header Row
                GridRow {
                    HeaderCell("SYM")
                    HeaderCell("BID")
                    HeaderCell("ASK")
                    HeaderCell("CHG")
                }
                
                // Data Rows
                DataRow(sym: "AAPL", bid: "173.40", ask: "173.45", chg: "+0.12", isPos: true)
                DataRow(sym: "MSFT", bid: "320.10", ask: "320.15", chg: "-0.45", isPos: false)
                DataRow(sym: "GOOG", bid: "135.20", ask: "135.30", chg: "+0.02", isPos: true)
            }
            .border(Color.gray.opacity(0.3), width: 1)
        }
        .background(Color(white: 0.12)) // Dark IDE background
    }
}

struct HeaderCell: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text)
            .font(.system(size: 11, weight: .bold, design: .monospaced))
            .foregroundColor(.gray)
            .padding(4)
            .frame(minWidth: 60, alignment: .leading)
            .border(Color.gray.opacity(0.3), width: 0.5)
            .background(Color(white: 0.18))
    }
}

struct DataRow: View {
    let sym, bid, ask, chg: String
    let isPos: Bool
    var body: some View {
        GridRow {
            Cell(sym, color: .white)
            Cell(bid, color: .white, align: .trailing)
            Cell(ask, color: .white, align: .trailing)
            Cell(chg, color: isPos ? .green : .red, align: .trailing)
        }
    }
}

struct Cell: View {
    let text: String
    let color: Color
    let align: Alignment
    init(_ text: String, color: Color, align: Alignment = .leading) {
        self.text = text; self.color = color; self.align = align
    }
    var body: some View {
        Text(text)
            .font(.system(size: 12, design: .monospaced))
            .foregroundColor(color)
            .padding(4)
            .frame(minWidth: 60, alignment: align)
            .border(Color.gray.opacity(0.3), width: 0.5)
    }
}
```
- Use `Grid` with `0` spacing.
- Font must be `.system(..., design: .monospaced)`.
- Use a `.border()` with `0.5` width on every single cell to recreate the dense spreadsheet look.

### Flutter
```dart
class DataDenseScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF1E1E1E),
      body: SingleChildScrollView(
        scrollDirection: Axis.vertical,
        child: SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          child: Theme(
            // Override theme specifically to make the table hyper-dense
            data: Theme.of(context).copyWith(
              dividerColor: Colors.grey[800],
           
