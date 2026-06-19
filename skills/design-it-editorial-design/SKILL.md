---
name: editorial-design
description: Web and App implementation guide for Editorial Design. Trigger when user wants a magazine-inspired layout, large headlines, and elegant typography pairing. 
category: Creative & Media
source: antigravity
tags: [react, ai, llm, design, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/editorial-design
---


# Editorial Design

> "The digital magazine. Sophisticated typography pairings and deliberate, elegant pacing."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Serif & Sans-Serif Pairing**: The hallmark of editorial design. A beautiful, high-contrast serif for headings, paired with a clean sans-serif for body copy.
2. **Large Drop Caps & Pull Quotes**: Typographic flourishes that guide the eye and break up long blocks of text.
3. **Columnar Layouts**: Content flows in distinct columns, often with fine lines (rules) separating them.

## Visual DNA
- **Colors**: **Modern Editorial** or **Yacht Club**. Warm, paper-like backgrounds with deep, ink-like blacks or navy blues.
- **Typography**: 
  - Headlines: `Playfair Display`, `Merriweather`, `Bodoni`.
  - Body: `Lato`, `Open Sans`, `Source Sans Pro`.
- **Borders**: Thin, elegant horizontal lines (hairlines) used to separate sections.

## Web Implementation
- **CSS Example**:
```css
body {
  background-color: #F9F9F9; /* Paper white */
  color: #121212; /* Ink black */
}

/* Typography Pairing */
.editorial-headline {
  font-family: 'Playfair Display', serif;
  font-size: 4rem;
  font-weight: 700;
  font-style: italic;
  margin-bottom: 24px;
  border-bottom: 1px solid #121212;
  padding-bottom: 24px;
}

.editorial-body {
  font-family: 'Lato', sans-serif;
  font-size: 1.1rem;
  line-height: 1.8;
  column-count: 2; /* Magazine columns */
  column-gap: 40px;
}

/* Drop Cap */
.editorial-body::first-letter {
  font-family: 'Playfair Display', serif;
  font-size: 4rem;
  float: left;
  line-height: 0.8;
  padding-right: 12px;
  color: var(--cta-highlight);
}

.pull-quote {
  font-family: 'Playfair Display', serif;
  font-size: 2rem;
  text-align: center;
  margin: 48px 0;
  padding: 24px 0;
  border-top: 2px solid #121212;
  border-bottom: 2px solid #121212;
}
```

## App Implementation

### SwiftUI
```swift
struct EditorialView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                // Editorial Headline
                Text("The Digital\nMagazine")
                    .font(.custom("Playfair Display", size: 48))
                    .fontWeight(.bold)
                    .italic()
                    .foregroundColor(Color(white: 0.05))
                    .padding(.bottom, 16)
                
                Divider().background(Color.black)
                
                // Drop Cap and Body
                HStack(alignment: .top, spacing: 8) {
                    Text("I")
                        .font(.custom("Playfair Display", size: 64))
                        .foregroundColor(Color(red: 0.7, green: 0.2, blue: 0.2))
                        // Negative padding to pull the body text tighter to the drop cap
                        .padding(.top, -10) 
                    
                    Text("n an era of sterile, flat interfaces, the return to elegant typography feels like a breath of fresh air. The interplay of serif and sans-serif...")
                        .font(.custom("Lato", size: 16))
                        .lineSpacing(6)
                        .foregroundColor(Color(white: 0.1))
                }
                
                // Pull Quote
                VStack {
                    Divider().background(Color.black)
                    Text("“Sophistication is in the spacing.”")
                        .font(.custom("Playfair Display", size: 28))
                        .italic()
                        .multilineTextAlignment(.center)
                        .padding(.vertical, 24)
                    Divider().background(Color.black)
                }
                .padding(.vertical, 24)
            }
            .padding(24)
        }
        .background(Color(red: 0.98, green: 0.98, blue: 0.96)) // Warm paper white
    }
}
```
- Extensive use of `.font(.custom())` is mandatory. System fonts look too app-like.
- Use `Divider()` to create the hairlines that are so common in print design.
- A fake "drop cap" can be achieved with an `HStack` aligning top.

### Flutter
```dart
class EditorialScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFFF9F9F8), // Paper background
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(24.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const SizedBox(height: 40),
            const Text(
              'The Digital\nMagazine',
              style: TextStyle(fontFamily: 'PlayfairDisplay', fontSize: 48, fontWeight: FontWeight.bold, fontStyle: FontStyle.italic, height: 1.1),
            ),
            const SizedBox(height: 24),
            const Divider(color: Colors.black, thickness: 1)
