---
name: dashboard-design
description: Web and App implementation guide for Dashboard Design. Trigger when user wants analytics-focused layouts, data visualization, and modular overview screens. 
category: Creative & Media
source: antigravity
tags: [react, ai, llm, template, design, image, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/design-it/dashboard-design
---


# Dashboard Design

> "Data at a glance. Organized, scannable, and highly functional."


## When to Use
Use this sub-style when the user's request matches the aesthetic described above. This is a child reference of the `design-it` skill and is not meant to be triggered directly.

## Core Principles
1. **Modular Grid**: The screen is broken down into functional "widgets" or cards. Usually a sidebar on the left and a top nav.
2. **Data Hierarchy**: The most important numbers (KPIs) are large and usually at the top. Charts take up the middle, and lists/tables are at the bottom.
3. **Muted Backgrounds**: A soft grey or off-white background so the white data cards stand out clearly.

## Visual DNA
- **Colors**: **Minimalist Slate** or **Earth-Grounded Elegance**. Avoid too many colors. Use red/green strictly for positive/negative trends.
- **Typography**: Clean, tabular sans-serifs (`Inter`, `Roboto Mono` for numbers).
- **Styling**: Very subtle shadows or 1px borders to separate cards.

## Web Implementation
- Use CSS Grid for the macro layout (Sidebar, Header, Main).
- **CSS Example**:
```css
body {
  background-color: #F8F9FA;
  color: #212529;
  font-family: 'Inter', sans-serif;
  margin: 0;
}

.dashboard-layout {
  display: grid;
  grid-template-columns: 250px 1fr;
  grid-template-rows: 70px 1fr;
  height: 100vh;
}

.sidebar {
  grid-row: 1 / 3;
  background-color: #ffffff;
  border-right: 1px solid #e9ecef;
  padding: 20px;
}

.header {
  background-color: #ffffff;
  border-bottom: 1px solid #e9ecef;
  padding: 0 30px;
  display: flex;
  align-items: center;
}

.main-content {
  padding: 30px;
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 20px;
  overflow-y: auto;
}

/* KPI Card */
.kpi-card {
  background: #fff;
  border-radius: 8px;
  padding: 24px;
  border: 1px solid #e9ecef;
  box-shadow: 0 2px 4px rgba(0,0,0,0.02);
}

.kpi-title { font-size: 0.9rem; color: #6c757d; }
.kpi-value { font-size: 2rem; font-weight: 700; margin-top: 8px; }
.kpi-trend.positive { color: #28a745; }
```

## App Implementation

### SwiftUI
```swift
struct DashboardView: View {
    // For iPad/Mac, NavigationSplitView is ideal.
    // For iPhone, we use a scrolling VGrid.
    let columns = [
        GridItem(.adaptive(minimum: 150), spacing: 16)
    ]
    
    var body: some View {
        NavigationView {
            ScrollView {
                LazyVGrid(columns: columns, spacing: 16) {
                    KPICard(title: "Revenue", value: "$45,231", trend: "+12.5%", isPositive: true)
                    KPICard(title: "Active Users", value: "2,405", trend: "+4.1%", isPositive: true)
                    KPICard(title: "Churn Rate", value: "1.2%", trend: "-0.4%", isPositive: false)
                    KPICard(title: "Avg. Session", value: "4m 12s", trend: "+0.1%", isPositive: true)
                }
                .padding()
                
                // Placeholder for Chart
                RoundedRectangle(cornerRadius: 12)
                    .fill(Color.white)
                    .frame(height: 250)
                    .overlay(Text("Chart Area").foregroundColor(.gray))
                    .padding(.horizontal)
            }
            .background(Color(UIColor.systemGroupedBackground))
            .navigationTitle("Overview")
        }
    }
}

struct KPICard: View {
    let title: String
    let value: String
    let trend: String
    let isPositive: Bool
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.subheadline).foregroundColor(.secondary)
            Text(value).font(.title2).fontWeight(.bold)
            Text(trend)
                .font(.caption)
                .fontWeight(.semibold)
                .foregroundColor(isPositive ? .green : .red)
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.white)
        .cornerRadius(12)
        .shadow(color: Color.black.opacity(0.02), radius: 4, y: 2)
    }
}
```
- Dashboards require `.adaptive` grids. `LazyVGrid` handles rearranging 4 cards in a row on iPad down to 2 cards on iPhone automatically.
- Use `Color(UIColor.systemGroupedBackground)` to provide that subtle off-white contrast against stark white cards.

### Flutter
```dart
class DashboardScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFFF8F9FA),
      appBar: AppBar(
        title: const Text('Overview', style: TextStyle(color: Colors.black)),
        backgroundColor: Colors.white,
        elevation: 1,
      ),
      // On tablets, use a Row with NavigationRail. On mobile, use Drawer.
      drawer: const Drawer(), 
      body: CustomScrollView(
        slivers: [
          SliverPadding(
            padding: const EdgeInsets.all(16),
            sliver: SliverGrid.extent(
              maxCrossAxisExtent: 200, // Adapts layout based on width
              mainAxisSpacing: 16
