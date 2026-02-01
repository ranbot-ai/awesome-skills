---
name: d3-viz
description: Creating interactive data visualisations using d3.js. This skill should be used when creating custom charts, graphs, network diagrams, geographic visualisations, or any complex SVG-based data visualis
category: Document Processing
source: antigravity
tags: [javascript, react, node, ai, workflow, template, document, rag, seo, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/claude-d3js-skill
---


# D3.js Visualisation

## Overview

This skill provides guidance for creating sophisticated, interactive data visualisations using d3.js. D3.js (Data-Driven Documents) excels at binding data to DOM elements and applying data-driven transformations to create custom, publication-quality visualisations with precise control over every visual element. The techniques work across any JavaScript environment, including vanilla JavaScript, React, Vue, Svelte, and other frameworks.

## When to use d3.js

**Use d3.js for:**
- Custom visualisations requiring unique visual encodings or layouts
- Interactive explorations with complex pan, zoom, or brush behaviours
- Network/graph visualisations (force-directed layouts, tree diagrams, hierarchies, chord diagrams)
- Geographic visualisations with custom projections
- Visualisations requiring smooth, choreographed transitions
- Publication-quality graphics with fine-grained styling control
- Novel chart types not available in standard libraries

**Consider alternatives for:**
- 3D visualisations - use Three.js instead

## Core workflow

### 1. Set up d3.js

Import d3 at the top of your script:

```javascript
import * as d3 from 'd3';
```

Or use the CDN version (7.x):

```html
<script src="https://d3js.org/d3.v7.min.js"></script>
```

All modules (scales, axes, shapes, transitions, etc.) are accessible through the `d3` namespace.

### 2. Choose the integration pattern

**Pattern A: Direct DOM manipulation (recommended for most cases)**
Use d3 to select DOM elements and manipulate them imperatively. This works in any JavaScript environment:

```javascript
function drawChart(data) {
  if (!data || data.length === 0) return;

  const svg = d3.select('#chart'); // Select by ID, class, or DOM element

  // Clear previous content
  svg.selectAll("*").remove();

  // Set up dimensions
  const width = 800;
  const height = 400;
  const margin = { top: 20, right: 30, bottom: 40, left: 50 };

  // Create scales, axes, and draw visualisation
  // ... d3 code here ...
}

// Call when data changes
drawChart(myData);
```

**Pattern B: Declarative rendering (for frameworks with templating)**
Use d3 for data calculations (scales, layouts) but render elements via your framework:

```javascript
function getChartElements(data) {
  const xScale = d3.scaleLinear()
    .domain([0, d3.max(data, d => d.value)])
    .range([0, 400]);

  return data.map((d, i) => ({
    x: 50,
    y: i * 30,
    width: xScale(d.value),
    height: 25
  }));
}

// In React: {getChartElements(data).map((d, i) => <rect key={i} {...d} fill="steelblue" />)}
// In Vue: v-for directive over the returned array
// In vanilla JS: Create elements manually from the returned data
```

Use Pattern A for complex visualisations with transitions, interactions, or when leveraging d3's full capabilities. Use Pattern B for simpler visualisations or when your framework prefers declarative rendering.

### 3. Structure the visualisation code

Follow this standard structure in your drawing function:

```javascript
function drawVisualization(data) {
  if (!data || data.length === 0) return;

  const svg = d3.select('#chart'); // Or pass a selector/element
  svg.selectAll("*").remove(); // Clear previous render

  // 1. Define dimensions
  const width = 800;
  const height = 400;
  const margin = { top: 20, right: 30, bottom: 40, left: 50 };
  const innerWidth = width - margin.left - margin.right;
  const innerHeight = height - margin.top - margin.bottom;

  // 2. Create main group with margins
  const g = svg.append("g")
    .attr("transform", `translate(${margin.left},${margin.top})`);

  // 3. Create scales
  const xScale = d3.scaleLinear()
    .domain([0, d3.max(data, d => d.x)])
    .range([0, innerWidth]);

  const yScale = d3.scaleLinear()
    .domain([0, d3.max(data, d => d.y)])
    .range([innerHeight, 0]); // Note: inverted for SVG coordinates

  // 4. Create and append axes
  const xAxis = d3.axisBottom(xScale);
  const yAxis = d3.axisLeft(yScale);

  g.append("g")
    .attr("transform", `translate(0,${innerHeight})`)
    .call(xAxis);

  g.append("g")
    .call(yAxis);

  // 5. Bind data and create visual elements
  g.selectAll("circle")
    .data(data)
    .join("circle")
    .attr("cx", d => xScale(d.x))
    .attr("cy", d => yScale(d.y))
    .attr("r", 5)
    .attr("fill", "steelblue");
}

// Call when data changes
drawVisualization(myData);
```

### 4. Implement responsive sizing

Make visualisations responsive to container size:

```javascript
function setupResponsiveChart(containerId, data) {
  const container = document.getElementById(containerId);
  const svg = d3.select(`#${containerId}`).append('svg');

  function updateChart() {
    const { width, height } = container.getBoundingClientRect();
    svg.attr('width', width).attr('height', height);

    // Redraw visualisation with new dimensions
    drawChart(data, svg, width, height);
  }

  // Update on initial load
  updateChart();

  // Update on window resize
  window
