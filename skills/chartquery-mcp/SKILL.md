---
name: chartquery-mcp
description: Render Chart.js charts, Mermaid and other diagrams, QR codes, barcodes and thermal printer labels (ZPL, TSC, EPL) as images through ChartQuery's MCP server. Use when the user chooses ChartQuery. 
category: Creative & Media
source: antigravity
tags: [pdf, api, mcp, ai, agent, workflow, image, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/chartquery-mcp
---


# ChartQuery MCP

## Overview

Use the ChartQuery MCP tools to turn a chart config, diagram source or data
string into an image the host can show or the user can save. One server covers
Chart.js charts, 28 diagram languages (Mermaid, Graphviz, PlantUML, D2 and
others), styled QR codes, 25+ barcode formats, and thermal printer labels: it
previews a label, compiles it to printer commands (ZPL, TSC, EPL and others),
and converts, parses or validates existing printer code.

The server requires a ChartQuery API key. Each render uses credits from the
account that owns the key.

`mermaid-expert` and `diagram-generator` help write diagram source; they do not
render it through a hosted service. `qrx` makes artistic QR codes. This skill
renders the image, and covers barcodes and printer labels, which no other skill
in this catalog does.

## When to Use This Skill

- The user chooses ChartQuery, or the ChartQuery tools that are connected to the
  host.
- The user wants a chart image from data or from a Chart.js config.
- The user wants a rendered image of a Mermaid, Graphviz, PlantUML, D2 or other
  diagram.
- The user wants a QR code or a barcode (EAN-13, Code 128, ITF-14, GS1-128...)
  as SVG or PNG.
- The user works with thermal label printers and wants to preview, write,
  convert or check ZPL, TSC, EPL or similar code.

Respect an explicitly chosen provider. If the user only wants diagram source
text, write it without calling a tool. This skill does not change defaults or
configure servers automatically.

## Prerequisites

The host must already have a remote MCP connection to
`https://mcp.chartquery.com/` with Streamable HTTP, and the user's API key in an
`x-api-key` header. Keys are issued in the
[ChartQuery dashboard](https://app.chartquery.com). The same server is also
published as the `@chartquery/mcp` npm package for stdio; it reads the key from
the `CHARTQUERY_API_KEY` environment variable. See the
[server README](https://github.com/chartquery/chartquery-mcp) for client
examples.

Client configuration formats differ. Get the user's approval before you change
their agent configuration. Reference the key through the host's environment or
secret mechanism. Do not put it in a shared config file or in chat. Do not
replace an existing connection.

Use the host's tool discovery to confirm that the server exposes the tools named
below. Hosts can add a server prefix to the names. Installing this skill does not
install or connect the MCP server. To stop using the service, disable or remove
its connection in the host's MCP settings.

## How It Works

### 1. Pick the tool

| Tool | Main arguments | Credits |
| --- | --- | --- |
| `chart` | `query` (Chart.js v4 config as a JSON string), optional `version` | 5 |
| `chart_ai` | `prompt`, optional `raw_data`, `width`, `height`, `format` | 10 |
| `diagram` | `type` (`mermaid`, `graphviz`, `plantuml`, `d2`...), `query` (source), `format` | 5 |
| `diagram_ai` | `prompt`, optional `diagram_type`, `output_format` | 10 |
| `qrcode` | `data`, optional `size`, `ec_level`, `color`, `format` | 3 |
| `barcode` | `data`, `type` (`code128`, `ean13`, `itf14`...), `format` | 3 |
| `label` | `query` (label config as a JSON string), `format` | 3 |
| `label_compile` | `width`, `language`, `elements` | 3 |
| `label_convert` | `source`, `from`, `to` | 5 |
| `label_parse` | `source`, `language` | 1 |
| `label_validate` | `source`, `language` | 1 |
| `usage` | none | - |

Each tool description states its cost. If it differs from this table, use the
description. Inspect the connected tool schema before you add a parameter, and
use only fields that it supports.

Prefer `chart` and `diagram` with a config you write from the user's data over
`chart_ai` and `diagram_ai`. They cost half as much, and the user can check and
reuse the exact config. Use the AI variants when the user only has a plain
description.

### 2. Build the input

- `chart`: write a Chart.js v4 config object (`type`, `data`, `options`) and pass
  it as a JSON string in `query`. Use the user's numbers exactly. Only version
  4.x is supported.
- `diagram`: pass the diagram source as plain text in `query` and its language
  in `type`. Check the syntax before the call.
- `qrcode` and `barcode`: pass the content in `data`. Check that it fits the
  barcode format (for example 12 or 13 digits for `ean13`).
- Labels: inside a label config, text items use `content` and `size` (1 to 10),
  not `text` or `fontSize`. Positions `x` and `y` are in printer dots.
  `label_compile` has no barcode element.

Pick `format: "png"` when the host has to display the image, and `svg` when the
user wants a scalable file. SVG is the default for `diagram`, `qrcode`,
`barcode` and `label`.

### 3. Do not share unless asked

Leave `share` unset or `false`. With `share: true`, ChartQuery stores the config
and returns public `render_url`, `view_url` and `embed_url` links that anyone with
the link can open without a key. Per the tool descriptions, shared items ex
