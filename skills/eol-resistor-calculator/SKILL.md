---
name: eol-resistor-calculator
description: Calculates and validates end-of-line (EOL, SEOL, DEOL, TEOL) resistor loops for intrusion alarm panels (Honeywell, DSC, Paradox, Bosch) with wire gauge drop and state tables. Trigger phrases: eol resi
category: Document Processing
source: antigravity
tags: [python, markdown, claude, ai, workflow, design, document, security, rag, seo]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/eol-resistor-calculator
---


# EOL Resistor Calculator: Precision Intrusion Loop Supervision & State Solver

Accurately size, configure, and troubleshoot Single (SEOL), Double (DEOL), and Triple (TEOL) end-of-line resistor loops across major security panel architectures with copper wire drop compensation and tamper state discrimination.

## When to Use This Skill

Activate this skill when:
- Sizing, retrofitting, or diagnosing hardwired security loops on alarm panels (DSC PowerSeries/Neo, Honeywell Ademco Vista, Paradox EVO/Spectra, Bosch B/G Series, Texecom Premier Elite).
- The user asks: "How do I wire double EOL on a DSC panel?", "Calculate zone loop resistance for a 200m cable run", "Troubleshoot a constant zone tamper fault", or "What resistor values does Honeywell Vista use?".
- Differentiating between Normal, Alarm, Tamper (Short), and Cut (Open) circuit states across varying panel threshold windows.
- Sizing copper loop resistance drops on long perimeter runs (e.g. 22 AWG over 150+ meters) to prevent phantom false alarms.

Do NOT use this skill when:
- Designing wireless sensors or addressable polling loop multiplexers (polling loops use digital transponders, not passive EOL resistors).
- Bypassing safety or life-safety supervision circuits (never advise strapping out resistors or bypassing line supervision).
- Working on 2-wire smoke detector loops without consulting panel-specific smoke circuit polarity and current-limiting specs.

## Core Mental Models & Non-Negotiable Rules

1. **The Far-End Placement Axiom (Strict Anti-Panel Stacking)**:
   - Resistors MUST be installed **inside the sensor housing at the farthest physical end of the cable run**.
   - Placing resistors across screw terminals inside the alarm panel enclosure protects only the metal cabinet itself; the entire 50-meter cable run to the sensor is left vulnerable to undetected wire cuts or staple shorts.
   - Any wiring diagram showing EOL resistors at the panel board for field sensors is flagged as a Grade 2/Grade 3 compliance violation.

2. **The 4-State Double-EOL (DEOL) Truth Table**:
   - Double EOL uses two resistors: an End-of-Line resistor ($R_{EOL}$) and an Alarm contact resistor ($R_{ALARM}$).
   - Standard series-parallel configuration (e.g., DSC standard 5.6k / 5.6k):
     $$\text{Loop State} = \begin{cases} 
     0\ \Omega\ (\text{Short Circuit}) & \implies \mathbf{Tamper\ (Short)} \\
     R_{EOL}\ (5.6\text{k}\ \Omega) & \implies \mathbf{Normal\ (Secure)} \\
     R_{EOL} + R_{ALARM}\ (11.2\text{k}\ \Omega) & \implies \mathbf{Alarm\ (Tripped)} \\
     \infty\ \Omega\ (\text{Open Circuit}) & \implies \mathbf{Tamper\ (Cut\ Wire)}
     \end{cases}$$
   - This provides complete supervised discrimination between intruder activation and physical sabotage.

3. **Copper Wire Resistance Compensation Formula**:
   - Long field cable runs add series loop resistance across both conductors:
     $$R_{loop} = 2 \times D \times \rho_{gauge}$$
     where $D$ is one-way distance in meters, and $\rho_{gauge}$ is resistance per meter:
     - **22 AWG (0.326 mm²)**: $0.053\ \Omega/\text{meter}$ ($16.14\ \Omega/1000\text{ft}$)
     - **20 AWG (0.518 mm²)**: $0.033\ \Omega/\text{meter}$ ($10.15\ \Omega/1000\text{ft}$)
     - **18 AWG (0.823 mm²)**: $0.021\ \Omega/\text{meter}$ ($6.38\ \Omega/1000\text{ft}$)
   - A 150m run of 22 AWG adds $2 \times 150 \times 0.053 \approx 15.9\ \Omega$. Ensure total loop resistance does not push readings beyond the panel's $\pm 15\%$ ADC tolerance window.

4. **Panel Reference Resistor Standards Matrix**:
   - **DSC PowerSeries / Neo**: $5.6\text{k}\ \Omega$ SEOL / $5.6\text{k} + 5.6\text{k}$ DEOL.
   - **Honeywell Ademco Vista**: $2.0\text{k}\ \Omega$ SEOL (Standard zones), $1.0\text{k}$ (Zone 1 on some models).
   - **Paradox EVO / Spectra**: $1.0\text{k}\ \Omega$ SEOL / $1.0\text{k} + 1.0\text{k}$ DEOL (or ATZ mode with $1.0\text{k} / 2.2\text{k}$).
   - **Bosch B / G Series**: Dual supervision with $1.0\text{k} / 2.0\text{k}$ or panel-selectable windows.
   - **Texecom Premier Elite**: $2.2\text{k} / 4.7\text{k}$ or selectable Grade 3 Triple-EOL ($4.7\text{k} / 4.7\text{k} / 2.2\text{k}$ anti-mask).

5. **ADC Voltage Divider Acceptance Windows**:
   - Security panels measure zone voltage through an internal pull-up resistor ($R_{pullup}$, typically $1\text{k}$ to $3.3\text{k}\ \Omega$) connected to a reference voltage ($V_{ref}$, typically $5.0\text{V}$ or $13.8\text{V}$).
   - Terminal voltage is given by:
     $$V_{zone} = V_{ref} \times \frac{R_{loop\_total}}{R_{pullup} + R_{loop\_total}}$$
   - Always confirm whether a measured terminal voltage falls inside the manufacturer's specified ADC threshold window before replacing field hardware.

## Named Sins & Anti-Patterns (Что категорически ЗАПРЕЩЕНО)

| Anti-Pattern | Manifestation in Code/Workflow | Mandatory Production Counter-Rule |
| :--- | :--- | :--- |
| **Panel-Terminal Resistor Stacking** | Crimping EOL resistors into the screw terminals on the panel PCB. | Install resist
