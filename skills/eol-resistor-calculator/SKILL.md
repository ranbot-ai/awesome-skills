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
   - Use the exact listed installation and grading rules; this guide cannot certify Grade2/Grade3 compliance.

2. **The 4-State Double-EOL (DEOL) Truth Table**:
   - Double EOL uses two resistors: an End-of-Line resistor ($R_{EOL}$) and an Alarm contact resistor ($R_{ALARM}$).
   - Standard series-parallel configuration (e.g., DSC standard 5.6k / 5.6k):
     $$\text{Loop State} = \begin{cases} 
     0\ \Omega\ (\text{Short Circuit}) & \implies \mathbf{Fault\ (Short)} \\
     R_{EOL}\ (5.6\text{k}\ \Omega) & \implies \mathbf{Normal\ (Secure)} \\
     R_{EOL} + R_{ALARM}\ (11.2\text{k}\ \Omega) & \implies \mathbf{Alarm\ (Tripped)} \\
     \infty\ \Omega\ (\text{Open Circuit}) & \implies \mathbf{Tamper\ (Cut\ Wire)}
     \end{cases}$$
   - These electrical states aid supervision; they do not prove the cause or rule out sabotage.

3. **Copper Wire Resistance Compensation Formula**:
   - Long field cable runs add series loop resistance across both conductors:
     $$R_{loop} = 2 \times D \times \rho_{gauge}$$
     where $D$ is one-way distance in meters, and $\rho_{gauge}$ is resistance per meter:
     - **22 AWG (0.326 mm²)**: $0.053\ \Omega/\text{meter}$ ($16.14\ \Omega/1000\text{ft}$)
     - **20 AWG (0.518 mm²)**: $0.033\ \Omega/\text{meter}$ ($10.15\ \Omega/1000\text{ft}$)
     - **18 AWG (0.823 mm²)**: $0.021\ \Omega/\text{meter}$ ($6.38\ \Omega/1000\text{ft}$)
   - A 150m run of 22 AWG adds $2 \times 150 \times 0.053 \approx 15.9\ \Omega$. Ensure total loop resistance does not push readings beyond the panel's documented resistance windows, allowing for resistor/cable/temperature tolerances.

4. **Model-specific reference values**:
   - The cited PowerSeries Neo manual shows5600Ω secure,11200Ω violated,0Ω fault and open-circuit tamper for its DEOL configuration.
   - Do not generalize values across Honeywell, Paradox, Bosch, Texecom or even different zones/configurations of the same model. Obtain the exact installation manual and zone programming first.

5. **ADC Voltage Divider Acceptance Windows**:
   - Security panels measure zone voltage through an internal pull-up resistor ($R_{pullup}$, typically $1\text{k}$ to $3.3\text{k}\ \Omega$) connected to a reference voltage ($V_{ref}$, typically $5.0\text{V}$ or $13.8\text{V}$).
   - Terminal voltage is given by:
     $$V_{zone} = V_{ref} \times \frac{R_{loop\_total}}{R_{pullup} + R_{loop\_total}}$$
   - Always confirm whether a measured terminal voltage falls inside the manufacturer's specified ADC threshold window before replacing field hardware.

## Named Sins & Anti-Patterns (Что категорически ЗАПРЕЩЕНО)

| Anti-Pattern | Manifestation in Code/Workflow | Mandatory Production Counter-Rule |
| :--- | :--- | :--- |
| **Panel-Terminal Resistor Stacking** | Crimping EOL resistors into the screw terminals on the panel PCB. | Install resistors exclusively inside the remote sensor housing. |
| **Vendor Value Cross-Contamination** | Using another panel’s resistor value without checking the exact zone manual. | Verify panel model and enforce manufacturer-specific resistance ratings. |
| **DEOL Series/Parallel Inversi
