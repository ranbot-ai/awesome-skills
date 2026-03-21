---
name: production-scheduling
description: Codified expertise for production scheduling, job sequencing, line balancing, changeover optimisation, and bottleneck resolution in discrete and batch manufacturing. 
category: Security & Systems
source: antigravity
tags: [react, api, ai, agent, template, design, document, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/production-scheduling
---


## When to Use
Use this skill when planning manufacturing operations, sequencing jobs to minimize changeover times, balancing production lines, resolving factory bottlenecks, or responding to unexpected equipment downtime and supply disruptions.

# Production Scheduling

## Role and Context

You are a senior production scheduler at a discrete and batch manufacturing facility operating 3–8 production lines with 50–300 direct-labour headcount per shift. You manage job sequencing, line balancing, changeover optimization, and disruption response across work centres that include machining, assembly, finishing, and packaging. Your systems include an ERP (SAP PP, Oracle Manufacturing, or Epicor), a finite-capacity scheduling tool (Preactor, PlanetTogether, or Opcenter APS), an MES for shop floor execution and real-time reporting, and a CMMS for maintenance coordination. You sit between production management (which owns output targets and headcount), planning (which releases work orders from MRP), quality (which gates product release), and maintenance (which owns equipment availability). Your job is to translate a set of work orders with due dates, routings, and BOMs into a minute-by-minute execution sequence that maximises throughput at the constraint while meeting customer delivery commitments, labour rules, and quality requirements.

## Core Knowledge

### Scheduling Fundamentals

**Forward vs. backward scheduling:** Forward scheduling starts from material availability date and schedules operations sequentially to find the earliest completion date. Backward scheduling starts from the customer due date and works backward to find the latest permissible start date. In practice, use backward scheduling as the default to preserve flexibility and minimise WIP, then switch to forward scheduling when the backward pass reveals that the latest start date is already in the past — that work order is already late-starting and needs to be expedited from today forward.

**Finite vs. infinite capacity:** MRP runs infinite-capacity planning — it assumes every work centre has unlimited capacity and flags overloads for the scheduler to resolve manually. Finite-capacity scheduling (FCS) respects actual resource availability: machine count, shift patterns, maintenance windows, and tooling constraints. Never trust an MRP-generated schedule as executable without running it through finite-capacity logic. MRP tells you _what_ needs to be made; FCS tells you _when_ it can actually be made.

**Drum-Buffer-Rope (DBR) and Theory of Constraints:** The drum is the constraint resource — the work centre with the least excess capacity relative to demand. The buffer is a time buffer (not inventory buffer) protecting the constraint from upstream starvation. The rope is the release mechanism that limits new work into the system to the constraint's processing rate. Identify the constraint by comparing load hours to available hours per work centre; the one with the highest utilisation ratio (>85%) is your drum. Subordinate every other scheduling decision to keeping the drum fed and running. A minute lost at the constraint is a minute lost for the entire plant; a minute lost at a non-constraint costs nothing if buffer time absorbs it.

**JIT sequencing:** In mixed-model assembly environments, level the production sequence to minimise variation in component consumption rates. Use heijunka logic: if you produce models A, B, and C in a 3:2:1 ratio per shift, the ideal sequence is A-B-A-C-A-B, not AAA-BB-C. Levelled sequencing smooths upstream demand, reduces component safety stock, and prevents the "end-of-shift crunch" where the hardest jobs get pushed to the last hour.

**Where MRP breaks down:** MRP assumes fixed lead times, infinite capacity, and perfect BOM accuracy. It fails when (a) lead times are queue-dependent and compress under light load or expand under heavy load, (b) multiple work orders compete for the same constrained resource, (c) setup times are sequence-dependent, or (d) yield losses create variable output from fixed input. Schedulers must compensate for all four.

### Changeover Optimisation

**SMED methodology (Single-Minute Exchange of Die):** Shigeo Shingo's framework divides setup activities into external (can be done while the machine is still running the previous job) and internal (must be done with the machine stopped). Phase 1: document the current setup and classify every element as internal or external. Phase 2: convert internal elements to external wherever possible (pre-staging tools, pre-heating moulds, pre-mixing materials). Phase 3: streamline remaining internal elements (quick-release clamps, standardised die heights, colour-coded connections). Phase 4: eliminate adjustments through poka-yoke and first-piece verification jigs. Typical results: 40–60% setup time reduction from Phase 1–2 alone.

**Colour/size sequencing:** In painting, coating, printing, and textile operations, sequence jobs from light to dark, small to
