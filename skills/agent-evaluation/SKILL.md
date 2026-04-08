---
name: agent-evaluation
description: Testing and benchmarking LLM agents including behavioral testing, capability assessment, reliability metrics, and production monitoring—where even top agents achieve less than 50% on real-world benc
category: Security & Systems
source: antigravity
tags: [ai, agent, llm, workflow, design, document, security, vulnerability, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/agent-evaluation
---


# Agent Evaluation

Testing and benchmarking LLM agents including behavioral testing, capability assessment, reliability metrics, and production monitoring—where even top agents achieve less than 50% on real-world benchmarks

## Capabilities

- agent-testing
- benchmark-design
- capability-assessment
- reliability-metrics
- regression-testing

## Prerequisites

- Knowledge: Testing methodologies, Statistical analysis basics, LLM behavior patterns
- Skills_recommended: autonomous-agents, multi-agent-orchestration
- Required skills: testing-fundamentals, llm-fundamentals

## Scope

- Does_not_cover: Model training evaluation (loss, perplexity), Fairness and bias testing, User experience testing
- Boundaries: Focus is agent capability and reliability, Covers functional and behavioral testing

## Ecosystem

### Primary_tools

- AgentBench - Multi-environment benchmark for LLM agents (ICLR 2024)
- τ-bench (Tau-bench) - Sierra's real-world agent benchmark
- ToolEmu - Risky behavior detection for agent tool use
- Langsmith - LLM tracing and evaluation platform

### Alternatives

- Braintrust - When: Need production monitoring integration LLM evaluation and monitoring
- PromptFoo - When: Focus on prompt-level evaluation Prompt testing framework

### Deprecated

- Manual testing only

## Patterns

### Statistical Test Evaluation

Run tests multiple times and analyze result distributions

**When to use**: Evaluating stochastic agent behavior

interface TestResult {
    testId: string;
    runId: string;
    passed: boolean;
    score: number;  // 0-1 for partial credit
    latencyMs: number;
    tokensUsed: number;
    output: string;
    expectedBehaviors: string[];
    actualBehaviors: string[];
}

interface StatisticalAnalysis {
    passRate: number;
    confidence95: [number, number];
    meanScore: number;
    stdDevScore: number;
    meanLatency: number;
    p95Latency: number;
    behaviorConsistency: number;
}

class StatisticalEvaluator {
    private readonly minRuns = 10;
    private readonly confidenceLevel = 0.95;

    async evaluateAgent(
        agent: Agent,
        testSuite: TestCase[]
    ): Promise<EvaluationReport> {
        const results: TestResult[] = [];

        // Run each test multiple times
        for (const test of testSuite) {
            for (let run = 0; run < this.minRuns; run++) {
                const result = await this.runTest(agent, test, run);
                results.push(result);
            }
        }

        // Analyze by test
        const byTest = this.groupByTest(results);
        const testAnalyses = new Map<string, StatisticalAnalysis>();

        for (const [testId, testResults] of byTest) {
            testAnalyses.set(testId, this.analyzeResults(testResults));
        }

        // Overall analysis
        const overall = this.analyzeResults(results);

        return {
            overall,
            byTest: testAnalyses,
            concerns: this.identifyConcerns(testAnalyses),
            recommendations: this.generateRecommendations(testAnalyses)
        };
    }

    private analyzeResults(results: TestResult[]): StatisticalAnalysis {
        const passes = results.filter(r => r.passed);
        const passRate = passes.length / results.length;

        // Calculate confidence interval for pass rate
        const z = 1.96;  // 95% confidence
        const se = Math.sqrt((passRate * (1 - passRate)) / results.length);
        const confidence95: [number, number] = [
            Math.max(0, passRate - z * se),
            Math.min(1, passRate + z * se)
        ];

        const scores = results.map(r => r.score);
        const latencies = results.map(r => r.latencyMs);

        return {
            passRate,
            confidence95,
            meanScore: this.mean(scores),
            stdDevScore: this.stdDev(scores),
            meanLatency: this.mean(latencies),
            p95Latency: this.percentile(latencies, 95),
            behaviorConsistency: this.calculateConsistency(results)
        };
    }

    private calculateConsistency(results: TestResult[]): number {
        // How consistent are the behaviors across runs?
        if (results.length < 2) return 1;

        const behaviorSets = results.map(r => new Set(r.actualBehaviors));
        let consistencySum = 0;
        let comparisons = 0;

        for (let i = 0; i < behaviorSets.length; i++) {
            for (let j = i + 1; j < behaviorSets.length; j++) {
                const intersection = new Set(
                    [...behaviorSets[i]].filter(x => behaviorSets[j].has(x))
                );
                const union = new Set([...behaviorSets[i], ...behaviorSets[j]]);
                consistencySum += intersection.size / union.size;
                comparisons++;
            }
        }

        return consistencySum / comparisons;
    }

    private identifyConcerns(analyses: Map<string, StatisticalAnalysis>): Concern[] {
        const concerns: Concern[] = [];

        for (const [testId, 
