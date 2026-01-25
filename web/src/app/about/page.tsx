import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';
import {
  Bot,
  FileCode,
  Folder,
  Layers,
  Zap,
  ExternalLink,
  CheckCircle,
  Code,
  BookOpen,
  Users
} from 'lucide-react';
import Link from 'next/link';

const compatibleTools = [
  { name: 'Claude', url: 'https://claude.ai/' },
  { name: 'Claude Code', url: 'https://claude.ai/code' },
  { name: 'Cursor', url: 'https://cursor.com/' },
  { name: 'VS Code', url: 'https://code.visualstudio.com/' },
  { name: 'GitHub Copilot', url: 'https://github.com/' },
  { name: 'OpenAI Codex', url: 'https://developers.openai.com/codex' },
  { name: 'Gemini CLI', url: 'https://geminicli.com' },
  { name: 'Roo Code', url: 'https://roocode.com' },
  { name: 'Amp', url: 'https://ampcode.com/' },
  { name: 'Goose', url: 'https://block.github.io/goose/' },
  { name: 'OpenCode', url: 'https://opencode.ai/' },
  { name: 'Firebender', url: 'https://firebender.com/' },
];

export default function AboutPage() {
  return (
    <div className="min-h-screen bg-slate-950">
      <Header />
      <main>
        {/* Hero Section */}
        <section className="relative py-20 overflow-hidden border-b border-white/5">
          <div className="absolute inset-0 bg-gradient-to-b from-violet-600/10 via-transparent to-transparent" />
          <div className="absolute top-0 left-1/4 w-96 h-96 bg-violet-500/20 rounded-full blur-3xl" />
          <div className="absolute top-0 right-1/4 w-96 h-96 bg-cyan-500/20 rounded-full blur-3xl" />

          <div className="container mx-auto px-4 relative">
            <div className="max-w-4xl mx-auto text-center">
              <div className="inline-flex items-center gap-2 px-4 py-2 bg-slate-800/80 border border-slate-700 rounded-full text-sm text-slate-300 mb-6">
                <BookOpen className="h-4 w-4 text-violet-400" />
                <span>Open Standard</span>
              </div>

              <h1 className="text-4xl md:text-6xl font-bold text-white mb-6 leading-tight">
                What are{' '}
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-violet-400 via-cyan-400 to-violet-400">
                  Agent Skills?
                </span>
              </h1>

              <p className="text-xl text-slate-400 mb-10 max-w-2xl mx-auto">
                A simple, open format for giving AI agents new capabilities and expertise.
                Originally developed by Anthropic, now adopted across the ecosystem.
              </p>

              <div className="flex flex-wrap justify-center gap-4">
                <a
                  href="https://agentskills.io"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 px-6 py-3 bg-violet-600 hover:bg-violet-500 text-white font-medium rounded-xl transition-colors"
                >
                  Official Specification
                  <ExternalLink className="h-4 w-4" />
                </a>
                <Link
                  href="/"
                  className="inline-flex items-center gap-2 px-6 py-3 bg-slate-800 hover:bg-slate-700 text-white font-medium rounded-xl transition-colors border border-slate-700"
                >
                  Browse Skills
                </Link>
              </div>
            </div>
          </div>
        </section>

        {/* How Skills Work */}
        <section className="py-16 border-b border-white/5">
          <div className="container mx-auto px-4">
            <div className="max-w-4xl mx-auto">
              <h2 className="text-3xl font-bold text-white mb-8 text-center">How Skills Work</h2>

              <div className="grid md:grid-cols-3 gap-6 mb-12">
                <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6">
                  <div className="w-12 h-12 bg-violet-500/20 rounded-xl flex items-center justify-center mb-4">
                    <Layers className="h-6 w-6 text-violet-400" />
                  </div>
                  <h3 className="text-lg font-semibold text-white mb-2">1. Discovery</h3>
                  <p className="text-slate-400 text-sm">
                    At startup, agents load only the name and description of each skill—just enough to know when it might be relevant.
                  </p>
                </div>

                <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6">
                  <div className="w-12 h-12 bg-cyan-500/20 rounded-xl flex items-center justify-center mb-4">
                    <Zap className="h-6 w-6 text-cyan-400" />
                  </div>
                  <h3 className="text-lg font-semibold text-white mb-2">2. Activation</h3>
                  <p className="text-slate-400 text-sm">
                    When a task matches a skill&apos;s description, the agent reads the full SKILL.md instructions into context.
                  </p>
                </div>

                <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6">
                  <div className="w-12 h-12 bg-emerald-500/20 rounded-xl flex items-center justify-center mb-4">
                    <Bot className="h-6 w-6 text-emerald-400" />
                  </div>
                  <h3 className="text-lg font-semibold text-white mb-2">3. Execution</h3>
                  <p className="text-slate-400 text-sm">
                    The agent follows the instructions, optionally loading referenced files or executing bundled scripts as needed.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Skill Structure */}
        <section className="py-16 border-b border-white/5">
          <div className="container mx-auto px-4">
            <div className="max-w-4xl mx-auto">
              <h2 className="text-3xl font-bold text-white mb-8 text-center">Skill Structure</h2>

              <div className="grid md:grid-cols-2 gap-8">
                <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <Folder className="h-6 w-6 text-amber-400" />
                    <h3 className="text-lg font-semibold text-white">Directory Layout</h3>
                  </div>
                  <pre className="bg-slate-950 rounded-xl p-4 text-sm text-slate-300 overflow-x-auto">
{`skill-name/
├── SKILL.md          # Required
├── scripts/          # Optional
├── references/       # Optional
└── assets/           # Optional`}
                  </pre>
                </div>

                <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <FileCode className="h-6 w-6 text-violet-400" />
                    <h3 className="text-lg font-semibold text-white">SKILL.md Format</h3>
                  </div>
                  <pre className="bg-slate-950 rounded-xl p-4 text-sm text-slate-300 overflow-x-auto">
{`---
name: my-skill
description: What this
  skill does and when
  to use it.
---

# Instructions

Step-by-step guide...`}
                  </pre>
                </div>
              </div>

              <div className="mt-8 bg-slate-900/50 border border-slate-800 rounded-2xl p-6">
                <h3 className="text-lg font-semibold text-white mb-4">Required Fields</h3>
                <div className="grid md:grid-cols-2 gap-4">
                  <div className="flex items-start gap-3">
                    <CheckCircle className="h-5 w-5 text-emerald-400 mt-0.5 flex-shrink-0" />
                    <div>
                      <code className="text-violet-400 text-sm">name</code>
                      <p className="text-slate-400 text-sm">Max 64 chars. Lowercase letters, numbers, hyphens only.</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <CheckCircle className="h-5 w-5 text-emerald-400 mt-0.5 flex-shrink-0" />
                    <div>
                      <code className="text-violet-400 text-sm">description</code>
                      <p className="text-slate-400 text-sm">Max 1024 chars. What the skill does and when to use it.</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Why Skills Matter */}
        <section className="py-16 border-b border-white/5">
          <div className="container mx-auto px-4">
            <div className="max-w-4xl mx-auto">
              <h2 className="text-3xl font-bold text-white mb-8 text-center">Why Agent Skills?</h2>

              <div className="grid md:grid-cols-2 gap-6">
                <div className="bg-gradient-to-br from-violet-500/10 to-transparent border border-violet-500/20 rounded-2xl p-6">
                  <h3 className="text-lg font-semibold text-white mb-3">For Skill Authors</h3>
                  <p className="text-slate-400">
                    Build capabilities once and deploy them across multiple agent products. Your skills work everywhere.
                  </p>
                </div>

                <div className="bg-gradient-to-br from-cyan-500/10 to-transparent border border-cyan-500/20 rounded-2xl p-6">
                  <h3 className="text-lg font-semibold text-white mb-3">For Compatible Agents</h3>
                  <p className="text-slate-400">
                    Support for skills lets end users give agents new capabilities out of the box without custom development.
                  </p>
                </div>

                <div className="bg-gradient-to-br from-emerald-500/10 to-transparent border border-emerald-500/20 rounded-2xl p-6">
                  <h3 className="text-lg font-semibold text-white mb-3">For Teams & Enterprises</h3>
                  <p className="text-slate-400">
                    Capture organizational knowledge in portable, version-controlled packages that can be shared and audited.
                  </p>
                </div>

                <div className="bg-gradient-to-br from-amber-500/10 to-transparent border border-amber-500/20 rounded-2xl p-6">
                  <h3 className="text-lg font-semibold text-white mb-3">Interoperability</h3>
                  <p className="text-slate-400">
                    Reuse the same skill across different skills-compatible agent products. Write once, run anywhere.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Compatible Tools */}
        <section className="py-16 border-b border-white/5">
          <div className="container mx-auto px-4">
            <div className="max-w-4xl mx-auto">
              <div className="text-center mb-8">
                <div className="inline-flex items-center gap-2 px-4 py-2 bg-slate-800/80 border border-slate-700 rounded-full text-sm text-slate-300 mb-4">
                  <Users className="h-4 w-4 text-cyan-400" />
                  <span>Growing Ecosystem</span>
                </div>
                <h2 className="text-3xl font-bold text-white mb-4">Compatible Tools</h2>
                <p className="text-slate-400">
                  Agent Skills are supported by leading AI development tools.
                </p>
              </div>

              <div className="flex flex-wrap justify-center gap-3">
                {compatibleTools.map((tool) => (
                  <a
                    key={tool.name}
                    href={tool.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-4 py-2 bg-slate-800/60 border border-slate-700/50 rounded-xl text-slate-300 hover:text-white hover:bg-slate-800 hover:border-slate-600 transition-all text-sm"
                  >
                    {tool.name}
                  </a>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* Resources */}
        <section className="py-16">
          <div className="container mx-auto px-4">
            <div className="max-w-4xl mx-auto">
              <h2 className="text-3xl font-bold text-white mb-8 text-center">Resources</h2>

              <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
                <a
                  href="https://agentskills.io/what-are-skills"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="group bg-slate-900/50 border border-slate-800 rounded-2xl p-6 hover:border-violet-500/50 transition-colors"
                >
                  <BookOpen className="h-8 w-8 text-violet-400 mb-4" />
                  <h3 className="font-semibold text-white mb-2 group-hover:text-violet-400 transition-colors">
                    What are Skills?
                  </h3>
                  <p className="text-slate-400 text-sm">
                    Learn about skills, how they work, and why they matter.
                  </p>
                </a>

                <a
                  href="https://agentskills.io/specification"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="group bg-slate-900/50 border border-slate-800 rounded-2xl p-6 hover:border-cyan-500/50 transition-colors"
                >
                  <FileCode className="h-8 w-8 text-cyan-400 mb-4" />
                  <h3 className="font-semibold text-white mb-2 group-hover:text-cyan-400 transition-colors">
                    Specification
                  </h3>
                  <p className="text-slate-400 text-sm">
                    The complete format specification for SKILL.md files.
                  </p>
                </a>

                <a
                  href="https://agentskills.io/integrate-skills"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="group bg-slate-900/50 border border-slate-800 rounded-2xl p-6 hover:border-emerald-500/50 transition-colors"
                >
                  <Code className="h-8 w-8 text-emerald-400 mb-4" />
                  <h3 className="font-semibold text-white mb-2 group-hover:text-emerald-400 transition-colors">
                    Integrate Skills
                  </h3>
                  <p className="text-slate-400 text-sm">
                    Add skills support to your agent or tool.
                  </p>
                </a>

                <a
                  href="https://github.com/anthropics/skills"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="group bg-slate-900/50 border border-slate-800 rounded-2xl p-6 hover:border-amber-500/50 transition-colors"
                >
                  <Folder className="h-8 w-8 text-amber-400 mb-4" />
                  <h3 className="font-semibold text-white mb-2 group-hover:text-amber-400 transition-colors">
                    Example Skills
                  </h3>
                  <p className="text-slate-400 text-sm">
                    Browse example skills on GitHub from Anthropic.
                  </p>
                </a>

                <a
                  href="https://github.com/agentskills/agentskills"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="group bg-slate-900/50 border border-slate-800 rounded-2xl p-6 hover:border-rose-500/50 transition-colors"
                >
                  <Bot className="h-8 w-8 text-rose-400 mb-4" />
                  <h3 className="font-semibold text-white mb-2 group-hover:text-rose-400 transition-colors">
                    Agent Skills Repo
                  </h3>
                  <p className="text-slate-400 text-sm">
                    The open standard repository and reference library.
                  </p>
                </a>

                <Link
                  href="/"
                  className="group bg-gradient-to-br from-violet-500/20 to-cyan-500/20 border border-violet-500/30 rounded-2xl p-6 hover:border-violet-500/50 transition-colors"
                >
                  <Zap className="h-8 w-8 text-violet-400 mb-4" />
                  <h3 className="font-semibold text-white mb-2 group-hover:text-violet-400 transition-colors">
                    Browse All Skills
                  </h3>
                  <p className="text-slate-400 text-sm">
                    Explore {52}+ skills from the community.
                  </p>
                </Link>
              </div>
            </div>
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
