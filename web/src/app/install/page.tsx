'use client';

import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';
import {
  Download,
  Terminal,
  Copy,
  Check,
  Folder,
  Package,
  Zap,
  List,
  Search,
  Trash2,
  RefreshCw,
  ExternalLink,
  CheckCircle,
  ArrowRight,
  Command,
  Box
} from 'lucide-react';
import Link from 'next/link';
import { useState } from 'react';

interface CodeBlockProps {
  code: string;
  language?: string;
  title?: string;
}

function CodeBlock({ code, title }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="relative group">
      {title && (
        <div className="flex items-center justify-between px-4 py-2 bg-slate-800 border-b border-slate-700 rounded-t-xl">
          <span className="text-sm text-slate-400">{title}</span>
        </div>
      )}
      <div className={`relative bg-slate-950 ${title ? 'rounded-b-xl' : 'rounded-xl'} overflow-hidden`}>
        <pre className="p-4 text-sm whitespace-pre-wrap break-all">
          <code className="text-emerald-400 font-mono">{code}</code>
        </pre>
        <button
          onClick={handleCopy}
          className="absolute top-3 right-3 p-2 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors opacity-0 group-hover:opacity-100"
          title="Copy to clipboard"
        >
          {copied ? (
            <Check className="h-4 w-4 text-emerald-400" />
          ) : (
            <Copy className="h-4 w-4 text-slate-400" />
          )}
        </button>
      </div>
    </div>
  );
}

const installMethods = [
  {
    id: 'skills-sh',
    title: 'skills.sh CLI',
    description: 'Recommended: Works with 36+ AI agents',
    icon: Zap,
    color: 'violet'
  },
  {
    id: 'one-liner',
    title: 'One-Liner Script',
    description: 'Install to ~/.claude/skills directly',
    icon: Terminal,
    color: 'cyan'
  },
  {
    id: 'selective',
    title: 'Selective Install',
    description: 'Choose specific skills to install',
    icon: Package,
    color: 'emerald'
  },
  {
    id: 'local',
    title: 'From Local Clone',
    description: 'Clone repo and install locally',
    icon: Folder,
    color: 'amber'
  }
];

const commands = {
  // skills.sh CLI commands
  'npx-install-all': 'npx skills add ranbot-ai/awesome-skills --all',
  'npx-list': 'npx skills add ranbot-ai/awesome-skills --list',
  'npx-specific': 'npx skills add ranbot-ai/awesome-skills --skill code-review --skill docker',
  'npx-agent': 'npx skills add ranbot-ai/awesome-skills -a claude-code -a cursor',
  'npx-global': 'npx skills add ranbot-ai/awesome-skills -g',
  'npx-find': 'npx skills find',
  'npx-update': 'npx skills update',
  'npx-remove': 'npx skills remove',
  // One-liner script commands
  'install-all': 'curl -fsSL https://raw.githubusercontent.com/ranbot-ai/awesome-skills/main/scripts/install-skills.sh | bash',
  'install-specific': 'curl -fsSL https://raw.githubusercontent.com/ranbot-ai/awesome-skills/main/scripts/install-skills.sh | bash -s -- code-review docker kubernetes',
  'clone': 'git clone https://github.com/ranbot-ai/awesome-skills.git && cd awesome-skills',
  'list': './scripts/install-skills.sh --list',
  'local-install': './scripts/install-skills.sh --local ./data',
  'search': './scripts/install-skills.sh --search docker',
  'source': './scripts/install-skills.sh --source anthropic',
  'category': './scripts/install-skills.sh --category "Development"',
  'info': './scripts/install-skills.sh --info code-review',
  'update': './scripts/install-skills.sh --update',
  'uninstall': './scripts/install-skills.sh --uninstall skill-name',
  'clean': './scripts/install-skills.sh --clean'
};

const sources = [
  { name: 'anthropic', description: 'Official Anthropic skills', count: '16+' },
  { name: 'composio', description: 'Community Claude skills', count: '16+' },
  { name: 'superpowers', description: 'Agentic development skills', count: '14+' },
  { name: 'openhands', description: 'AI-driven development', count: '10+' }
];

export default function InstallPage() {
  const [activeMethod, setActiveMethod] = useState('skills-sh');

  return (
    <div className="min-h-screen bg-slate-950">
      <Header />
      <main>
        {/* Hero Section */}
        <section className="relative py-20 overflow-hidden border-b border-white/5">
          <div className="absolute inset-0 bg-gradient-to-b from-emerald-600/10 via-transparent to-transparent" />
          <div className="absolute top-0 left-1/4 w-96 h-96 bg-emerald-500/20 rounded-full blur-3xl" />
          <div className="absolute top-0 right-1/4 w-96 h-96 bg-cyan-500/20 rounded-full blur-3xl" />

          <div className="container mx-auto px-4 relative">
            <div className="max-w-4xl mx-auto text-center">
              <div className="inline-flex items-center gap-2 px-4 py-2 bg-slate-800/80 border border-slate-700 rounded-full text-sm text-slate-300 mb-6">
                <Terminal className="h-4 w-4 text-emerald-400" />
                <span>Local Installation</span>
              </div>

              <h1 className="text-4xl md:text-6xl font-bold text-white mb-6 leading-tight">
                Install Skills{' '}
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 via-cyan-400 to-emerald-400">
                  Locally
                </span>
              </h1>

              <p className="text-xl text-slate-400 mb-10 max-w-2xl mx-auto">
                Set up agent skills in your <code className="text-emerald-400 bg-slate-800 px-2 py-1 rounded">~/.claude/skills</code> directory with one command.
                Works with Claude Code, Cursor, and other AI agents.
              </p>

              <div className="flex flex-wrap justify-center gap-4">
                <a
                  href="#quick-start"
                  className="inline-flex items-center gap-2 px-6 py-3 bg-emerald-600 hover:bg-emerald-500 text-white font-medium rounded-xl transition-colors"
                >
                  <Download className="h-4 w-4" />
                  Quick Start
                </a>
                <Link
                  href="/"
                  className="inline-flex items-center gap-2 px-6 py-3 bg-slate-800 hover:bg-slate-700 text-white font-medium rounded-xl transition-colors border border-slate-700"
                >
                  Browse Skills First
                </Link>
              </div>
            </div>
          </div>
        </section>

        {/* Quick Start Section */}
        <section id="quick-start" className="py-16 border-b border-white/5">
          <div className="container mx-auto px-4">
            <div className="max-w-4xl mx-auto">
              <div className="text-center mb-12">
                <h2 className="text-3xl font-bold text-white mb-4">Quick Start</h2>
                <p className="text-slate-400">Choose your preferred installation method</p>
              </div>

              {/* Method Tabs */}
              <div className="flex flex-wrap justify-center gap-3 mb-8">
                {installMethods.map((method) => {
                  const Icon = method.icon;
                  const isActive = activeMethod === method.id;
                  return (
                    <button
                      key={method.id}
                      onClick={() => setActiveMethod(method.id)}
                      className={`flex items-center gap-2 px-4 py-3 rounded-xl transition-all ${
                        isActive
                          ? 'bg-slate-800 border-2 border-emerald-500/50 text-white'
                          : 'bg-slate-900/50 border border-slate-800 text-slate-400 hover:text-white hover:border-slate-700'
                      }`}
                    >
                      <Icon className={`h-5 w-5 ${isActive ? 'text-emerald-400' : ''}`} />
                      <span className="font-medium">{method.title}</span>
                    </button>
                  );
                })}
              </div>

              {/* Method Content */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6 md:p-8">
                {activeMethod === 'skills-sh' && (
                  <div className="space-y-6">
                    <div className="bg-gradient-to-r from-violet-500/10 to-cyan-500/10 border border-violet-500/20 rounded-xl p-4 mb-6">
                      <div className="flex items-center gap-3">
                        <Zap className="h-5 w-5 text-violet-400" />
                        <div>
                          <p className="text-white font-medium">Recommended Method</p>
                          <p className="text-slate-400 text-sm">Works with Claude Code, Cursor, Codex, Gemini CLI, and 36+ other AI agents</p>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-start gap-4">
                      <div className="w-10 h-10 bg-violet-500/20 rounded-xl flex items-center justify-center flex-shrink-0">
                        <span className="text-violet-400 font-bold">1</span>
                      </div>
                      <div className="flex-1">
                        <h3 className="text-lg font-semibold text-white mb-2">Install All Skills</h3>
                        <p className="text-slate-400 text-sm mb-4">
                          Use the skills.sh CLI to install all skills to all your AI agents:
                        </p>
                        <CodeBlock code={commands['npx-install-all']} />
                      </div>
                    </div>

                    <div className="flex items-start gap-4">
                      <div className="w-10 h-10 bg-violet-500/20 rounded-xl flex items-center justify-center flex-shrink-0">
                        <span className="text-violet-400 font-bold">2</span>
                      </div>
                      <div className="flex-1">
                        <h3 className="text-lg font-semibold text-white mb-2">Or Install Specific Skills</h3>
                        <p className="text-slate-400 text-sm mb-4">
                          Choose which skills to install:
                        </p>
                        <CodeBlock code={commands['npx-specific']} />
                      </div>
                    </div>

                    <div className="flex items-start gap-4">
                      <div className="w-10 h-10 bg-violet-500/20 rounded-xl flex items-center justify-center flex-shrink-0">
                        <span className="text-violet-400 font-bold">3</span>
                      </div>
                      <div className="flex-1">
                        <h3 className="text-lg font-semibold text-white mb-2">Target Specific Agents</h3>
                        <p className="text-slate-400 text-sm mb-4">
                          Install only to specific AI agents:
                        </p>
                        <CodeBlock code={commands['npx-agent']} />
                        <p className="text-slate-400 text-sm mt-3">
                          Supported agents: <code className="text-cyan-400">claude-code</code>, <code className="text-cyan-400">cursor</code>, <code className="text-cyan-400">codex</code>, <code className="text-cyan-400">gemini-cli</code>, <code className="text-cyan-400">github-copilot</code>, <code className="text-cyan-400">cline</code>, <code className="text-cyan-400">opencode</code>, <code className="text-cyan-400">windsurf</code>, and more.
                        </p>
                      </div>
                    </div>

                    <div className="mt-6 p-4 bg-slate-800/50 rounded-xl">
                      <h4 className="text-white font-medium mb-3">More Commands</h4>
                      <div className="space-y-2 text-sm">
                        <div className="flex items-center gap-2">
                          <code className="text-emerald-400 bg-slate-900 px-2 py-1 rounded">npx skills list</code>
                          <span className="text-slate-400">- List installed skills</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <code className="text-emerald-400 bg-slate-900 px-2 py-1 rounded">npx skills find</code>
                          <span className="text-slate-400">- Search for skills</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <code className="text-emerald-400 bg-slate-900 px-2 py-1 rounded">npx skills update</code>
                          <span className="text-slate-400">- Update installed skills</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <code className="text-emerald-400 bg-slate-900 px-2 py-1 rounded">npx skills remove</code>
                          <span className="text-slate-400">- Remove skills</span>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {activeMethod === 'one-liner' && (
                  <div className="space-y-6">
                    <div className="flex items-start gap-4">
                      <div className="w-10 h-10 bg-emerald-500/20 rounded-xl flex items-center justify-center flex-shrink-0">
                        <span className="text-emerald-400 font-bold">1</span>
                      </div>
                      <div className="flex-1">
                        <h3 className="text-lg font-semibold text-white mb-2">Install All Skills</h3>
                        <p className="text-slate-400 text-sm mb-4">
                          Run this command to download and install all 70+ skills to your local machine:
                        </p>
                        <CodeBlock code={commands['install-all']} />
                      </div>
                    </div>

                    <div className="flex items-start gap-4">
                      <div className="w-10 h-10 bg-emerald-500/20 rounded-xl flex items-center justify-center flex-shrink-0">
                        <span className="text-emerald-400 font-bold">2</span>
                      </div>
                      <div className="flex-1">
                        <h3 className="text-lg font-semibold text-white mb-2">Done!</h3>
                        <p className="text-slate-400 text-sm mb-4">
                          Skills are installed following the official directory structure:
                        </p>
                        <div className="bg-slate-950 rounded-xl p-4 text-sm font-mono">
                          <div className="text-slate-400">~/.claude/skills/</div>
                          <div className="text-slate-400 ml-4">├── code-review/</div>
                          <div className="text-emerald-400 ml-8">│   └── SKILL.md</div>
                          <div className="text-slate-400 ml-4">├── docker/</div>
                          <div className="text-emerald-400 ml-8">│   └── SKILL.md</div>
                          <div className="text-slate-400 ml-4">└── ...</div>
                        </div>
                        <p className="text-slate-400 text-sm mt-4">
                          Your AI agent will automatically discover and use them.
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {activeMethod === 'selective' && (
                  <div className="space-y-6">
                    <div className="flex items-start gap-4">
                      <div className="w-10 h-10 bg-cyan-500/20 rounded-xl flex items-center justify-center flex-shrink-0">
                        <span className="text-cyan-400 font-bold">1</span>
                      </div>
                      <div className="flex-1">
                        <h3 className="text-lg font-semibold text-white mb-2">Install Specific Skills</h3>
                        <p className="text-slate-400 text-sm mb-4">
                          Add skill names after the script to install only what you need:
                        </p>
                        <CodeBlock code={commands['install-specific']} />
                      </div>
                    </div>

                    <div className="flex items-start gap-4">
                      <div className="w-10 h-10 bg-cyan-500/20 rounded-xl flex items-center justify-center flex-shrink-0">
                        <span className="text-cyan-400 font-bold">2</span>
                      </div>
                      <div className="flex-1">
                        <h3 className="text-lg font-semibold text-white mb-2">Or Install by Source</h3>
                        <p className="text-slate-400 text-sm mb-4">
                          Install all skills from a specific source (anthropic, composio, superpowers, openhands):
                        </p>
                        <CodeBlock code={commands['source']} />
                      </div>
                    </div>

                    <div className="flex items-start gap-4">
                      <div className="w-10 h-10 bg-cyan-500/20 rounded-xl flex items-center justify-center flex-shrink-0">
                        <span className="text-cyan-400 font-bold">3</span>
                      </div>
                      <div className="flex-1">
                        <h3 className="text-lg font-semibold text-white mb-2">Or by Category</h3>
                        <p className="text-slate-400 text-sm mb-4">
                          Install all skills matching a category:
                        </p>
                        <CodeBlock code={commands['category']} />
                      </div>
                    </div>
                  </div>
                )}

                {activeMethod === 'local' && (
                  <div className="space-y-6">
                    <div className="flex items-start gap-4">
                      <div className="w-10 h-10 bg-violet-500/20 rounded-xl flex items-center justify-center flex-shrink-0">
                        <span className="text-violet-400 font-bold">1</span>
                      </div>
                      <div className="flex-1">
                        <h3 className="text-lg font-semibold text-white mb-2">Clone the Repository</h3>
                        <p className="text-slate-400 text-sm mb-4">
                          First, clone the awesome-skills repo:
                        </p>
                        <CodeBlock code={commands['clone']} />
                      </div>
                    </div>

                    <div className="flex items-start gap-4">
                      <div className="w-10 h-10 bg-violet-500/20 rounded-xl flex items-center justify-center flex-shrink-0">
                        <span className="text-violet-400 font-bold">2</span>
                      </div>
                      <div className="flex-1">
                        <h3 className="text-lg font-semibold text-white mb-2">List Available Skills</h3>
                        <p className="text-slate-400 text-sm mb-4">
                          See all available skills grouped by source:
                        </p>
                        <CodeBlock code={commands['list']} />
                      </div>
                    </div>

                    <div className="flex items-start gap-4">
                      <div className="w-10 h-10 bg-violet-500/20 rounded-xl flex items-center justify-center flex-shrink-0">
                        <span className="text-violet-400 font-bold">3</span>
                      </div>
                      <div className="flex-1">
                        <h3 className="text-lg font-semibold text-white mb-2">Install from Local Data</h3>
                        <p className="text-slate-400 text-sm mb-4">
                          Install skills using the local data directory:
                        </p>
                        <CodeBlock code={commands['local-install']} />
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </section>

        {/* Available Sources */}
        <section className="py-16 border-b border-white/5">
          <div className="container mx-auto px-4">
            <div className="max-w-4xl mx-auto">
              <div className="text-center mb-8">
                <h2 className="text-3xl font-bold text-white mb-4">Available Sources</h2>
                <p className="text-slate-400">Install skills from trusted repositories</p>
              </div>

              <div className="grid md:grid-cols-2 gap-4">
                {sources.map((source) => (
                  <div
                    key={source.name}
                    className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-colors"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <code className="text-emerald-400 font-mono">{source.name}</code>
                      <span className="text-xs text-slate-500 bg-slate-800 px-2 py-1 rounded">{source.count} skills</span>
                    </div>
                    <p className="text-slate-400 text-sm">{source.description}</p>
                    <div className="mt-3">
                      <CodeBlock code={`./scripts/install-skills.sh --source ${source.name}`} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* All Commands Reference */}
        <section className="py-16 border-b border-white/5">
          <div className="container mx-auto px-4">
            <div className="max-w-4xl mx-auto">
              <div className="text-center mb-8">
                <h2 className="text-3xl font-bold text-white mb-4">Command Reference</h2>
                <p className="text-slate-400">All available commands for managing skills</p>
              </div>

              <div className="grid gap-4">
                <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5">
                  <div className="flex items-center gap-3 mb-3">
                    <List className="h-5 w-5 text-cyan-400" />
                    <h3 className="font-semibold text-white">List Skills</h3>
                  </div>
                  <p className="text-slate-400 text-sm mb-3">Show all available skills grouped by source</p>
                  <CodeBlock code={commands['list']} />
                </div>

                <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5">
                  <div className="flex items-center gap-3 mb-3">
                    <Search className="h-5 w-5 text-violet-400" />
                    <h3 className="font-semibold text-white">Search Skills</h3>
                  </div>
                  <p className="text-slate-400 text-sm mb-3">Find skills by name or description</p>
                  <CodeBlock code={commands['search']} />
                </div>

                <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5">
                  <div className="flex items-center gap-3 mb-3">
                    <Box className="h-5 w-5 text-amber-400" />
                    <h3 className="font-semibold text-white">Skill Info</h3>
                  </div>
                  <p className="text-slate-400 text-sm mb-3">Get detailed information about a specific skill</p>
                  <CodeBlock code={commands['info']} />
                </div>

                <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5">
                  <div className="flex items-center gap-3 mb-3">
                    <RefreshCw className="h-5 w-5 text-emerald-400" />
                    <h3 className="font-semibold text-white">Update Skills</h3>
                  </div>
                  <p className="text-slate-400 text-sm mb-3">Overwrite existing skills with latest versions</p>
                  <CodeBlock code={commands['update']} />
                </div>

                <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5">
                  <div className="flex items-center gap-3 mb-3">
                    <Trash2 className="h-5 w-5 text-rose-400" />
                    <h3 className="font-semibold text-white">Uninstall / Clean</h3>
                  </div>
                  <p className="text-slate-400 text-sm mb-3">Remove specific skills or all installed skills</p>
                  <div className="space-y-3">
                    <CodeBlock code={commands['uninstall']} title="Uninstall specific skill" />
                    <CodeBlock code={commands['clean']} title="Remove all skills" />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Environment Variables */}
        <section className="py-16 border-b border-white/5">
          <div className="container mx-auto px-4">
            <div className="max-w-4xl mx-auto">
              <div className="text-center mb-8">
                <h2 className="text-3xl font-bold text-white mb-4">Configuration</h2>
                <p className="text-slate-400">Customize the installation behavior</p>
              </div>

              <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6">
                <h3 className="text-lg font-semibold text-white mb-4">Environment Variables</h3>

                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead>
                      <tr className="border-b border-slate-700">
                        <th className="pb-3 text-slate-400 font-medium">Variable</th>
                        <th className="pb-3 text-slate-400 font-medium">Default</th>
                        <th className="pb-3 text-slate-400 font-medium">Description</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td className="py-3">
                          <code className="text-emerald-400 bg-slate-800 px-2 py-1 rounded text-sm">CLAUDE_SKILLS_DIR</code>
                        </td>
                        <td className="py-3">
                          <code className="text-slate-400 text-sm">~/.claude/skills</code>
                        </td>
                        <td className="py-3 text-slate-400 text-sm">
                          Override the default skills installation directory
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>

                <div className="mt-6">
                  <p className="text-slate-400 text-sm mb-3">Example: Install skills to a custom directory</p>
                  <CodeBlock code="CLAUDE_SKILLS_DIR=~/my-skills ./scripts/install-skills.sh" />
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Requirements */}
        <section className="py-16 border-b border-white/5">
          <div className="container mx-auto px-4">
            <div className="max-w-4xl mx-auto">
              <div className="text-center mb-8">
                <h2 className="text-3xl font-bold text-white mb-4">Requirements</h2>
                <p className="text-slate-400">What you need to run the install script</p>
              </div>

              <div className="grid md:grid-cols-2 gap-6">
                <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6">
                  <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                    <CheckCircle className="h-5 w-5 text-emerald-400" />
                    Required
                  </h3>
                  <ul className="space-y-3">
                    <li className="flex items-center gap-3 text-slate-300">
                      <Command className="h-4 w-4 text-slate-500" />
                      <span><code className="text-emerald-400">curl</code> - For downloading files</span>
                    </li>
                    <li className="flex items-center gap-3 text-slate-300">
                      <Command className="h-4 w-4 text-slate-500" />
                      <span><code className="text-emerald-400">bash</code> - Shell interpreter</span>
                    </li>
                  </ul>
                </div>

                <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6">
                  <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                    <Zap className="h-5 w-5 text-amber-400" />
                    Recommended
                  </h3>
                  <ul className="space-y-3">
                    <li className="flex items-center gap-3 text-slate-300">
                      <Command className="h-4 w-4 text-slate-500" />
                      <span><code className="text-amber-400">jq</code> - For better JSON parsing & search</span>
                    </li>
                  </ul>
                  <p className="mt-4 text-slate-400 text-sm">
                    Install jq: <code className="text-slate-300">brew install jq</code> (macOS) or <code className="text-slate-300">apt install jq</code> (Linux)
                  </p>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* CTA Section */}
        <section className="py-16">
          <div className="container mx-auto px-4">
            <div className="max-w-4xl mx-auto text-center">
              <h2 className="text-3xl font-bold text-white mb-4">Ready to Get Started?</h2>
              <p className="text-slate-400 mb-8">
                Browse all available skills or install them right now
              </p>

              <div className="flex flex-wrap justify-center gap-4">
                <Link
                  href="/"
                  className="inline-flex items-center gap-2 px-6 py-3 bg-slate-800 hover:bg-slate-700 text-white font-medium rounded-xl transition-colors border border-slate-700"
                >
                  Browse All Skills
                  <ArrowRight className="h-4 w-4" />
                </Link>
                <a
                  href="https://github.com/ranbot-ai/awesome-skills"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 px-6 py-3 bg-emerald-600 hover:bg-emerald-500 text-white font-medium rounded-xl transition-colors"
                >
                  View on GitHub
                  <ExternalLink className="h-4 w-4" />
                </a>
              </div>

              <div className="mt-12 p-6 bg-gradient-to-r from-emerald-500/10 via-cyan-500/10 to-emerald-500/10 border border-emerald-500/20 rounded-2xl">
                <p className="text-slate-300 mb-4">Quick install - run this in your terminal:</p>
                <CodeBlock code={commands['install-all']} />
              </div>
            </div>
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
