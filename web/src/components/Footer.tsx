import { Github, Heart, ExternalLink } from 'lucide-react';
import Link from 'next/link';
import Image from 'next/image';

export function Footer() {
  return (
    <footer className="border-t border-white/10 bg-slate-900/50">
      <div className="container mx-auto px-4 py-12">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          <div className="col-span-1 md:col-span-2">
            <Link href="/" className="flex items-center gap-3 mb-4">
              <Image
                src="/logo-simple.svg"
                alt="Agent Skills Logo"
                width={40}
                height={40}
                className="rounded-lg"
              />
              <div className="flex flex-col">
                <span className="font-bold text-xl text-white">Agent Skills</span>
                <span className="text-xs text-slate-400">by RanBOT Labs</span>
              </div>
            </Link>
            <p className="text-slate-400 max-w-md mb-4">
              A curated collection of AI agent skills from the open-source community.
              Discover, explore, and implement powerful capabilities for your AI workflows.
            </p>
            <a
              href="https://ranbot.online"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 text-sm text-violet-400 hover:text-violet-300 transition-colors"
            >
              Visit RanBOT Labs
              <ExternalLink className="h-3 w-3" />
            </a>
          </div>

          <div>
            <h3 className="font-semibold text-white mb-4">Sources</h3>
            <ul className="space-y-2">
              <li>
                <a
                  href="https://github.com/obra/superpowers"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  Superpowers
                </a>
              </li>
              <li>
                <a
                  href="https://github.com/anthropics/skills"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  Anthropic Skills
                </a>
              </li>
              <li>
                <a
                  href="https://github.com/ComposioHQ/awesome-claude-skills"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  ComposioHQ Skills
                </a>
              </li>
              <li>
                <a
                  href="https://github.com/OpenHands/OpenHands"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  OpenHands Skills
                </a>
              </li>
              <li>
                <a
                  href="https://github.com/Prat011/awesome-llm-skills"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  Awesome LLM Skills
                </a>
              </li>
            </ul>
          </div>

          <div>
            <h3 className="font-semibold text-white mb-4">Resources</h3>
            <ul className="space-y-2">
              <li>
                <Link
                  href="/install"
                  className="text-emerald-400 hover:text-emerald-300 transition-colors"
                >
                  Install Locally
                </Link>
              </li>
              <li>
                <Link
                  href="/about"
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  About Agent Skills
                </Link>
              </li>
              <li>
                <a
                  href="https://agentskills.io"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  Official Specification
                </a>
              </li>
              <li>
                <a
                  href="https://github.com/ranbot-ai/awesome-skills"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  GitHub Repository
                </a>
              </li>
              <li>
                <a
                  href="https://docs.anthropic.com/en/docs/claude-skills"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  Claude Skills Docs
                </a>
              </li>
            </ul>
          </div>
        </div>

        <div className="border-t border-white/10 mt-8 pt-8 flex flex-col md:flex-row justify-between items-center gap-4">
          <p className="text-slate-400 text-sm flex items-center gap-1">
            Made with <Heart className="h-4 w-4 text-red-500 fill-red-500" /> by{' '}
            <a
              href="https://ranbot.online"
              target="_blank"
              rel="noopener noreferrer"
              className="text-violet-400 hover:text-violet-300 transition-colors"
            >
              RanBOT Labs
            </a>
          </p>
          <div className="flex items-center gap-4">
            <a
              href="https://ranbot.online"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 text-slate-400 hover:text-white transition-colors"
            >
              <span className="text-sm">ranbot.online</span>
            </a>
            <a
              href="https://github.com/ranbot-ai/awesome-skills"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 text-slate-400 hover:text-white transition-colors"
            >
              <Github className="h-5 w-5" />
              <span className="text-sm">GitHub</span>
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}
