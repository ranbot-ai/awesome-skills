'use client';

import Link from 'next/link';
import Image from 'next/image';
import { Github, Sparkles, Download } from 'lucide-react';

export function Header() {
  return (
    <header className="sticky top-0 z-50 w-full border-b border-white/10 bg-slate-900/80 backdrop-blur-xl">
      <div className="container mx-auto flex h-16 items-center justify-between px-4">
        <Link href="/" className="flex items-center gap-3 group">
          <div className="relative">
            <div className="absolute inset-0 bg-gradient-to-r from-violet-500 to-cyan-500 rounded-lg blur-sm opacity-75 group-hover:opacity-100 transition-opacity" />
            <Image
              src="/logo-simple.svg"
              alt="Agent Skills Logo"
              width={40}
              height={40}
              className="relative rounded-lg"
            />
          </div>
          <div className="flex flex-col">
            <span className="font-bold text-lg text-white leading-tight">Agent Skills</span>
            <span className="text-xs text-slate-400">by RanBOT Labs</span>
          </div>
        </Link>

        <nav className="hidden md:flex items-center gap-6">
          <Link
            href="/"
            className="text-sm font-medium text-slate-300 hover:text-white transition-colors"
          >
            Browse Skills
          </Link>
          <Link
            href="/#categories"
            className="text-sm font-medium text-slate-300 hover:text-white transition-colors"
          >
            Categories
          </Link>
          <Link
            href="/install"
            className="flex items-center gap-1.5 text-sm font-medium text-emerald-400 hover:text-emerald-300 transition-colors"
          >
            <Download className="h-3.5 w-3.5" />
            Install
          </Link>
          <Link
            href="/about"
            className="text-sm font-medium text-slate-300 hover:text-white transition-colors"
          >
            About
          </Link>
          <a
            href="https://github.com/ranbot-ai/awesome-skills"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 text-sm font-medium text-slate-300 hover:text-white transition-colors"
          >
            <Github className="h-4 w-4" />
            GitHub
          </a>
        </nav>

        <div className="flex items-center gap-3">
          <a
            href="https://github.com/ranbot-ai/awesome-skills"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-violet-600 to-cyan-600 hover:from-violet-500 hover:to-cyan-500 text-white text-sm font-medium rounded-full transition-all shadow-lg shadow-violet-500/25 hover:shadow-violet-500/40"
          >
            <Sparkles className="h-4 w-4" />
            <span className="hidden sm:inline">Star on GitHub</span>
          </a>
        </div>
      </div>
    </header>
  );
}
