import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';
import { notFound } from 'next/navigation';
import Link from 'next/link';
import {
  ArrowLeft,
  ExternalLink,
  Github,
  Tag,
  Folder,
  BookOpen,
  Copy,
  CheckCircle,
  Lightbulb
} from 'lucide-react';
import { getSourceLabel, getSourceColor } from '@/lib/skills';
import type { Skill, SkillsData } from '@/types/skill';
import clsx from 'clsx';

async function getSkillsData(): Promise<SkillsData> {
  const fs = await import('fs');
  const path = await import('path');
  const dataPath = path.join(process.cwd(), 'public', 'data', 'skills.json');
  const data = JSON.parse(fs.readFileSync(dataPath, 'utf-8'));
  return data;
}

interface PageProps {
  params: Promise<{ slug: string }>;
}

export async function generateStaticParams() {
  const data = await getSkillsData();
  return data.skills.map((skill) => ({
    slug: skill.slug,
  }));
}

export async function generateMetadata({ params }: PageProps) {
  const { slug } = await params;
  const data = await getSkillsData();
  const skill = data.skills.find((s) => s.slug === slug);

  if (!skill) {
    return { title: 'Skill Not Found' };
  }

  return {
    title: `${skill.name} - Agent Skills`,
    description: skill.description,
  };
}

export default async function SkillPage({ params }: PageProps) {
  const { slug } = await params;
  const data = await getSkillsData();
  const skill = data.skills.find((s) => s.slug === slug);

  if (!skill) {
    notFound();
  }

  // Get related skills (same category, different skill)
  const relatedSkills = data.skills
    .filter((s) => s.category === skill.category && s.id !== skill.id)
    .slice(0, 3);

  return (
    <div className="min-h-screen bg-slate-950">
      <Header />
      <main>
        {/* Hero Section */}
        <section className="relative py-12 overflow-hidden border-b border-white/5">
          <div className="absolute inset-0 bg-gradient-to-b from-violet-600/5 via-transparent to-transparent" />

          <div className="container mx-auto px-4 relative">
            <Link
              href="/"
              className="inline-flex items-center gap-2 text-slate-400 hover:text-white transition-colors mb-8"
            >
              <ArrowLeft className="h-4 w-4" />
              Back to Skills
            </Link>

            <div className="max-w-4xl">
              <div className="flex flex-wrap items-center gap-3 mb-4">
                <span className={clsx(
                  'inline-flex items-center px-3 py-1 rounded-full text-sm font-medium text-white',
                  getSourceColor(skill.source)
                )}>
                  {getSourceLabel(skill.source)}
                </span>
                <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-slate-800 rounded-full text-sm text-slate-300">
                  <Folder className="h-3.5 w-3.5" />
                  {skill.category}
                </span>
              </div>

              <h1 className="text-3xl md:text-5xl font-bold text-white mb-4">
                {skill.name}
              </h1>

              <p className="text-xl text-slate-400 mb-8">
                {skill.description}
              </p>

              <div className="flex flex-wrap gap-4">
                <a
                  href={skill.skillUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-violet-600 to-cyan-600 hover:from-violet-500 hover:to-cyan-500 text-white font-medium rounded-xl transition-all shadow-lg shadow-violet-500/25 hover:shadow-violet-500/40"
                >
                  <Github className="h-5 w-5" />
                  View on GitHub
                  <ExternalLink className="h-4 w-4" />
                </a>
                <a
                  href={skill.repoUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 px-6 py-3 bg-slate-800 hover:bg-slate-700 text-white font-medium rounded-xl border border-slate-700 transition-all"
                >
                  View Repository
                  <ExternalLink className="h-4 w-4" />
                </a>
              </div>
            </div>
          </div>
        </section>

        {/* Content Section */}
        <section className="py-12">
          <div className="container mx-auto px-4">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
              {/* Main Content */}
              <div className="lg:col-span-2 space-y-8">
                {/* Content */}
                {skill.content && (
                  <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-8">
                    <div className="flex items-center gap-3 mb-6">
                      <BookOpen className="h-6 w-6 text-violet-400" />
                      <h2 className="text-2xl font-bold text-white">Documentation</h2>
                    </div>
                    <div className="prose prose-invert prose-slate max-w-none">
                      <pre className="bg-slate-800/50 rounded-xl p-6 overflow-x-auto text-sm text-slate-300 whitespace-pre-wrap">
                        {skill.content}
                      </pre>
                    </div>
                  </div>
                )}

                {/* Use Cases */}
                {skill.useCases.length > 0 && (
                  <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-8">
                    <div className="flex items-center gap-3 mb-6">
                      <Lightbulb className="h-6 w-6 text-amber-400" />
                      <h2 className="text-2xl font-bold text-white">Use Cases</h2>
                    </div>
                    <ul className="space-y-3">
                      {skill.useCases.map((useCase, index) => (
                        <li key={index} className="flex items-start gap-3">
                          <CheckCircle className="h-5 w-5 text-emerald-400 flex-shrink-0 mt-0.5" />
                          <span className="text-slate-300">{useCase}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

              {/* Sidebar */}
              <div className="space-y-6">
                {/* Quick Info */}
                <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6">
                  <h3 className="font-semibold text-white mb-4">Quick Info</h3>
                  <dl className="space-y-4">
                    <div>
                      <dt className="text-sm text-slate-400 mb-1">Source</dt>
                      <dd className="text-white">{getSourceLabel(skill.source)}</dd>
                    </div>
                    <div>
                      <dt className="text-sm text-slate-400 mb-1">Category</dt>
                      <dd className="text-white">{skill.category}</dd>
                    </div>
                    <div>
                      <dt className="text-sm text-slate-400 mb-1">Repository</dt>
                      <dd>
                        <a
                          href={skill.repoUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-violet-400 hover:text-violet-300 transition-colors inline-flex items-center gap-1"
                        >
                          View Repo
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      </dd>
                    </div>
                    <div>
                      <dt className="text-sm text-slate-400 mb-1">Scraped At</dt>
                      <dd className="text-white text-sm">
                        {new Date(skill.scrapedAt).toLocaleDateString('en-US', {
                          year: 'numeric',
                          month: 'short',
                          day: 'numeric',
                        })}
                      </dd>
                    </div>
                  </dl>
                </div>

                {/* Tags */}
                {skill.tags.length > 0 && (
                  <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6">
                    <h3 className="font-semibold text-white mb-4">Tags</h3>
                    <div className="flex flex-wrap gap-2">
                      {skill.tags.map((tag) => (
                        <span
                          key={tag}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 rounded-lg text-sm text-slate-300"
                        >
                          <Tag className="h-3.5 w-3.5" />
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Related Skills */}
                {relatedSkills.length > 0 && (
                  <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6">
                    <h3 className="font-semibold text-white mb-4">Related Skills</h3>
                    <div className="space-y-3">
                      {relatedSkills.map((related) => (
                        <Link
                          key={related.id}
                          href={`/skill/${related.slug}`}
                          className="block p-4 bg-slate-800/50 hover:bg-slate-800 rounded-xl transition-colors group"
                        >
                          <h4 className="font-medium text-white group-hover:text-violet-400 transition-colors mb-1">
                            {related.name}
                          </h4>
                          <p className="text-sm text-slate-400 line-clamp-2">
                            {related.description}
                          </p>
                        </Link>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
