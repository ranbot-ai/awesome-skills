'use client';

import Link from 'next/link';
import { ExternalLink, Tag, ArrowRight } from 'lucide-react';
import { getSourceLabel, getSourceColor } from '@/lib/skills';
import type { Skill } from '@/types/skill';
import clsx from 'clsx';

interface SkillCardProps {
  skill: Skill;
}

export function SkillCard({ skill }: SkillCardProps) {
  return (
    <Link href={`/skill/${skill.slug}`}>
      <div className="group relative h-full">
        {/* Glow effect on hover */}
        <div className="absolute -inset-0.5 bg-gradient-to-r from-violet-600 to-cyan-600 rounded-2xl opacity-0 group-hover:opacity-75 blur transition-all duration-500" />

        <div className="relative h-full bg-slate-800/90 border border-slate-700/50 rounded-2xl p-6 flex flex-col transition-all duration-300 group-hover:border-transparent group-hover:bg-slate-800">
          {/* Header */}
          <div className="flex items-start justify-between gap-3 mb-4">
            <div className="flex-1 min-w-0">
              <h3 className="font-semibold text-lg text-white truncate group-hover:text-transparent group-hover:bg-clip-text group-hover:bg-gradient-to-r group-hover:from-violet-400 group-hover:to-cyan-400 transition-all">
                {skill.name}
              </h3>
              <div className="flex items-center gap-2 mt-1">
                <span className={clsx(
                  'inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium text-white',
                  getSourceColor(skill.source)
                )}>
                  {getSourceLabel(skill.source)}
                </span>
              </div>
            </div>
            <ArrowRight className="h-5 w-5 text-slate-500 group-hover:text-violet-400 group-hover:translate-x-1 transition-all flex-shrink-0" />
          </div>

          {/* Description */}
          <p className="text-slate-400 text-sm leading-relaxed line-clamp-3 flex-1 mb-4">
            {skill.description}
          </p>

          {/* Category */}
          <div className="mb-4">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-slate-700/50 rounded-lg text-xs text-slate-300">
              {skill.category}
            </span>
          </div>

          {/* Tags */}
          {skill.tags.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {skill.tags.slice(0, 4).map((tag) => (
                <span
                  key={tag}
                  className="inline-flex items-center gap-1 px-2 py-0.5 bg-slate-700/30 rounded text-xs text-slate-400"
                >
                  <Tag className="h-3 w-3" />
                  {tag}
                </span>
              ))}
              {skill.tags.length > 4 && (
                <span className="px-2 py-0.5 text-xs text-slate-500">
                  +{skill.tags.length - 4} more
                </span>
              )}
            </div>
          )}
        </div>
      </div>
    </Link>
  );
}
