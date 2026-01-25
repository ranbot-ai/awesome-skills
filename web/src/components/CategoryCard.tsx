'use client';

import { getCategoryIcon } from '@/lib/skills';
import type { SkillCategory } from '@/types/skill';
import clsx from 'clsx';

interface CategoryCardProps {
  category: SkillCategory;
  isSelected: boolean;
  onClick: () => void;
}

const categoryGradients: Record<string, string> = {
  'development--code-tools': 'from-violet-500 to-purple-500',
  'ai--agents': 'from-cyan-500 to-blue-500',
  'productivity--organization': 'from-emerald-500 to-teal-500',
  'business--marketing': 'from-orange-500 to-amber-500',
  'creative--media': 'from-pink-500 to-rose-500',
  'communication--writing': 'from-indigo-500 to-blue-500',
  'data--analysis': 'from-green-500 to-emerald-500',
  'document-processing': 'from-slate-500 to-zinc-500',
  'collaboration--project-management': 'from-yellow-500 to-orange-500',
  'security--systems': 'from-red-500 to-rose-500',
};

export function CategoryCard({ category, isSelected, onClick }: CategoryCardProps) {
  const gradient = categoryGradients[category.id] || 'from-slate-500 to-zinc-500';

  return (
    <button
      onClick={onClick}
      className={clsx(
        'group relative overflow-hidden rounded-2xl p-6 text-left transition-all duration-300',
        isSelected
          ? 'ring-2 ring-violet-500 bg-slate-800'
          : 'bg-slate-800/50 hover:bg-slate-800 border border-slate-700/50 hover:border-slate-600'
      )}
    >
      {/* Background gradient on hover */}
      <div className={clsx(
        'absolute inset-0 bg-gradient-to-br opacity-0 group-hover:opacity-10 transition-opacity',
        gradient
      )} />

      <div className="relative">
        <div className="flex items-center justify-between mb-3">
          <span className="text-3xl">{getCategoryIcon(category.icon)}</span>
          <span className={clsx(
            'px-2.5 py-1 rounded-full text-xs font-semibold',
            isSelected
              ? 'bg-violet-500 text-white'
              : 'bg-slate-700 text-slate-300'
          )}>
            {category.count}
          </span>
        </div>

        <h3 className="font-semibold text-white mb-1">{category.name}</h3>
        <p className="text-sm text-slate-400 line-clamp-2">{category.description}</p>
      </div>
    </button>
  );
}
