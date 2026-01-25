'use client';

import { ChevronDown, Filter, X } from 'lucide-react';
import { useState, useRef, useEffect } from 'react';
import clsx from 'clsx';
import type { SkillCategory } from '@/types/skill';

interface FilterBarProps {
  categories: SkillCategory[];
  selectedCategory: string;
  selectedSource: string;
  onCategoryChange: (category: string) => void;
  onSourceChange: (source: string) => void;
  totalCount: number;
  filteredCount: number;
}

const sources = [
  { id: 'all', name: 'All Sources' },
  { id: 'composio', name: 'ComposioHQ' },
  { id: 'openhands', name: 'OpenHands' },
];

export function FilterBar({
  categories,
  selectedCategory,
  selectedSource,
  onCategoryChange,
  onSourceChange,
  totalCount,
  filteredCount,
}: FilterBarProps) {
  const [showCategoryDropdown, setShowCategoryDropdown] = useState(false);
  const [showSourceDropdown, setShowSourceDropdown] = useState(false);
  const categoryRef = useRef<HTMLDivElement>(null);
  const sourceRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (categoryRef.current && !categoryRef.current.contains(event.target as Node)) {
        setShowCategoryDropdown(false);
      }
      if (sourceRef.current && !sourceRef.current.contains(event.target as Node)) {
        setShowSourceDropdown(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const hasFilters = selectedCategory !== 'all' || selectedSource !== 'all';

  const clearFilters = () => {
    onCategoryChange('all');
    onSourceChange('all');
  };

  const getCategoryName = () => {
    if (selectedCategory === 'all') return 'All Categories';
    return categories.find(c => c.id === selectedCategory)?.name || 'All Categories';
  };

  const getSourceName = () => {
    return sources.find(s => s.id === selectedSource)?.name || 'All Sources';
  };

  return (
    <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-6">
      <div className="flex flex-wrap items-center gap-3">
        {/* Category Dropdown */}
        <div className="relative" ref={categoryRef}>
          <button
            onClick={() => setShowCategoryDropdown(!showCategoryDropdown)}
            className={clsx(
              'flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium transition-all',
              selectedCategory !== 'all'
                ? 'bg-violet-600 text-white'
                : 'bg-slate-800 text-slate-300 hover:bg-slate-700 border border-slate-700'
            )}
          >
            <Filter className="h-4 w-4" />
            {getCategoryName()}
            <ChevronDown className={clsx('h-4 w-4 transition-transform', showCategoryDropdown && 'rotate-180')} />
          </button>

          {showCategoryDropdown && (
            <div className="absolute top-full left-0 mt-2 w-64 bg-slate-800 border border-slate-700 rounded-xl shadow-xl z-50 overflow-hidden">
              <div className="max-h-80 overflow-y-auto">
                <button
                  onClick={() => {
                    onCategoryChange('all');
                    setShowCategoryDropdown(false);
                  }}
                  className={clsx(
                    'w-full px-4 py-3 text-left text-sm hover:bg-slate-700 transition-colors',
                    selectedCategory === 'all' ? 'bg-violet-600/20 text-violet-400' : 'text-slate-300'
                  )}
                >
                  All Categories
                </button>
                {categories.map((category) => (
                  <button
                    key={category.id}
                    onClick={() => {
                      onCategoryChange(category.id);
                      setShowCategoryDropdown(false);
                    }}
                    className={clsx(
                      'w-full px-4 py-3 text-left text-sm hover:bg-slate-700 transition-colors flex items-center justify-between',
                      selectedCategory === category.id ? 'bg-violet-600/20 text-violet-400' : 'text-slate-300'
                    )}
                  >
                    <span>{category.name}</span>
                    <span className="text-slate-500">{category.count}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Source Dropdown */}
        <div className="relative" ref={sourceRef}>
          <button
            onClick={() => setShowSourceDropdown(!showSourceDropdown)}
            className={clsx(
              'flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium transition-all',
              selectedSource !== 'all'
                ? 'bg-cyan-600 text-white'
                : 'bg-slate-800 text-slate-300 hover:bg-slate-700 border border-slate-700'
            )}
          >
            {getSourceName()}
            <ChevronDown className={clsx('h-4 w-4 transition-transform', showSourceDropdown && 'rotate-180')} />
          </button>

          {showSourceDropdown && (
            <div className="absolute top-full left-0 mt-2 w-48 bg-slate-800 border border-slate-700 rounded-xl shadow-xl z-50 overflow-hidden">
              {sources.map((source) => (
                <button
                  key={source.id}
                  onClick={() => {
                    onSourceChange(source.id);
                    setShowSourceDropdown(false);
                  }}
                  className={clsx(
                    'w-full px-4 py-3 text-left text-sm hover:bg-slate-700 transition-colors',
                    selectedSource === source.id ? 'bg-cyan-600/20 text-cyan-400' : 'text-slate-300'
                  )}
                >
                  {source.name}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Clear Filters */}
        {hasFilters && (
          <button
            onClick={clearFilters}
            className="flex items-center gap-1.5 px-3 py-2 text-sm text-slate-400 hover:text-white transition-colors"
          >
            <X className="h-4 w-4" />
            Clear
          </button>
        )}
      </div>

      {/* Results Count */}
      <p className="text-sm text-slate-400">
        Showing <span className="text-white font-medium">{filteredCount}</span> of{' '}
        <span className="text-white font-medium">{totalCount}</span> skills
      </p>
    </div>
  );
}
