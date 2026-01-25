'use client';

import { useState, useMemo } from 'react';
import { SkillCard } from './SkillCard';
import { SearchBar } from './SearchBar';
import { FilterBar } from './FilterBar';
import { CategoryCard } from './CategoryCard';
import { searchSkills, filterByCategory, filterBySource } from '@/lib/skills';
import type { Skill, SkillCategory, SourceInfo } from '@/types/skill';
import { Sparkles, Package, Star, Github } from 'lucide-react';

interface SkillsGridProps {
  skills: Skill[];
  categories: SkillCategory[];
  sources: SourceInfo[];
}

export function SkillsGrid({ skills, categories, sources }: SkillsGridProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [selectedSource, setSelectedSource] = useState('all');

  const filteredSkills = useMemo(() => {
    let result = skills;

    if (searchQuery) {
      result = searchSkills(result, searchQuery);
    }

    if (selectedCategory !== 'all') {
      const categoryName = categories.find(c => c.id === selectedCategory)?.name;
      if (categoryName) {
        result = result.filter(s => s.category === categoryName);
      }
    }

    if (selectedSource !== 'all') {
      result = filterBySource(result, selectedSource);
    }

    return result;
  }, [skills, categories, searchQuery, selectedCategory, selectedSource]);

  const handleCategoryClick = (categoryId: string) => {
    setSelectedCategory(selectedCategory === categoryId ? 'all' : categoryId);
  };

  return (
    <div>
      {/* Hero Section */}
      <section className="relative py-20 overflow-hidden">
        {/* Background Effects */}
        <div className="absolute inset-0 bg-gradient-to-b from-violet-600/10 via-transparent to-transparent" />
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-violet-500/20 rounded-full blur-3xl" />
        <div className="absolute top-0 right-1/4 w-96 h-96 bg-cyan-500/20 rounded-full blur-3xl" />

        <div className="container mx-auto px-4 relative">
          <div className="max-w-4xl mx-auto text-center">
            <div className="inline-flex items-center gap-2 px-4 py-2 bg-slate-800/80 border border-slate-700 rounded-full text-sm text-slate-300 mb-6">
              <Sparkles className="h-4 w-4 text-violet-400" />
              <span>{skills.length} Agent Skills Available</span>
            </div>

            <h1 className="text-4xl md:text-6xl font-bold text-white mb-6 leading-tight">
              Discover{' '}
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-violet-400 via-cyan-400 to-violet-400 animate-gradient">
                AI Agent Skills
              </span>
            </h1>

            <p className="text-xl text-slate-400 mb-10 max-w-2xl mx-auto">
              A curated collection of powerful skills from the open-source community.
              Enhance your AI agents with specialized capabilities.
            </p>

            {/* Search */}
            <div className="max-w-xl mx-auto">
              <SearchBar
                value={searchQuery}
                onChange={setSearchQuery}
                placeholder="Search by name, category, or tags..."
              />
            </div>
          </div>

          {/* Sources with Stars */}
          <div className="flex flex-wrap justify-center gap-4 mt-10">
            {sources.map((source) => (
              <a
                key={source.name}
                href={source.url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-3 px-4 py-2 bg-slate-800/60 border border-slate-700/50 rounded-xl hover:bg-slate-800 hover:border-slate-600 transition-all group"
              >
                <Github className="h-4 w-4 text-slate-400 group-hover:text-white transition-colors" />
                <span className="text-sm font-medium text-slate-300 group-hover:text-white transition-colors">
                  {source.name}
                </span>
                {source.stars && source.stars > 0 && (
                  <span className="flex items-center gap-1 text-sm text-amber-400">
                    <Star className="h-3.5 w-3.5 fill-amber-400" />
                    {source.stars >= 1000 ? `${(source.stars / 1000).toFixed(1)}k` : source.stars}
                  </span>
                )}
                {source.skillCount > 0 && (
                  <span className="text-xs text-slate-500">
                    {source.skillCount} skills
                  </span>
                )}
              </a>
            ))}
          </div>
        </div>
      </section>

      {/* Categories Section */}
      <section id="categories" className="py-12 border-t border-white/5">
        <div className="container mx-auto px-4">
          <div className="flex items-center gap-3 mb-8">
            <Package className="h-6 w-6 text-violet-400" />
            <h2 className="text-2xl font-bold text-white">Browse by Category</h2>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {categories.map((category) => (
              <CategoryCard
                key={category.id}
                category={category}
                isSelected={selectedCategory === category.id}
                onClick={() => handleCategoryClick(category.id)}
              />
            ))}
          </div>
        </div>
      </section>

      {/* Skills Grid */}
      <section className="py-12 border-t border-white/5">
        <div className="container mx-auto px-4">
          <FilterBar
            categories={categories}
            selectedCategory={selectedCategory}
            selectedSource={selectedSource}
            onCategoryChange={setSelectedCategory}
            onSourceChange={setSelectedSource}
            totalCount={skills.length}
            filteredCount={filteredSkills.length}
          />

          {filteredSkills.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {filteredSkills.map((skill) => (
                <SkillCard key={skill.id} skill={skill} />
              ))}
            </div>
          ) : (
            <div className="text-center py-20">
              <div className="text-6xl mb-4">🔍</div>
              <h3 className="text-xl font-semibold text-white mb-2">No skills found</h3>
              <p className="text-slate-400">Try adjusting your search or filters</p>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
