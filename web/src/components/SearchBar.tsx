'use client';

import { Search, X } from 'lucide-react';

interface SearchBarProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}

export function SearchBar({ value, onChange, placeholder = 'Search skills...' }: SearchBarProps) {
  return (
    <div className="relative group">
      <div className="absolute inset-0 bg-gradient-to-r from-violet-500/20 to-cyan-500/20 rounded-xl blur-xl opacity-0 group-focus-within:opacity-100 transition-opacity" />
      <div className="relative flex items-center">
        <Search className="absolute left-4 h-5 w-5 text-slate-400" />
        <input
          type="text"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          className="w-full bg-slate-800/80 border border-slate-700 rounded-xl py-3 pl-12 pr-12 text-white placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-violet-500/50 focus:border-violet-500 transition-all"
        />
        {value && (
          <button
            onClick={() => onChange('')}
            className="absolute right-4 p-1 rounded-full hover:bg-slate-700 transition-colors"
          >
            <X className="h-4 w-4 text-slate-400" />
          </button>
        )}
      </div>
    </div>
  );
}
