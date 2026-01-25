import type { SkillsData, Skill } from '@/types/skill';

let cachedData: SkillsData | null = null;

export async function getSkillsData(): Promise<SkillsData> {
  if (cachedData) return cachedData;

  const response = await fetch(`${process.env.NEXT_PUBLIC_BASE_URL || ''}/data/skills.json`);
  cachedData = await response.json();
  return cachedData!;
}

export async function getSkillBySlug(slug: string): Promise<Skill | null> {
  const data = await getSkillsData();
  return data.skills.find(s => s.slug === slug) || null;
}

export function searchSkills(skills: Skill[], query: string): Skill[] {
  const lowerQuery = query.toLowerCase().trim();
  if (!lowerQuery) return skills;

  return skills.filter(skill => {
    return (
      skill.name.toLowerCase().includes(lowerQuery) ||
      skill.description.toLowerCase().includes(lowerQuery) ||
      skill.category.toLowerCase().includes(lowerQuery) ||
      skill.tags.some(tag => tag.toLowerCase().includes(lowerQuery))
    );
  });
}

export function filterByCategory(skills: Skill[], category: string): Skill[] {
  if (!category || category === 'all') return skills;
  return skills.filter(skill => skill.category === category);
}

export function filterBySource(skills: Skill[], source: string): Skill[] {
  if (!source || source === 'all') return skills;
  return skills.filter(skill => skill.source === source);
}

export function getSourceLabel(source: string): string {
  const labels: Record<string, string> = {
    composio: 'ComposioHQ',
    openhands: 'OpenHands',
    anthropic: 'Anthropic',
    superpowers: 'Superpowers',
    'awesome-llm': 'Awesome LLM',
  };
  return labels[source] || source;
}

export function getSourceColor(source: string): string {
  const colors: Record<string, string> = {
    composio: 'bg-violet-500',
    openhands: 'bg-emerald-500',
    anthropic: 'bg-orange-500',
    superpowers: 'bg-yellow-500',
    'awesome-llm': 'bg-pink-500',
  };
  return colors[source] || 'bg-gray-500';
}

export function getCategoryIcon(icon: string): string {
  const iconMap: Record<string, string> = {
    'file-text': '📄',
    'code': '💻',
    'bar-chart': '📊',
    'briefcase': '💼',
    'message-circle': '💬',
    'palette': '🎨',
    'folder': '📁',
    'users': '👥',
    'shield': '🛡️',
    'bot': '🤖',
  };
  return iconMap[icon] || '📦';
}
