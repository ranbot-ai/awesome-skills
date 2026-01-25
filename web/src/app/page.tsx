import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';
import { SkillsGrid } from '@/components/SkillsGrid';
import type { SkillsData } from '@/types/skill';

async function getSkillsData(): Promise<SkillsData> {
  // In production, this would fetch from an API or static file
  const fs = await import('fs');
  const path = await import('path');
  const dataPath = path.join(process.cwd(), 'public', 'data', 'skills.json');
  const data = JSON.parse(fs.readFileSync(dataPath, 'utf-8'));
  return data;
}

export default async function HomePage() {
  const data = await getSkillsData();

  return (
    <div className="min-h-screen bg-slate-950">
      <Header />
      <main>
        <SkillsGrid skills={data.skills} categories={data.categories} sources={data.sources} />
      </main>
      <Footer />
    </div>
  );
}
