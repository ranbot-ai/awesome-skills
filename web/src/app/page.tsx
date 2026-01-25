import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';
import { SkillsGrid } from '@/components/SkillsGrid';
import { getSkillsData } from '@/lib/data-loader';

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
