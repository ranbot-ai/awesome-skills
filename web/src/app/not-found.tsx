import Link from 'next/link';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';
import { ArrowLeft, SearchX } from 'lucide-react';

export default function NotFound() {
  return (
    <div className="min-h-screen bg-slate-950 flex flex-col">
      <Header />
      <main className="flex-1 flex items-center justify-center">
        <div className="text-center px-4">
          <div className="relative inline-block mb-8">
            <div className="absolute inset-0 bg-gradient-to-r from-violet-500 to-cyan-500 rounded-full blur-2xl opacity-30" />
            <div className="relative bg-slate-900 rounded-full p-6">
              <SearchX className="h-16 w-16 text-slate-400" />
            </div>
          </div>

          <h1 className="text-4xl font-bold text-white mb-4">Skill Not Found</h1>
          <p className="text-xl text-slate-400 mb-8 max-w-md mx-auto">
            The skill you are looking for does not exist or has been removed.
          </p>

          <Link
            href="/"
            className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-violet-600 to-cyan-600 hover:from-violet-500 hover:to-cyan-500 text-white font-medium rounded-xl transition-all shadow-lg shadow-violet-500/25 hover:shadow-violet-500/40"
          >
            <ArrowLeft className="h-5 w-5" />
            Back to Skills
          </Link>
        </div>
      </main>
      <Footer />
    </div>
  );
}
