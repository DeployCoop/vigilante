import Link from "next/link";
import { ReactNode } from "react";

const navigation = [
  { name: "Introduction", href: "/docs" },
  { name: "Getting Started", href: "/docs/getting-started" },
  { name: "Architecture", href: "/docs/architecture" },
  { name: "Development & Testing", href: "/docs/development" },
  { name: "Engines Reference", href: "/docs/engines" },
  { name: "Agents", href: "/docs/agents" },
  { name: "First Response", href: "/docs/first-response" },
];

export default function DocsLayout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans">
      <nav className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <Link href="/" className="flex items-center space-x-2">
            <span className="text-2xl font-black tracking-wider text-emerald-400">VIGILANTE</span>
          </Link>
          <span className="text-xs bg-emerald-950 text-emerald-300 border border-emerald-800 px-2 py-0.5 rounded-full font-mono">Docs</span>
        </div>
        <div className="flex items-center space-x-6 text-sm text-slate-400">
          <Link href="/" className="hover:text-emerald-400 transition">← Back to Overview</Link>
          <a href="https://github.com/DeployCoop/vigilante" target="_blank" rel="noreferrer" className="text-emerald-400 hover:text-emerald-300 transition font-medium">GitHub →</a>
        </div>
      </nav>

      <div className="mx-auto flex w-full max-w-7xl items-start gap-x-8 px-4 py-10 sm:px-6 lg:px-8">
        <aside className="sticky top-24 hidden w-64 shrink-0 lg:block">
          <nav className="flex flex-col gap-4">
            <div className="text-sm font-semibold leading-6 text-emerald-400">Documentation</div>
            <ul role="list" className="flex flex-col gap-2">
              {navigation.map((item) => (
                <li key={item.name}>
                  <Link
                    href={item.href}
                    className="block text-sm leading-6 text-slate-400 hover:text-emerald-300"
                  >
                    {item.name}
                  </Link>
                </li>
              ))}
            </ul>
          </nav>
        </aside>

        <main className="flex-1 overflow-hidden min-w-0">
          <div className="prose prose-invert prose-emerald max-w-none">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
