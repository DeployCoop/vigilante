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
    <div className="mx-auto flex w-full max-w-7xl items-start gap-x-8 px-4 py-10 sm:px-6 lg:px-8 bg-gray-950 text-gray-100 min-h-screen">
      <aside className="sticky top-10 hidden w-64 shrink-0 lg:block">
        <nav className="flex flex-col gap-4">
          <div className="text-sm font-semibold leading-6 text-emerald-400">Documentation</div>
          <ul role="list" className="flex flex-col gap-2">
            {navigation.map((item) => (
              <li key={item.name}>
                <Link
                  href={item.href}
                  className="block text-sm leading-6 text-gray-400 hover:text-emerald-300"
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
  );
}
