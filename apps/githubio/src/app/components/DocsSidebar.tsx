'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

export interface NavItem {
  name: string;
  href: string;
}

export function DocsSidebar({ navigation }: { navigation: NavItem[] }) {
  const pathname = usePathname();

  return (
    <aside data-pagefind-ignore className="sticky top-24 hidden w-64 shrink-0 lg:block">
      <nav className="flex flex-col gap-4 font-mono text-xs">
        <div className="text-xs font-bold uppercase tracking-wider text-emerald-400">
          Documentation Manuals
        </div>
        <ul role="list" className="flex flex-col gap-1 border-l border-slate-800">
          {navigation.map((item) => {
            const isActive = pathname === item.href || (item.href !== '/docs' && pathname?.startsWith(item.href));

            return (
              <li key={item.name}>
                <Link
                  href={item.href}
                  className={`block py-1.5 pl-4 -ml-px border-l-2 transition-all font-sans text-sm ${
                    isActive
                      ? 'border-emerald-400 bg-emerald-950/20 text-emerald-300 font-semibold'
                      : 'border-transparent text-slate-400 hover:text-emerald-300 hover:border-slate-600'
                  }`}
                >
                  <span className="flex items-center justify-between">
                    <span>{item.name}</span>
                    {isActive && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse mr-2" />}
                  </span>
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>
    </aside>
  );
}
