'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

export interface NavItem {
  name: string;
  href: string;
}

export function DocsPagination({ navigation }: { navigation: NavItem[] }) {
  const pathname = usePathname();

  // Find current index
  const currentIndex = navigation.findIndex(
    (item) => item.href === pathname || (item.href !== '/docs' && pathname?.startsWith(item.href))
  );

  const prev = currentIndex > 0 ? navigation[currentIndex - 1] : null;
  const next = currentIndex >= 0 && currentIndex < navigation.length - 1 ? navigation[currentIndex + 1] : null;

  if (!prev && !next) return null;

  return (
    <div data-pagefind-ignore className="mt-16 pt-8 border-t border-slate-800 grid grid-cols-1 sm:grid-cols-2 gap-4 not-prose font-sans">
      {prev ? (
        <Link
          href={prev.href}
          className="group p-4 rounded-xl border border-slate-800 bg-slate-900/60 hover:bg-slate-900 hover:border-emerald-500/50 transition-all flex flex-col space-y-1"
        >
          <span className="text-xs font-mono text-slate-500 group-hover:text-emerald-400 transition-colors">
            ← Previous Manual
          </span>
          <span className="text-sm font-bold text-slate-200 group-hover:text-white transition-colors">
            {prev.name}
          </span>
        </Link>
      ) : (
        <div />
      )}

      {next ? (
        <Link
          href={next.href}
          className="group p-4 rounded-xl border border-slate-800 bg-slate-900/60 hover:bg-slate-900 hover:border-emerald-500/50 transition-all flex flex-col items-end space-y-1 text-right"
        >
          <span className="text-xs font-mono text-slate-500 group-hover:text-emerald-400 transition-colors">
            Next Manual →
          </span>
          <span className="text-sm font-bold text-slate-200 group-hover:text-white transition-colors">
            {next.name}
          </span>
        </Link>
      ) : (
        <div />
      )}
    </div>
  );
}
