"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";

export function MobileNav({ navigation }: { navigation: { name: string; href: string }[] }) {
  const [isOpen, setIsOpen] = useState(false);
  const pathname = usePathname();

  return (
    <div className="lg:hidden mb-8 border-b border-slate-800 pb-4">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center text-sm font-semibold text-emerald-400 focus:outline-none"
      >
        <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          {isOpen ? (
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          ) : (
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
          )}
        </svg>
        {isOpen ? "Close Menu" : "Menu"}
      </button>

      {isOpen && (
        <nav className="mt-4 flex flex-col gap-4 bg-slate-900 p-4 rounded-lg border border-slate-800">
          <ul role="list" className="flex flex-col gap-2">
            {navigation.map((item) => {
              const isActive = pathname === item.href || pathname === item.href + "/";
              return (
                <li key={item.name}>
                  <Link
                    href={item.href}
                    onClick={() => setIsOpen(false)}
                    className={`block text-sm leading-6 transition-colors ${
                      isActive ? "text-emerald-400 font-semibold" : "text-slate-400 hover:text-emerald-300"
                    }`}
                  >
                    {item.name}
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>
      )}
    </div>
  );
}
