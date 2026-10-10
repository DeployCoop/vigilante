"use client";

import { useState, useEffect, useRef } from "react";
import Link from "next/link";

interface SearchResult {
  url: string;
  meta: {
    title: string;
  };
  excerpt: string;
}

export function Search() {
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResult[]>([]);
  const [pagefind, setPagefind] = useState<any>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    async function loadPagefind() {
      if (typeof window !== "undefined") {
        try {
          // Dynamic import for the Pagefind bundle generated post-build
          // @ts-ignore
          const pf = await import(
            /* webpackIgnore: true */ "/vigilante/pagefind/pagefind.js"
          );
          await pf.options({ basePath: "/vigilante" });
          pf.init();
          setPagefind(pf);
        } catch (err) {
          console.error("Failed to load pagefind", err);
        }
      }
    }
    loadPagefind();
  }, []);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setIsOpen((open) => !open);
      }
      if (e.key === "Escape") {
        setIsOpen(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus();
    }
  }, [isOpen]);

  useEffect(() => {
    async function performSearch() {
      if (!pagefind || !query) {
        setResults([]);
        return;
      }
      const search = await pagefind.search(query);
      const data = await Promise.all(search.results.slice(0, 5).map((r: any) => r.data()));
      setResults(data);
    }
    performSearch();
  }, [query, pagefind]);

  return (
    <>
      <button
        onClick={() => setIsOpen(true)}
        className="flex items-center space-x-2 text-slate-400 hover:text-emerald-400 transition"
      >
        <svg
          xmlns="http://www.w3.org/2000/svg"
          fill="none"
          viewBox="0 0 24 24"
          strokeWidth={2}
          stroke="currentColor"
          className="w-5 h-5"
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="m21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" />
        </svg>
        <span className="hidden sm:inline">Search</span>
        <kbd className="hidden sm:inline font-mono text-xs border border-slate-700 bg-slate-800 rounded px-1 text-slate-500">⌘K</kbd>
      </button>

      {isOpen && (
        <div className="fixed inset-0 z-[100] flex items-start justify-center pt-16 sm:pt-24">
          <div className="fixed inset-0 bg-slate-900/80 backdrop-blur-sm" onClick={() => setIsOpen(false)} />
          <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-xl shadow-2xl overflow-hidden mx-4">
            <div className="flex items-center px-4 py-3 border-b border-slate-800">
              <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor" className="w-5 h-5 text-emerald-400">
                <path strokeLinecap="round" strokeLinejoin="round" d="m21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" />
              </svg>
              <input
                ref={inputRef}
                type="text"
                className="flex-1 bg-transparent border-0 outline-none px-3 text-slate-200 placeholder-slate-500 text-lg"
                placeholder="Search documentation..."
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
              <button onClick={() => setIsOpen(false)} className="text-slate-500 hover:text-slate-300">
                <kbd className="font-mono text-xs border border-slate-700 bg-slate-800 rounded px-1">ESC</kbd>
              </button>
            </div>
            
            {results.length > 0 && (
              <ul className="max-h-96 overflow-y-auto py-2">
                {results.map((res, i) => (
                  <li key={i}>
                    <Link
                      href={res.url.replace(/^\/vigilante/, "")}
                      onClick={() => setIsOpen(false)}
                      className="block px-4 py-3 hover:bg-slate-800 transition"
                    >
                      <div className="text-emerald-300 font-medium">{res.meta.title}</div>
                      <div className="text-sm text-slate-400 mt-1 line-clamp-2" dangerouslySetInnerHTML={{ __html: res.excerpt }} />
                    </Link>
                  </li>
                ))}
              </ul>
            )}
            
            {query && results.length === 0 && (
              <div className="px-4 py-8 text-center text-slate-500">
                No results found for "{query}".
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}
