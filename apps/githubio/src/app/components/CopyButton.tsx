"use client";

import { useState } from "react";

export function CopyButton({ text }: { text: string }) {
  const [isCopied, setIsCopied] = useState(false);

  const copy = async () => {
    await navigator.clipboard.writeText(text);
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
  };

  return (
    <button
      disabled={isCopied}
      onClick={copy}
      className="absolute right-4 top-4 rounded bg-slate-800 px-2 py-1 text-xs font-medium text-slate-300 hover:bg-slate-700 disabled:opacity-50 transition"
    >
      {isCopied ? "Copied!" : "Copy"}
    </button>
  );
}
