"use client";

import React, { useEffect, useRef, useState } from "react";
import mermaid from "mermaid";

mermaid.initialize({
  startOnLoad: false,
  theme: "dark",
  securityLevel: "loose",
});

export function Mermaid({ chart }: { chart: string }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [svgCode, setSvgCode] = useState<string>("");

  useEffect(() => {
    let isMounted = true;

    const renderChart = async () => {
      try {
        if (!chart) return;
        // Generate a unique ID for the SVG
        const id = `mermaid-svg-${Math.random().toString(36).substr(2, 9)}`;
        const { svg } = await mermaid.render(id, chart);
        if (isMounted) {
          setSvgCode(svg);
        }
      } catch (error) {
        console.error("Mermaid rendering error", error);
      }
    };

    renderChart();

    return () => {
      isMounted = false;
    };
  }, [chart]);

  return (
    <div
      ref={containerRef}
      className="my-6 flex justify-center overflow-x-auto bg-gray-900 rounded-lg p-4 border border-gray-700"
      dangerouslySetInnerHTML={{ __html: svgCode }}
    />
  );
}
