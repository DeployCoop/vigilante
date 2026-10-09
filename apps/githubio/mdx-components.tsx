import type { MDXComponents } from "mdx/types";

export function useMDXComponents(components: MDXComponents): MDXComponents {
  return {
    h1: (props) => <h1 className="text-4xl font-extrabold tracking-tight lg:text-5xl mb-6 text-emerald-400" {...props} />,
    h2: (props) => <h2 className="border-b border-gray-700 pb-2 text-3xl font-semibold tracking-tight transition-colors first:mt-0 mt-10 mb-4 text-emerald-300" {...props} />,
    h3: (props) => <h3 className="text-2xl font-semibold tracking-tight mt-8 mb-4 text-emerald-200" {...props} />,
    h4: (props) => <h4 className="text-xl font-semibold tracking-tight mt-6 mb-3 text-emerald-100" {...props} />,
    p: (props) => <p className="leading-7 [&:not(:first-child)]:mt-6 text-gray-300" {...props} />,
    ul: (props) => <ul className="my-6 ml-6 list-disc [&>li]:mt-2 text-gray-300" {...props} />,
    ol: (props) => <ol className="my-6 ml-6 list-decimal [&>li]:mt-2 text-gray-300" {...props} />,
    li: (props) => <li className="text-gray-300" {...props} />,
    blockquote: (props) => <blockquote className="mt-6 border-l-2 border-emerald-500 pl-6 italic text-gray-400" {...props} />,
    a: (props) => <a className="font-medium text-emerald-400 underline underline-offset-4 hover:text-emerald-300" {...props} />,
    pre: (props) => <pre className="mb-4 mt-6 overflow-x-auto rounded-lg border border-gray-700 bg-gray-900 p-4 text-gray-300" {...props} />,
    code: (props) => <code className="relative rounded bg-gray-800 px-[0.3rem] py-[0.2rem] font-mono text-sm text-emerald-300" {...props} />,
    table: (props) => <div className="my-6 w-full overflow-y-auto"><table className="w-full text-gray-300" {...props} /></div>,
    th: (props) => <th className="border border-gray-700 px-4 py-2 text-left font-bold [&[align=center]]:text-center [&[align=right]]:text-right bg-gray-800 text-emerald-200" {...props} />,
    td: (props) => <td className="border border-gray-700 px-4 py-2 text-left [&[align=center]]:text-center [&[align=right]]:text-right" {...props} />,
    hr: (props) => <hr className="my-10 border-gray-700" {...props} />,
    ...components,
  };
}
