import { visit } from "unist-util-visit";

export default function rehypeAttachRawCode() {
  return (tree) => {
    visit(tree, (node) => {
      if (node?.type === "element" && node?.tagName === "pre") {
        const [codeEl] = node.children;
        if (codeEl?.tagName !== "code") return;
        node.properties.rawtext = codeEl.children[0].value;
        const className = codeEl.properties?.className || [];
        const langClass = className.find((c) => c.startsWith("language-"));
        if (langClass) {
          node.properties.language = langClass.replace("language-", "");
        }
      }
    });
  };
}
