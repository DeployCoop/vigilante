declare module "*/pagefind/pagefind.js" {
  export const options: (opts: any) => Promise<void>;
  export const init: () => void;
  export const search: (query: string) => Promise<any>;
}
