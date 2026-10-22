/** @type {import('next').NextConfig} */
const nextConfig = {
  transpilePackages: ['vigilante_lib'],
  reactStrictMode: true,
  // Next 15+ name for experimental.serverComponentsExternalPackages.
  serverExternalPackages: ['execa', 'meow'],
  typescript: {
    ignoreBuildErrors: true
  }
  // The Next 14 `eslint` config key was removed in Next 16; linting is
  // configured by eslint.config.mjs and run via the lint script.
};

export default nextConfig;
