/** @type {import('next').NextConfig} */
const nextConfig = {
  transpilePackages: ['vigilante_lib'],
  reactStrictMode: true,
  experimental: {
    serverComponentsExternalPackages: ['execa', 'meow']
  },
  typescript: {
    ignoreBuildErrors: true
  },
  eslint: {
    ignoreDuringBuilds: true
  }
};

export default nextConfig;
