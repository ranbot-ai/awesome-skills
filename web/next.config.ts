import type { NextConfig } from "next";
import path from "path";

const nextConfig: NextConfig = {
  // Set the workspace root to fix multiple lockfile warning
  outputFileTracingRoot: path.join(__dirname, "../"),

  // Output mode: 'standalone' for Docker, 'export' for static
  output: process.env.NEXT_OUTPUT === "export"
    ? "export"
    : process.env.NEXT_OUTPUT === "standalone"
      ? "standalone"
      : undefined,

  // Enable trailing slash for static export compatibility
  // This generates /about/index.html instead of /about.html
  // Required for proper routing on static hosting servers
  trailingSlash: true,

  // Image optimization settings
  images: {
    unoptimized: process.env.NEXT_OUTPUT === "export",
  },
};

export default nextConfig;
