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

  // Image optimization settings
  images: {
    unoptimized: process.env.NEXT_OUTPUT === "export",
  },
};

export default nextConfig;
