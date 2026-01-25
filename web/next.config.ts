import type { NextConfig } from "next";
import path from "path";

const nextConfig: NextConfig = {
  // Set the workspace root to fix multiple lockfile warning
  outputFileTracingRoot: path.join(__dirname, "../"),

  // Enable static export for production builds
  output: process.env.NEXT_OUTPUT === "export" ? "export" : undefined,

  // Image optimization settings
  images: {
    unoptimized: process.env.NEXT_OUTPUT === "export",
  },
};

export default nextConfig;
