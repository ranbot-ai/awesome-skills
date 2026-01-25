import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Agent Skills | RanBOT Labs - Discover AI Capabilities",
  description: "A curated collection of AI agent skills from the open-source community. Discover, explore, and implement powerful capabilities for Claude, OpenHands, and other AI agents. A RanBOT Labs project.",
  keywords: ["AI", "agents", "skills", "Claude", "OpenHands", "LLM", "automation", "workflows", "RanBOT", "RanBOT Labs"],
  authors: [{ name: "RanBOT Labs", url: "https://ranbot.online" }],
  creator: "RanBOT Labs",
  publisher: "RanBOT Labs",
  icons: {
    icon: [
      { url: "/favicon.svg", type: "image/svg+xml" },
    ],
    apple: "/icon.svg",
  },
  openGraph: {
    title: "Agent Skills | RanBOT Labs - Discover AI Capabilities",
    description: "A curated collection of AI agent skills from the open-source community. A RanBOT Labs project.",
    type: "website",
    siteName: "Agent Skills by RanBOT Labs",
    url: "https://ranbot.online",
  },
  twitter: {
    card: "summary_large_image",
    title: "Agent Skills | RanBOT Labs",
    description: "A curated collection of AI agent skills from the open-source community.",
    creator: "@ranbotlabs",
  },
  metadataBase: new URL("https://ranbot.online"),
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-slate-950 text-white`}
      >
        {children}
      </body>
    </html>
  );
}
