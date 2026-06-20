import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "artifact-notary",
  description: "GitHub Actions artifact integrity and privilege boundary scanner",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}