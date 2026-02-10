import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Plateforme OSINT Passive",
  description: "Collecte passive de renseignements depuis des sources publiques",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="fr">
      <body className="min-h-screen bg-black text-white font-mono antialiased">
        <nav className="border-b border-neutral-800 px-8 h-12 flex items-center justify-between text-sm">
          <div className="font-bold tracking-widest uppercase">
            Plateforme OSINT Passive
          </div>
          <div className="flex gap-5 text-neutral-500 text-xs">
            <span>
              <span className="inline-block w-1.5 h-1.5 bg-white rounded-full mr-1.5" />
              En ligne
            </span>
          </div>
        </nav>
        <main className="max-w-5xl mx-auto px-6 py-10">{children}</main>
        <footer className="text-center py-8 text-[0.7rem] text-neutral-600 border-t border-neutral-900 mt-12 tracking-wide">
          Plateforme OSINT Passive v2.0.0 &mdash; Next.js 15 &mdash; Reconnaissance passive autorisée uniquement
        </footer>
      </body>
    </html>
  );
}
