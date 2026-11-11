import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { AuthProvider } from "@/contexts/AuthContext";
import { ThemeProvider, themeInitScript } from "@/contexts/ThemeContext";
import { OverlayProvider } from "@/components/ui/Overlays";
import Footer from "@/components/Footer";
import PwaSetup from "@/components/PwaSetup";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });

export const metadata: Metadata = {
  title: { default: "MySSO", template: "%s · MySSO" },
  description: "Un seul compte pour se connecter à toutes les applications MySSO.",
  applicationName: "MySSO",
  robots: { index: false, follow: false },
  // Installed on iOS: own window, name under the icon (the icon itself is app/apple-icon.png)
  appleWebApp: { capable: true, title: "MySSO", statusBarStyle: "default" },
  formatDetection: { telephone: false },
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#f9fafb" },
    { media: "(prefers-color-scheme: dark)", color: "#16181d" },
  ],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="fr" suppressHydrationWarning className={`${geistSans.variable} ${geistMono.variable}`}>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeInitScript }} />
      </head>
      <body className="flex min-h-dvh flex-col antialiased">
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-surface focus:px-3 focus:py-2 focus:shadow-[var(--shadow-pop)]"
        >
          Aller au contenu
        </a>
        <ThemeProvider>
          <AuthProvider>
            <OverlayProvider>
              <PwaSetup />
              <div className="flex flex-1 flex-col">{children}</div>
              <Footer />
            </OverlayProvider>
          </AuthProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
