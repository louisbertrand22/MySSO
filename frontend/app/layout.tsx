import type { Metadata } from "next";
import "./globals.css";
import { AuthProvider } from "@/contexts/AuthContext";
import { ThemeProvider } from "@/contexts/ThemeContext";
import Footer from "@/components/Footer";

export const metadata: Metadata = {
  title: "MySSO - Authentication",
  description: "Single Sign-On authentication system",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased flex flex-col min-h-screen">
        <ThemeProvider>
          <AuthProvider>
            <div className="flex-1 flex flex-col">
              {children}
            </div>
            <Footer />
          </AuthProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
