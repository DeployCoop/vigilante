import type { Metadata } from 'next';
import './globals.css';
import { AppShell } from '@/components/AppShell';

export const metadata: Metadata = {
  title: 'Vigilante | Autonomous Security Operations Platform',
  description: 'Cyber battle station, dynamic NastyMap network visualizer, kCTF arena, and eBPF security telemetry.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#070a13] text-slate-100 min-h-screen flex flex-col font-sans">
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}

