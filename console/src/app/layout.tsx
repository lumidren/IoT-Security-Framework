import type { Metadata, Viewport } from 'next';
import { Inter } from 'next/font/google';
import { Toaster } from '@/components/ui/sonner';
import { MockProvider } from '@/providers/mock-provider';
import { QueryProvider } from '@/providers/query-provider';
import { ThemeProvider } from '@/providers/theme-provider';
import './globals.css';

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
  display: 'swap',
});

export const metadata: Metadata = {
  title: {
    default: 'IronMesh Console',
    template: '%s · IronMesh Console',
  },
  description:
    'Fleet console for the IronMesh IoT security framework: device lifecycle, certificates, OTA campaigns, MQTT policy and anomaly alerts.',
  applicationName: 'IronMesh Console',
  referrer: 'strict-origin-when-cross-origin',
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  themeColor: [
    { media: '(prefers-color-scheme: light)', color: '#ffffff' },
    { media: '(prefers-color-scheme: dark)', color: '#131620' },
  ],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning className={inter.variable}>
      <body className="min-h-dvh font-sans">
        <ThemeProvider>
          <MockProvider>
            <QueryProvider>
              {children}
              <Toaster />
            </QueryProvider>
          </MockProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
