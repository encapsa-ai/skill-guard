import { Analytics } from '@vercel/analytics/next'
import type { Metadata, Viewport } from 'next'
import { Geist_Mono, Plus_Jakarta_Sans } from 'next/font/google'
import './globals.css'

const jakarta = Plus_Jakarta_Sans({ subsets: ['latin'], variable: '--font-jakarta', display: 'swap' })
const geistMono = Geist_Mono({ subsets: ['latin'], variable: '--font-geist-mono', display: 'swap' })

const description = 'Inspect AI skill ZIPs for prompt injection, credential exposure, risky scripts, and hidden threats. Clear, evidence-based security reports by Encapsa.'

export const metadata: Metadata = {
  metadataBase: new URL('https://skillguard.encapsa.ai'),
  title: 'Skill Guard — AI Skill Security Analyzer | Encapsa',
  description,
  applicationName: 'Skill Guard',
  alternates: { canonical: '/' },
  icons: {
    icon: '/encapsa-mark.png',
    apple: '/encapsa-mark.png',
  },
  openGraph: {
    title: 'Skill Guard — Powerful skills. Safer agents.',
    description,
    url: '/',
    siteName: 'Skill Guard by Encapsa',
    type: 'website',
    images: [{ url: '/images/skill-guard-art.png', width: 1024, height: 1024, alt: 'Skill Guard by Encapsa' }],
  },
  twitter: { card: 'summary', title: 'Skill Guard by Encapsa', description },
}

export const viewport: Viewport = {
  colorScheme: 'light',
  themeColor: '#192f4d',
  width: 'device-width',
  initialScale: 1,
}

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className="bg-background">
      <body className={`${jakarta.variable} ${geistMono.variable} font-sans antialiased`}>
        {children}
        {process.env.NODE_ENV === 'production' && <Analytics />}
      </body>
    </html>
  )
}
