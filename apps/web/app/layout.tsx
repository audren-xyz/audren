import type { Metadata } from 'next'
import { IBM_Plex_Mono, Instrument_Sans, Newsreader } from 'next/font/google'
import './globals.css'

const serif = Newsreader({
  subsets: ['latin'],
  variable: '--font-serif',
  weight: ['400', '500', '600'],
  style: ['normal', 'italic'],
})

const sans = Instrument_Sans({
  subsets: ['latin'],
  variable: '--font-sans',
  weight: ['400', '500', '600', '700'],
})

const mono = IBM_Plex_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
  weight: ['400', '500', '600'],
})

export const metadata: Metadata = {
  metadataBase: new URL('https://audren.xyz'),
  title: {
    default: 'Audren — Your tokens. Your keys. Private payments.',
    template: '%s · Audren',
  },
  description:
    'Private transfers protect the sender, recipient, token and amount. Use existing Solana assets and keep your spending keys. Explore the open protocol on Mainnet.',
  alternates: { canonical: '/' },
  openGraph: {
    title: 'Audren — Your tokens. Your keys. Private payments.',
    description:
      'Private payments with existing Solana assets. Local proofs, keys you control, and public on-chain vaults.',
    url: 'https://audren.xyz',
    siteName: 'Audren',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Audren — Your tokens. Your keys. Private payments.',
    description:
      'Private payments with existing Solana assets. Your spending keys stay with you. Explore Audren on Mainnet.',
  },
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" className={`${serif.variable} ${sans.variable} ${mono.variable}`}>
      <body>{children}</body>
    </html>
  )
}
