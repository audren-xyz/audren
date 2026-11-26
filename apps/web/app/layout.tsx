import type { Metadata } from 'next'
import { IBM_Plex_Mono, Instrument_Sans, Newsreader } from 'next/font/google'
import './globals.css'

const serif = Newsreader({
  subsets: ['latin'],
  variable: '--font-serif',
  weight: ['400', '500'],
  style: ['normal'],
})

const sans = Instrument_Sans({
  subsets: ['latin'],
  variable: '--font-sans',
  weight: ['400', '500'],
})

const mono = IBM_Plex_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
  weight: ['400', '500'],
})

export const metadata: Metadata = {
  metadataBase: new URL('https://audren.xyz'),
  title: {
    default: 'Audren · Private payments on Solana',
    template: '%s · Audren',
  },
  description:
    'Relayed private transfers protect the sender, recipient, token and amount. Use existing Solana assets and keep your spending keys. Explore the open protocol on Mainnet.',
  alternates: { canonical: '/' },
  openGraph: {
    title: 'Audren · Private payments on Solana',
    description:
      'Private payments with existing Solana assets. Local proofs, keys you control, and public on-chain vaults.',
    url: 'https://audren.xyz',
    siteName: 'Audren',
    type: 'website',
    images: [
      {
        url: '/og-image.png',
        width: 1280,
        height: 640,
        alt: 'Audren: Private payments on Solana with existing tokens in one shared pool.',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Audren · Private payments on Solana',
    description:
      'Private payments with existing Solana assets. Your spending keys stay with you. Explore Audren on Mainnet.',
    images: ['/og-image.png'],
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
