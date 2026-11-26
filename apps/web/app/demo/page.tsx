import type { Metadata } from 'next'
import { DevnetDemoExperience } from '@/components/DevnetDemoExperience'

export const metadata: Metadata = {
  title: 'App & Devnet Sandbox',
  description:
    'Connect a Solana wallet on Mainnet or Devnet, or run the free Devnet sandbox without installing a wallet: deposit, send privately, run shielded DeFi CPIs, fund DeFi sessions, and verify a single-note commitment receipt.',
  alternates: { canonical: 'https://audren.xyz/demo/' },
  openGraph: {
    title: 'App & Devnet Sandbox · Audren',
    description:
      'Connect a Solana wallet on Mainnet or Devnet, or run the free Devnet sandbox without installing a wallet.',
    url: 'https://audren.xyz/demo/',
    siteName: 'Audren',
    type: 'website',
    images: [{ url: '/og-image.png', width: 1280, height: 640, alt: 'Audren App & Devnet Sandbox' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'App & Devnet Sandbox · Audren',
    description:
      'Connect a Solana wallet on Mainnet or Devnet, or run the free Devnet sandbox without installing a wallet.',
    images: ['/og-image.png'],
  },
}

export default function DemoPage() {
  return <DevnetDemoExperience />
}
