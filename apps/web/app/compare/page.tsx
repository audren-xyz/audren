import type { Metadata } from 'next'
import { CompareExperience } from '@/components/CompareExperience'

export const metadata: Metadata = {
  title: 'Compare privacy approaches',
  description:
    'Compare public transfers, native Confidential Balances, Audren and other Solana privacy protocols by what is hidden and how they operate.',
  alternates: { canonical: 'https://audren.xyz/compare/' },
  openGraph: {
    title: 'Compare privacy approaches · Audren',
    description:
      'Compare public transfers, native Confidential Balances, Audren and other Solana privacy protocols by what is hidden and how they operate.',
    url: 'https://audren.xyz/compare/',
    siteName: 'Audren',
    type: 'website',
    images: [{ url: '/og-image.png', width: 1280, height: 640, alt: 'Compare Solana privacy approaches' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Compare privacy approaches · Audren',
    description:
      'Compare public transfers, native Confidential Balances, Audren and other Solana privacy protocols by what is hidden and how they operate.',
    images: ['/og-image.png'],
  },
}

export default function ComparePage() {
  return <CompareExperience />
}
