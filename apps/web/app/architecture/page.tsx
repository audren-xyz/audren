import type { Metadata } from 'next'
import { ArchitectureExperience } from '@/components/ArchitectureExperience'

export const metadata: Metadata = {
  title: 'Protocol Specification',
  description:
    'Formal binary layout, BN254 Groth16 4-ary Depth-20 global MASP equations, Solana Transaction v1 (4,096 B) single-tx execution, inline GlobalRootHistory, 16-lane global MASP capacity and read-only full-exit scaling, and security invariants for Audren on Solana.',
  alternates: { canonical: 'https://audren.xyz/architecture/' },
  openGraph: {
    title: 'Protocol Specification · Audren',
    description:
      'Formal binary layout, BN254 Groth16 4-ary Depth-20 global MASP, inline GlobalRootHistory, and security invariants for Audren on Solana.',
    url: 'https://audren.xyz/architecture/',
    siteName: 'Audren',
    type: 'website',
    images: [{ url: '/og-image.png', width: 1280, height: 640, alt: 'Audren Protocol Specification' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Protocol Specification · Audren',
    description:
      'Formal binary layout, BN254 Groth16 4-ary Depth-20 global MASP, inline GlobalRootHistory, and security invariants for Audren on Solana.',
    images: ['/og-image.png'],
  },
}

export default function ArchitecturePage() {
  return <ArchitectureExperience />
}
