import type { Metadata } from 'next'
import { FaqExperience } from '@/components/FaqExperience'

export const metadata: Metadata = {
  title: 'FAQ',
  description:
    'Technical and institutional questions about Audren multi-asset shielded pools, protocol-agnostic ExecViaEscrow DeFi CPIs, deterministic DeFi sessions, Solana Transaction v1 (4,096 B) single-tx execution, standard RPC scanning, and auditability.',
  alternates: { canonical: 'https://audren.xyz/faq/' },
  openGraph: {
    title: 'FAQ · Audren',
    description:
      'Technical and institutional questions about Audren multi-asset shielded pools, ExecViaEscrow DeFi CPIs, RPC scanning, and auditability.',
    url: 'https://audren.xyz/faq/',
    siteName: 'Audren',
    type: 'website',
    images: [{ url: '/og-image.png', width: 1280, height: 640, alt: 'Audren FAQ' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'FAQ · Audren',
    description:
      'Technical and institutional questions about Audren multi-asset shielded pools, ExecViaEscrow DeFi CPIs, RPC scanning, and auditability.',
    images: ['/og-image.png'],
  },
}

export default function FaqPage() {
  return <FaqExperience />
}
