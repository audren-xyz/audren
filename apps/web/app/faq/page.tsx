import type { Metadata } from 'next'
import { FaqExperience } from '@/components/FaqExperience'

export const metadata: Metadata = {
  title: 'FAQ',
  description:
    'Technical and institutional questions about Audren multi-asset shielded pools, router-agnostic DEX swaps, Solana Transaction v1 (4,096 B) single-tx execution, standard RPC scanning, and auditability.',
  alternates: { canonical: 'https://audren.xyz/faq/' },
}

export default function FaqPage() {
  return <FaqExperience />
}
