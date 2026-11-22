import type { Metadata } from 'next'
import { FaqExperience } from '@/components/FaqExperience'

export const metadata: Metadata = {
  title: 'FAQ',
  description:
    'Technical and institutional questions about Audren multi-asset shielded pools, protocol-agnostic ExecViaEscrow DeFi CPIs, deterministic DeFi sessions, Solana Transaction v1 (4,096 B) single-tx execution, standard RPC scanning, and auditability.',
  alternates: { canonical: 'https://audren.xyz/faq/' },
}

export default function FaqPage() {
  return <FaqExperience />
}
