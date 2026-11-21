import type { Metadata } from 'next'
import { ArchitectureExperience } from '@/components/ArchitectureExperience'

export const metadata: Metadata = {
  title: 'Protocol Specification',
  description:
    'Formal binary layout, Multi-Base Binary Triptych equations, Solana Transaction v1 (4,096 B) single-tx execution, ProofBuffer support, and security invariants for Audren v1 on Solana.',
  alternates: { canonical: 'https://audren.xyz/architecture/' },
}

export default function ArchitecturePage() {
  return <ArchitectureExperience />
}
