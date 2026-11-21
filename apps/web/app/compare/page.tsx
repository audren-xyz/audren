import type { Metadata } from 'next'
import { CompareExperience } from '@/components/CompareExperience'

export const metadata: Metadata = {
  title: 'Compare privacy approaches',
  description:
    'Compare public transfers, native Confidential Balances, Audren and other Solana privacy protocols by what is hidden and how they operate.',
  alternates: { canonical: 'https://audren.xyz/compare/' },
}

export default function ComparePage() {
  return <CompareExperience />
}
