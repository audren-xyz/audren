import type { Metadata } from 'next'
import { DevelopersExperience } from '@/components/DevelopersExperience'

export const metadata: Metadata = {
  title: 'Build with Audren',
  description:
    'Start with the Rust proving client or zero-runtime-dependency TypeScript transaction helpers. Read the protocol and integrate independently.',
  alternates: { canonical: 'https://audren.xyz/developers/' },
}

export default function DevelopersPage() {
  return <DevelopersExperience />
}
