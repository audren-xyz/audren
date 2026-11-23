import type { Metadata } from 'next'
import { DevelopersExperience } from '@/components/DevelopersExperience'

export const metadata: Metadata = {
  title: 'Build with Audren',
  description:
    'Four standardized Apache-2.0 SDKs (Rust, TypeScript, Swift for iOS, and Kotlin for Android) sharing six identical building blocks and one cross-language conformance spec.',
  alternates: { canonical: 'https://audren.xyz/developers/' },
}

export default function DevelopersPage() {
  return <DevelopersExperience />
}
