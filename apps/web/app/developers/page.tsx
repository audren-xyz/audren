import type { Metadata } from 'next'
import { DevelopersExperience } from '@/components/DevelopersExperience'

export const metadata: Metadata = {
  title: 'Build with Audren',
  description:
    'Published Codama and Anchor IDLs plus four optional Apache-2.0 SDKs (Rust, TypeScript, Swift for iOS, and Kotlin for Android) verified against one cross-language conformance spec.',
  alternates: { canonical: 'https://audren.xyz/developers/' },
  openGraph: {
    title: 'Build with Audren · Audren',
    description:
      'Published Codama and Anchor IDLs plus four optional Apache-2.0 SDKs verified against one cross-language conformance spec.',
    url: 'https://audren.xyz/developers/',
    siteName: 'Audren',
    type: 'website',
    images: [{ url: '/og-image.png', width: 1280, height: 640, alt: 'Build with Audren' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Build with Audren · Audren',
    description:
      'Published Codama and Anchor IDLs plus four optional Apache-2.0 SDKs verified against one cross-language conformance spec.',
    images: ['/og-image.png'],
  },
}

export default function DevelopersPage() {
  return <DevelopersExperience />
}
