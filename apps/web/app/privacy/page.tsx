import type { Metadata } from 'next'
import { PrivacyExperience } from '@/components/PrivacyExperience'

export const metadata: Metadata = {
  title: 'Privacy Notice',
  description: 'Local keys, public transaction boundaries and provider metadata when using Audren.',
  alternates: { canonical: 'https://audren.xyz/privacy/' },
  openGraph: {
    title: 'Privacy Notice · Audren',
    description: 'Local keys, public transaction boundaries and provider metadata when using Audren.',
    url: 'https://audren.xyz/privacy/',
    siteName: 'Audren',
    type: 'website',
    images: [{ url: '/og-image.png', width: 1280, height: 640, alt: 'Audren Privacy Notice' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Privacy Notice · Audren',
    description: 'Local keys, public transaction boundaries and provider metadata when using Audren.',
    images: ['/og-image.png'],
  },
}

export default function PrivacyPage() {
  return <PrivacyExperience />
}
