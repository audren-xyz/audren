import type { Metadata } from 'next'
import { PrivacyExperience } from '@/components/PrivacyExperience'

export const metadata: Metadata = {
  title: 'Privacy Notice',
  description: 'Local keys, public transaction boundaries and provider metadata when using Audren.',
  alternates: { canonical: 'https://audren.xyz/privacy/' },
}

export default function PrivacyPage() {
  return <PrivacyExperience />
}
