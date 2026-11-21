import type { Metadata } from 'next'
import { DevnetDemoExperience } from '@/components/DevnetDemoExperience'

export const metadata: Metadata = {
  title: 'App & Devnet Sandbox',
  description:
    'Connect a Solana wallet on Mainnet or Devnet, or run the free Devnet sandbox without installing a wallet: deposit, send privately, swap via DEX aggregators, and verify a single-note commitment receipt.',
  alternates: { canonical: 'https://audren.xyz/demo/' },
}

export default function DemoPage() {
  return <DevnetDemoExperience />
}
