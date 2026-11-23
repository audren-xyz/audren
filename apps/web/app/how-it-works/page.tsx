import type { Metadata } from 'next'
import Link from 'next/link'
import { ArrowLeft } from 'lucide-react'
import { SiteHeader } from '@/components/SiteHeader'
import { SiteFooter } from '@/components/SiteFooter'
import { HowAudrenWorksVisual } from '@/components/HowAudrenWorksVisual'
import styles from '@/components/SubpageShell.module.css'

export const metadata: Metadata = {
  title: 'How Audren works',
  description:
    'Follow existing assets, private ownership records, local proofs and public settlement through Audren.',
  alternates: { canonical: 'https://audren.xyz/how-it-works/' },
}

export default function HowItWorksPage() {
  return (
    <div className={`page-shell ${styles.page}`}>
      <SiteHeader current="how-it-works" />
      <main>
        <section className={`container ${styles.hero}`}>
          <Link href="/" className={styles.backLink}>
            <ArrowLeft size={13} /> audren.xyz
          </Link>
          <div className={styles.heroSingle}>
            <h1>Public assets. Private ownership.</h1>
            <p className={styles.heroLead}>
              The shared vault holds original Solana assets while your device holds the spending
              key. Step through one reusable <code>aud1…</code> address, four real-world flows, and
              the checks the Audren program runs before any spend settles.
            </p>
          </div>
          <div className={styles.heroMetaStrip}>
            <div className={styles.heroMetaCell}>
              <span className={styles.heroMetaLabel}>Receiving address</span>
              <span className={styles.heroMetaValue}>
                BIP-350 Bech32m <code>aud1…</code> → 1-time stealth owners
              </span>
            </div>
            <div className={styles.heroMetaCell}>
              <span className={styles.heroMetaLabel}>Spend proof</span>
              <span className={styles.heroMetaValue}>
                192 B BN254 Groth16 · 4<sup>20</sup> Global MASP
              </span>
            </div>
            <div className={styles.heroMetaCell}>
              <span className={styles.heroMetaLabel}>Wallet discovery</span>
              <span className={styles.heroMetaValue}>Ordinary Solana RPC · Zero indexer</span>
            </div>
            <div className={styles.heroMetaCell}>
              <span className={styles.heroMetaLabel}>Public boundaries</span>
              <span className={styles.heroMetaValue}>
                Deposits, DEX legs, withdrawals &amp; fee payer
              </span>
            </div>
          </div>
        </section>

        <HowAudrenWorksVisual />
      </main>
      <SiteFooter current="how-it-works" />
    </div>
  )
}
