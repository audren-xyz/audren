import Link from 'next/link'
import { ArrowLeft, ArrowRight } from 'lucide-react'
import { SiteHeader } from '@/components/SiteHeader'
import { SiteFooter } from '@/components/SiteFooter'
import styles from '@/components/SubpageShell.module.css'
import { DataBoundaryMap } from '@/components/motion/DataBoundaryMap'

export function PrivacyExperience() {
  return (
    <div className={`page-shell ${styles.page}`}>
      <SiteHeader current="privacy" />

      <main>
        {/* HERO */}
        <section className={`container ${styles.hero}`}>
          <Link href="/" className={styles.backLink}>
            <ArrowLeft size={13} /> audren.xyz
          </Link>
          <div className={styles.heroSingle}>
            <h1>Privacy notice</h1>
            <p className={styles.heroLead}>
              Local key custody, on-chain privacy, and privacy from an infrastructure operator are
              three separate properties. This page maps exactly what stays on your device, what
              service providers can observe, and what lands on Solana.
            </p>
          </div>
        </section>

        {/* VISUAL 3-ZONE DATA BOUNDARY MAP */}
        <section className={`container ${styles.section}`}>
          <div className={styles.sectionIntro}>
            <div>
              <h2>Three separate visibility zones.</h2>
            </div>
            <p>
              audren.xyz loads zero advertising or third-party analytics scripts. Using the web app
              still sends ordinary network requests to hosting, RPC, routing, and optional relay
              infrastructure.
            </p>
          </div>

          <div className={styles.diagramStage}>
            <div className={styles.stageHead}>
              <span className={styles.stageTitle}>
                Data boundary map: browser, infrastructure, and Solana
              </span>
              <span className={styles.stageMeta}>Spending keys never leave your device</span>
            </div>
            <DataBoundaryMap />
          </div>
        </section>

        {/* DETAILED DISCLOSURES IN CLEAN 3-COLUMN LEDGER */}
        <section className={styles.sectionAlt}>
          <div className="container">
            <div className={styles.ledger3}>
              <article className={`${styles.ledgerCell} ${styles.ledgerCellHighlight}`}>
                <span className={styles.cellIndex}>Local custody</span>
                <h3>Local keys &amp; exports</h3>
                <ul className={styles.dashList}>
                  <li>The wallet derives keys, decrypts notes, generates Groth16 proofs in a dedicated Web Worker, and checks receipt openings locally in your browser.</li>
                  <li>Spending and viewing keys are not included in ordinary RPC or relay requests.</li>
                  <li>Exporting a backup, single-note receipt, or viewing key deliberately shares the information inside that export; any recipient can retain or redistribute it.</li>
                  <li>The site loads zero advertising or third-party analytics scripts.</li>
                </ul>
              </article>

              <article className={styles.ledgerCell}>
                <span className={styles.cellIndex}>On-chain boundaries</span>
                <h3>Intentional public entry &amp; exit</h3>
                <ul className={styles.dashList}>
                  <li>A deposit from a public wallet exposes its funding account, token, amount, and output record.</li>
                  <li>A withdrawal exposes its destination, token, and amount; <code>ExecViaEscrow</code> exposes the target DeFi program, mints, routed amounts, and output record; any stateful borrow or perp position opened by a deterministic session wallet (<code>Bᵢ</code>) remains public on that Solana protocol.</li>
                  <li>Private Transfer proofs conceal the selected input note and blind token and amount commitments with a fresh recipient key, while checkpoint roots, output lanes, nullifiers, timing, and fee payers remain public.</li>
                  <li>Concealing input selection does not guarantee that public information or external observations cannot connect transactions.</li>
                </ul>
                <div className={styles.cellFoot}>
                  <Link href="/faq" className={styles.textLink}>
                    Read effective-anonymity FAQ <ArrowRight size={13} />
                  </Link>
                </div>
              </article>

              <article className={styles.ledgerCell}>
                <span className={styles.cellIndex}>Providers &amp; relays</span>
                <h3>Relayer &amp; host metadata</h3>
                <ul className={styles.dashList}>
                  <li>Anyone can run a compatible relayer, or submit directly with your own fee payer. Neither choice provides network anonymity by itself.</li>
                  <li>The website proxies RPC, token metadata, and Direct Self-Pay routing through its Cloudflare Worker; wallet-mode relay calls go to your selected relay.</li>
                  <li>The hosted relay rate-limits submissions using IP hashes derived with an ephemeral daily rotating secret salt that is never stored alongside spent nullifiers (rate-limit hashing is not network anonymization; timestamps and sponsorship figures are still observed during processing).</li>
                  <li>Expired guard records are pruned on cleanup, not guaranteed immediate deletion across every infrastructure log.</li>
                </ul>
              </article>
            </div>
          </div>
        </section>

        {/* CLOSING */}
        <section className={styles.closing}>
          <div className={`container ${styles.closingInner}`}>
            <div>
              <h2>Verify how every instruction behaves on-chain.</h2>
              <p>
                Read the full cryptographic specification or inspect live transactions directly on
                Solscan.
              </p>
            </div>
            <div className={styles.closingActions}>
              <Link href="/architecture" className="btn-paper">
                Protocol specification
              </Link>
              <Link href="/terms" className={styles.closingLink}>
                Protocol terms <ArrowRight size={15} />
              </Link>
            </div>
          </div>
        </section>
      </main>

      <SiteFooter current="privacy" />
    </div>
  )
}
