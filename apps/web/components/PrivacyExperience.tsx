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
                  <li>Private transfer proofs hide the spent input note and keep the token and amount inside commitments under a fresh recipient key, while GlobalRootHistory ring indices, output lanes, nullifiers, timing, and the fee payer remain public. If you pay fees yourself, your wallet is that fee payer.</li>
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
                  <li>The web app sends its RPC reads, token metadata, swap quotes, and directly paid transactions through the audren.xyz Cloudflare Worker; relayed spends go to the relay you select. That worker sees your IP together with your connected public wallet address (balance lookup), the pool pages your wallet reads, transactions you broadcast directly, and swap quote details (tokens and amount). To avoid it, self-host the app or use an SDK with your own RPC.</li>
                  <li>The hosted relay rate-limits by a truncated SHA-256 of your IP and a random salt held only in memory and replaced every UTC day. Hashed-IP events (operation type, sponsorship amount, timestamp) are kept about 25 hours; in-flight nullifiers are kept 45 seconds with no IP attached. The relay still sees your IP and your transaction together while processing it.</li>
                  <li>The hosted relay has Cloudflare Workers request logging enabled; those logs follow Cloudflare’s retention, separate from the relay’s own rate-limit records.</li>
                  <li>audren.xyz and the hosted relay are run by the same operator, so with the default settings one party can connect your IP, connected wallet, page reads, and relayed spends. On a fee-charging relayer, private transfers request a fee quote naming the token (never the amount); on the hosted sponsored relayer (no shielded FVK configured), private transfers skip /v1/fee-quote altogether. Swap quotes are forwarded to the selected aggregator (Jupiter, DFlow, or OKX). A relay you choose yourself, or your own RPC, splits these views.</li>
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
