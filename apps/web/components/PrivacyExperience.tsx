import Link from 'next/link'
import { ArrowLeft, ArrowRight } from 'lucide-react'
import { SiteHeader } from '@/components/SiteHeader'
import { SiteFooter } from '@/components/SiteFooter'
import styles from '@/components/SubpageShell.module.css'

export function PrivacyExperience() {
  return (
    <div className={`page-shell ${styles.page}`}>
      <SiteHeader current="privacy" />

      <main>
        {/* HERO */}
        <section className={`container ${styles.hero}`}>
          <Link href="/" className={styles.backLink}>
            <ArrowLeft size={12} /> audren.xyz
          </Link>
          <div className={styles.heroSingle}>
            <h1>Privacy Notice</h1>
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
              <strong>Data boundary map — browser vs. infrastructure vs. Solana</strong>
              <span>Spending keys never leave your device</span>
            </div>
            <svg
              className={styles.stageSvg}
              viewBox="0 0 920 208"
              role="img"
              aria-label="Three privacy boundaries: Your Device holds spend keys, view keys, local note decryption, and proof generation; RPC, Web Host & Optional Relay sees IP/connection metadata, RPC lookups, swap quotes, and anti-abuse hashes without spend keys; Solana Public Ledger records deposits, withdrawals, DEX legs, fee payers, and blinded transfer commitments"
            >
              {/* Connecting dashed tracks + animated data pulses */}
              <line x1="286" y1="102" x2="322" y2="102" stroke="#d5d0c3" strokeWidth="1.5" />
              <line x1="286" y1="102" x2="322" y2="102" stroke="#184433" strokeWidth="1.8" className={styles.flowDash} />
              <polygon points="326,102 318,97 318,107" fill="#184433" />
              <circle r="3.5" fill="#184433" opacity="0">
                <animateMotion dur="2.4s" repeatCount="indefinite" path="M 286,102 L 322,102" calcMode="spline" keyTimes="0;1" keySplines="0.4 0 0.2 1" />
                <animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.15;0.82;1" dur="2.4s" repeatCount="indefinite" />
              </circle>

              <line x1="600" y1="102" x2="636" y2="102" stroke="#e4d6c4" strokeWidth="1.5" />
              <line x1="600" y1="102" x2="636" y2="102" stroke="#8b5e34" strokeWidth="1.8" className={styles.flowDash} />
              <polygon points="640,102 632,97 632,107" fill="#8b5e34" />
              <circle r="3.5" fill="#8b5e34" opacity="0">
                <animateMotion dur="2.4s" begin="1.1s" repeatCount="indefinite" path="M 600,102 L 636,102" calcMode="spline" keyTimes="0;1" keySplines="0.4 0 0.2 1" />
                <animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.15;0.82;1" dur="2.4s" begin="1.1s" repeatCount="indefinite" />
              </circle>

              {/* Your Device */}
              <rect x="12" y="16" width="274" height="174" rx="2" fill="#184433" />
              <text x="28" y="39" fill="#c7dac8" fontSize="10" fontWeight="700" fontFamily="monospace" letterSpacing="0.6">
                STAYS ON YOUR DEVICE
              </text>
              <text x="28" y="62" fill="#f4f1ea" fontSize="15" fontWeight="700">
                Local keys &amp; prover
              </text>
              <text x="28" y="88" fill="#e6efe4" fontSize="11">— Spend &amp; view key derivation</text>
              <text x="28" y="109" fill="#e6efe4" fontSize="11">— AES-256-GCM note decryption</text>
              <text x="28" y="130" fill="#e6efe4" fontSize="11">— Triptych &amp; Bulletproof creation</text>
              <text x="28" y="151" fill="#e6efe4" fontSize="11">— Receipt verification openings</text>
              <text x="28" y="174" fill="#b9d1be" fontSize="9.8">Never sent in ordinary RPC or relay calls</text>

              {/* Web Host / RPC / Relay */}
              <rect x="326" y="16" width="274" height="174" rx="2" fill="#faf8f3" stroke="#184433" strokeWidth="1.3" />
              <rect x="326" y="16" width="274" height="3" fill="#184433" />
              <text x="342" y="39" fill="#55574e" fontSize="10" fontWeight="700" fontFamily="monospace" letterSpacing="0.6">
                INFRASTRUCTURE OPERATORS
              </text>
              <text x="342" y="62" fill="#121210" fontSize="15" fontWeight="700">
                Web host, RPC &amp; relay
              </text>
              <text x="342" y="88" fill="#3b3f36" fontSize="11">— Connection &amp; IP request metadata</text>
              <text x="342" y="109" fill="#3b3f36" fontSize="11">— Account lookups &amp; swap quotes</text>
              <text x="342" y="130" fill="#3b3f36" fontSize="11">— Hosted relay anti-abuse guard hashes</text>
              <text x="342" y="151" fill="#3b3f36" fontSize="11">— Zero user spend or view keys</text>
              <text x="342" y="174" fill="#6b6e62" fontSize="9.8">Switchable RPC &amp; pluggable relay URL</text>

              {/* Solana Ledger */}
              <rect x="640" y="16" width="268" height="174" rx="2" fill="#f7efe3" stroke="#8b5e34" strokeWidth="1.3" />
              <rect x="640" y="16" width="268" height="3" fill="#8b5e34" />
              <text x="656" y="39" fill="#8b5e34" fontSize="10" fontWeight="700" fontFamily="monospace" letterSpacing="0.6">
                PUBLIC SOLANA CHAIN
              </text>
              <text x="656" y="62" fill="#121210" fontSize="15" fontWeight="700">
                On-chain visibility
              </text>
              <text x="656" y="88" fill="#3b3f36" fontSize="11">— Transfer: blinded mint, amount &amp; key</text>
              <text x="656" y="109" fill="#3b3f36" fontSize="11">— Deposit / Withdraw: public amounts</text>
              <text x="656" y="130" fill="#3b3f36" fontSize="11">— DEX swap: public pair &amp; amounts</text>
              <text x="656" y="151" fill="#3b3f36" fontSize="11">— Candidate pages, fee payer &amp; timing</text>
              <text x="656" y="174" fill="#6e4928" fontSize="9.8">Permanent public blockchain record</text>
            </svg>
          </div>
        </section>

        {/* DETAILED DISCLOSURES IN CLEAN 3-COLUMN LEDGER */}
        <section className={styles.sectionAlt}>
          <div className="container">
            <div className={styles.ledger3}>
              <article className={`${styles.ledgerCell} ${styles.ledgerCellHighlight}`}>
                <span className={styles.cellIndex}>LOCAL CUSTODY</span>
                <h3>Local keys &amp; exports</h3>
                <ul className={styles.dashList}>
                  <li>The wallet derives keys, decrypts notes, creates spending proofs, and checks receipt openings locally in your browser.</li>
                  <li>Spending and viewing keys are not included in ordinary RPC or relay requests.</li>
                  <li>Exporting a backup, single-note receipt, or viewing key deliberately shares the information inside that export; any recipient can retain or redistribute it.</li>
                  <li>The site loads zero advertising or third-party analytics scripts.</li>
                </ul>
              </article>

              <article className={styles.ledgerCell}>
                <span className={styles.cellIndex}>ON-CHAIN BOUNDARIES</span>
                <h3>Intentional public entry &amp; exit</h3>
                <ul className={styles.dashList}>
                  <li>A deposit from a public wallet exposes its funding account, token, amount, and output record.</li>
                  <li>A withdrawal exposes its destination, token, and amount; <code>ExecViaEscrow</code> exposes the target DeFi program, mints, routed amounts, and output record; any stateful borrow or perp position opened by a deterministic session wallet (<code>Bᵢ</code>) remains public on that Solana protocol.</li>
                  <li>Private Transfer proofs conceal the selected input note and blind token and amount commitments with a fresh recipient key, while candidate pages, timing, and fee payers remain public.</li>
                  <li>Concealing input selection does not guarantee that public information or external observations cannot connect transactions.</li>
                </ul>
                <div className={styles.cellFoot}>
                  <Link href="/faq" className={styles.textLink}>
                    Read effective-anonymity FAQ <ArrowRight size={13} />
                  </Link>
                </div>
              </article>

              <article className={styles.ledgerCell}>
                <span className={styles.cellIndex}>PROVIDERS &amp; RELAYS</span>
                <h3>Relayer &amp; host metadata</h3>
                <ul className={styles.dashList}>
                  <li>Anyone can run a compatible relayer, or submit directly with your own fee payer. Neither choice provides network anonymity by itself.</li>
                  <li>The website proxies RPC, token metadata, and Direct Self-Pay routing through its Cloudflare Worker; wallet-mode relay calls go to your selected relay.</li>
                  <li>The hosted relay stores IP-derived anti-abuse identifiers (salted with the public relay key — hashing is not anonymization), timestamps, sponsorship figures, and temporary associations with in-flight nullifiers.</li>
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
