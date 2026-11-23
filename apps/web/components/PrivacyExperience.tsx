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
            <svg
              className={styles.stageSvg}
              viewBox="0 0 920 212"
              role="img"
              aria-label="Three privacy boundaries: Your Device holds spend keys, view keys, session keypairs, local note decryption, and proof generation; RPC, Web Host and Optional Relay sees IP/connection metadata, RPC lookups, quotes, and anti-abuse hashes without spend keys; Solana Public Ledger records deposits, withdrawals, ExecViaEscrow DeFi CPI legs, session wallet activity, fee payers, and blinded transfer commitments"
            >
              {/* Connecting dashed tracks + animated data pulses */}
              <line x1="286" y1="106" x2="322" y2="106" stroke="#c8d4c8" strokeWidth="1.5" />
              <line x1="286" y1="106" x2="322" y2="106" stroke="#184433" strokeWidth="1.6" className={styles.flowDash} />
              <polygon points="326,106 318,101 318,111" fill="#184433" />
              <circle r="3.2" fill="#184433" opacity="0">
                <animateMotion dur="2.4s" repeatCount="indefinite" path="M 286,106 L 322,106" calcMode="spline" keyTimes="0;1" keySplines="0.4 0 0.2 1" />
                <animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.15;0.82;1" dur="2.4s" repeatCount="indefinite" />
              </circle>

              <line x1="600" y1="106" x2="636" y2="106" stroke="#dfd3c0" strokeWidth="1.5" />
              <line x1="600" y1="106" x2="636" y2="106" stroke="#6e4928" strokeWidth="1.6" className={styles.flowDash} />
              <polygon points="640,106 632,101 632,111" fill="#6e4928" />
              <circle r="3.2" fill="#6e4928" opacity="0">
                <animateMotion dur="2.4s" begin="1.1s" repeatCount="indefinite" path="M 600,106 L 636,106" calcMode="spline" keyTimes="0;1" keySplines="0.4 0 0.2 1" />
                <animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.15;0.82;1" dur="2.4s" begin="1.1s" repeatCount="indefinite" />
              </circle>

              {/* Your Device */}
              <rect x="12" y="16" width="274" height="180" rx="6" fill="#184433" />
              <text x="28" y="40" fill="#cfe0d4" fontSize="11.5" fontWeight="500" fontFamily="var(--font-sans), sans-serif">
                Stays on your device
              </text>
              <text x="28" y="64" fill="#faf8f3" fontSize="16" fontWeight="500" fontFamily="var(--font-serif), Georgia, serif">
                Local keys &amp; prover
              </text>
              <circle cx="31" cy="87.5" r="2" fill="#9bc0a8" />
              <text x="41" y="91" fill="#e6efe4" fontSize="11.5" fontWeight="400" fontFamily="var(--font-sans), sans-serif">
                Spend, nk &amp; view key derivation
              </text>
              <circle cx="31" cy="108.5" r="2" fill="#9bc0a8" />
              <text x="41" y="112" fill="#e6efe4" fontSize="11.5" fontWeight="400" fontFamily="var(--font-sans), sans-serif">
                ChaCha20-Poly1305 memo scan
              </text>
              <circle cx="31" cy="129.5" r="2" fill="#9bc0a8" />
              <text x="41" y="133" fill="#e6efe4" fontSize="11.5" fontWeight="400" fontFamily="var(--font-sans), sans-serif">
                BN254 Groth16 WASM proving
              </text>
              <circle cx="31" cy="150.5" r="2" fill="#9bc0a8" />
              <text x="41" y="154" fill="#e6efe4" fontSize="11.5" fontWeight="400" fontFamily="var(--font-sans), sans-serif">
                CompactWalletStore &amp; receipts
              </text>
              <text x="28" y="180" fill="#cfe0d4" fontSize="10.5" fontWeight="400" fontFamily="var(--font-sans), sans-serif">
                Never sent in ordinary RPC or relay calls
              </text>

              {/* Web Host / RPC / Relay */}
              <rect x="326" y="16" width="274" height="180" rx="6" fill="#faf8f3" />
              <text x="342" y="40" fill="#696b61" fontSize="11.5" fontWeight="500" fontFamily="var(--font-sans), sans-serif">
                Infrastructure operators
              </text>
              <text x="342" y="64" fill="#161614" fontSize="16" fontWeight="500" fontFamily="var(--font-serif), Georgia, serif">
                Web host, RPC &amp; relay
              </text>
              <circle cx="345" cy="87.5" r="2" fill="#696b61" />
              <text x="355" y="91" fill="#4f5148" fontSize="11.5" fontWeight="400" fontFamily="var(--font-sans), sans-serif">
                Connection &amp; IP request metadata
              </text>
              <circle cx="345" cy="108.5" r="2" fill="#696b61" />
              <text x="355" y="112" fill="#4f5148" fontSize="11.5" fontWeight="400" fontFamily="var(--font-sans), sans-serif">
                Account lookups &amp; swap quotes
              </text>
              <circle cx="345" cy="129.5" r="2" fill="#696b61" />
              <text x="355" y="133" fill="#4f5148" fontSize="11.5" fontWeight="400" fontFamily="var(--font-sans), sans-serif">
                Hosted relay anti-abuse guard hashes
              </text>
              <circle cx="345" cy="150.5" r="2" fill="#696b61" />
              <text x="355" y="154" fill="#4f5148" fontSize="11.5" fontWeight="400" fontFamily="var(--font-sans), sans-serif">
                Zero user spend or view keys
              </text>
              <text x="342" y="180" fill="#696b61" fontSize="10.5" fontWeight="400" fontFamily="var(--font-sans), sans-serif">
                Switchable RPC &amp; pluggable relay URL
              </text>

              {/* Solana Ledger */}
              <rect x="640" y="16" width="268" height="180" rx="6" fill="#f0ebe0" />
              <text x="656" y="40" fill="#6e4928" fontSize="11.5" fontWeight="500" fontFamily="var(--font-sans), sans-serif">
                Public Solana chain
              </text>
              <text x="656" y="64" fill="#161614" fontSize="16" fontWeight="500" fontFamily="var(--font-serif), Georgia, serif">
                On-chain visibility
              </text>
              <circle cx="659" cy="87.5" r="2" fill="#6e4928" />
              <text x="669" y="91" fill="#4f5148" fontSize="11.5" fontWeight="400" fontFamily="var(--font-sans), sans-serif">
                JoinSplit: hidden mint, amt &amp; key
              </text>
              <circle cx="659" cy="108.5" r="2" fill="#6e4928" />
              <text x="669" y="112" fill="#4f5148" fontSize="11.5" fontWeight="400" fontFamily="var(--font-sans), sans-serif">
                Deposit / Exit: public amounts
              </text>
              <circle cx="659" cy="129.5" r="2" fill="#6e4928" />
              <text x="669" y="133" fill="#4f5148" fontSize="11.5" fontWeight="400" fontFamily="var(--font-sans), sans-serif">
                DeFi CPI &amp; Bᵢ: public protocol legs
              </text>
              <circle cx="659" cy="150.5" r="2" fill="#6e4928" />
              <text x="669" y="154" fill="#4f5148" fontSize="11.5" fontWeight="400" fontFamily="var(--font-sans), sans-serif">
                Checkpoint, lane, fee payer &amp; timing
              </text>
              <text x="656" y="180" fill="#6e4928" fontSize="10.5" fontWeight="400" fontFamily="var(--font-sans), sans-serif">
                Permanent public blockchain record
              </text>
            </svg>
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
                  <li>The wallet derives keys, decrypts notes, creates spending proofs, and checks receipt openings locally in your browser.</li>
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
                  <li>The hosted relay stores IP-derived anti-abuse identifiers (salted with the public relay key; hashing is not anonymization), timestamps, sponsorship figures, and temporary associations with in-flight nullifiers.</li>
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
