import type { Metadata } from 'next'
import Link from 'next/link'
import { ArrowLeft, ArrowRight, ArrowUpRight } from 'lucide-react'
import { SiteHeader } from '@/components/SiteHeader'
import { SiteFooter } from '@/components/SiteFooter'
import { AUDREN, explorerAddress, solscanAddress } from '@/lib/protocol'
import styles from '@/components/SubpageShell.module.css'

export const metadata: Metadata = {
  title: 'Protocol Terms',
  description: 'Open-source cryptographic software notice for audren.xyz.',
  alternates: { canonical: 'https://audren.xyz/terms/' },
}

export default function TermsPage() {
  return (
    <div className={`page-shell ${styles.page}`}>
      <SiteHeader current="terms" />

      <main>
        {/* HERO */}
        <section className={`container ${styles.hero}`}>
          <Link href="/" className={styles.backLink}>
            <ArrowLeft size={13} /> audren.xyz
          </Link>
          <div className={styles.heroSingle}>
            <h1>Protocol terms</h1>
            <p className={styles.heroLead}>
              Effective November 2026. Open-source software notice, self-custody responsibilities,
              and independent verification checklist for audren.xyz and the Audren Solana program.
            </p>
          </div>
        </section>

        {/* 3-PILLAR TERMS LEDGER */}
        <section className={`container ${styles.section}`}>
          <div className={styles.ledger3}>
            <article className={styles.ledgerCell}>
              <span className={styles.cellIndex}>Scope</span>
              <h3>Informational specification</h3>
              <p className={styles.cellLead}>
                audren.xyz publishes open technical documentation, on-chain deployment records, an
                interactive browser wallet interface, and open-source SDK references for the Audren
                Solana program.
              </p>
              <ul className={styles.dashList}>
                <li>Nothing on this site constitutes financial, legal, tax, or investment advice.</li>
                <li>Software and hosted web endpoints are provided as-is without warranty of merchantability, uptime, or fitness for a particular purpose.</li>
              </ul>
            </article>

            <article className={`${styles.ledgerCell} ${styles.ledgerCellHighlight}`}>
              <span className={styles.cellIndex}>Custody &amp; license</span>
              <h3>Non-custodial Apache-2.0 software</h3>
              <p className={styles.cellLead}>
                Audren on-chain code and client libraries are released as non-custodial open-source
                software under the Apache-2.0 license: under the deployed program, no operator key can
                spend your notes.
              </p>
              <ul className={styles.dashList}>
                <li>During pre-audit releases, the program&rsquo;s upgrade authority can replace the program code, including its custody logic. Verify the deployed hash below before use.</li>
                <li>The pool authority cannot spend notes, but it can pause deposits and private spends (full exits stay open with read-only GlobalRootHistory) and adjust rent-fee caps within fixed bounds. Because GlobalRootHistory updates inline with zero idle wall-clock expiry and immutable root_epoch_interval, no authority can delay or block full exits.</li>
                <li>Both authorities are currently one operator key (<code style={{ wordBreak: 'break-all' }}>{AUDREN.operatorAuthority}</code>), not a multisig.</li>
                <li>Token issuers keep their own controls: a freeze authority, permanent delegate, pausable mint, or upgradable transfer hook applies to the shared vault account for that token and so to every Audren holder of it.</li>
                <li>Users and institutions are solely responsible for safeguarding master seeds, viewing keys, and auditor keys.</li>
                <li>Users are solely responsible for tax reporting and regulatory compliance within their jurisdictions.</li>
              </ul>
            </article>

            <article className={styles.ledgerCell}>
              <span className={styles.cellIndex}>Pre-audit status</span>
              <h3>Independent verification</h3>
              <p className={styles.cellLead}>
                Audren is in active pre-audit release using Groth16 keys derived from the official
                Hermez Perpetual Powers of Tau (54 contributions plus a beacon) plus Audren&rsquo;s
                two-contribution BGM17 Phase-2 ceremony (<code>ceremony/transcript.json</code>). Both
                Phase-2 contributions were made by Audren, so until an independent contributor joins,
                proof soundness depends on Audren having destroyed those secrets. No
                independent audit has been published yet, and the Solana upgrade authority remains
                mutable during pre-audit releases; any decision to revoke it will be announced
                separately.
              </p>
              <ul className={styles.dashList}>
                <li>Before committing capital, review the sBPFv3 source code and Groth16 circuit in <code>audren-xyz/audren</code> and verify deployed ProgramData hashes on-chain.</li>
                <li>Test full deposit-to-withdrawal flows on Solana Devnet or LiteSVM before Mainnet use.</li>
              </ul>
            </article>
          </div>
        </section>

        {/* VERIFICATION RECORD */}
        <section className={styles.sectionAlt}>
          <div className="container">
            <div className={styles.sectionIntro}>
              <div>
                <h2>Deployment verification register</h2>
              </div>
              <p>
                Verify the exact program, ProgramData account, and sBPFv3 ELF digest on Solana
                before interacting with Mainnet or Devnet pools.
              </p>
            </div>

            <div className={styles.tableWrap}>
              <table className={styles.table}>
                <thead>
                  <tr>
                    <th>Artifact</th>
                    <th>Identifier / Digest</th>
                    <th>Verify</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td><span className={styles.tableLead}>Audren Program ID</span></td>
                    <td><code>{AUDREN.programId}</code></td>
                    <td>
                      <a href={solscanAddress(AUDREN.programId)} target="_blank" rel="noreferrer" className={styles.textLink}>
                        Solscan <ArrowUpRight size={12} />
                      </a>
                    </td>
                  </tr>
                  <tr>
                    <td><span className={styles.tableLead}>ProgramData Account</span></td>
                    <td><code>{AUDREN.programData}</code></td>
                    <td>
                      <a href={solscanAddress(AUDREN.programData)} target="_blank" rel="noreferrer" className={styles.textLink}>
                        Solscan <ArrowUpRight size={12} />
                      </a>
                    </td>
                  </tr>
                  <tr>
                    <td><span className={styles.tableLead}>Pool #0 (open to anyone; has a pool authority)</span></td>
                    <td><code>{AUDREN.pool0Pda}</code></td>
                    <td>
                      <a href={solscanAddress(AUDREN.pool0Pda)} target="_blank" rel="noreferrer" className={styles.textLink}>
                        Solscan <ArrowUpRight size={12} />
                      </a>
                    </td>
                  </tr>
                  <tr>
                    <td><span className={styles.tableLead}>GlobalRootHistory PDA (Pool #0, AUD1RT01, 10,216 B)</span></td>
                    <td><code>{AUDREN.rootsPda}</code></td>
                    <td>
                      <a href={solscanAddress(AUDREN.rootsPda)} target="_blank" rel="noreferrer" className={styles.textLink}>
                        Solscan <ArrowUpRight size={12} />
                      </a>
                    </td>
                  </tr>
                  <tr>
                    <td><span className={styles.tableLead}>Vault Authority (WSOL &amp; Token Custody)</span></td>
                    <td><code>{AUDREN.vaultAuthPda}</code></td>
                    <td>
                      <a href={`${solscanAddress(AUDREN.vaultAuthPda)}#portfolio`} target="_blank" rel="noreferrer" className={styles.textLink}>
                        Solscan <ArrowUpRight size={12} />
                      </a>
                    </td>
                  </tr>
                  <tr>
                    <td><span className={styles.tableLead}>Verified Build Hash ({AUDREN.deployedReleaseTag})</span></td>
                    <td><code>{AUDREN.executableHash}</code></td>
                    <td>
                      <a href={explorerAddress(AUDREN.programId, 'verified-build')} target="_blank" rel="noreferrer" className={styles.textLink}>
                        Explorer Verified Build <ArrowUpRight size={12} />
                      </a>
                    </td>
                  </tr>
                  <tr>
                    <td><span className={styles.tableLead}>Deployed ELF SHA-256 ({AUDREN.elfBytes.toLocaleString()} B)</span></td>
                    <td><code>{AUDREN.elfSha256}</code></td>
                    <td>
                      <a href={AUDREN.deployedReleaseUrl} target="_blank" rel="noreferrer" className={styles.textLink}>
                        GitHub Release <ArrowUpRight size={12} />
                      </a>
                    </td>
                  </tr>
                  <tr>
                    <td><span className={styles.tableLead}>Canonical Program IDL PDA</span></td>
                    <td><code>{AUDREN.idlPda}</code></td>
                    <td>
                      <a href={explorerAddress(AUDREN.programId, 'idl')} target="_blank" rel="noreferrer" className={styles.textLink}>
                        Explorer IDL <ArrowUpRight size={12} />
                      </a>
                    </td>
                  </tr>
                  <tr>
                    <td><span className={styles.tableLead}>Canonical Security Metadata PDA</span></td>
                    <td><code>{AUDREN.securityPda}</code></td>
                    <td>
                      <a href={explorerAddress(AUDREN.programId, 'security')} target="_blank" rel="noreferrer" className={styles.textLink}>
                        Explorer Security <ArrowUpRight size={12} />
                      </a>
                    </td>
                  </tr>
                  <tr>
                    <td><span className={styles.tableLead}>Otter Verify PDA (Mainnet)</span></td>
                    <td><code>{AUDREN.otterVerifyPda}</code></td>
                    <td>
                      <a href={AUDREN.osecVerifyStatusUrl} target="_blank" rel="noreferrer" className={styles.textLink}>
                        verify.osec.io <ArrowUpRight size={12} />
                      </a>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </section>

        {/* CLOSING */}
        <section className={styles.closing}>
          <div className={`container ${styles.closingInner}`}>
            <div>
              <h2>Read the privacy boundaries and technical spec.</h2>
              <p>
                Understand exactly what stays on your device, what relays observe, and what lands
                on Solana.
              </p>
            </div>
            <div className={styles.closingActions}>
              <Link href="/privacy" className="btn-paper">
                Privacy notice
              </Link>
              <Link href="/architecture" className={styles.closingLink}>
                Protocol specification <ArrowRight size={15} />
              </Link>
            </div>
          </div>
        </section>
      </main>

      <SiteFooter current="terms" />
    </div>
  )
}
