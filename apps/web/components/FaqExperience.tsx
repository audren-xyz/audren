'use client'

import { useState } from 'react'
import Link from 'next/link'
import { ArrowLeft, ArrowRight, ChevronDown } from 'lucide-react'
import { SiteHeader } from '@/components/SiteHeader'
import { SiteFooter } from '@/components/SiteFooter'
import styles from '@/components/SubpageShell.module.css'

type CategoryId = 'all' | 'privacy' | 'swaps' | 'crypto' | 'custody'

interface FaqItem {
  id: string
  category: Exclude<CategoryId, 'all'>
  catLabel: string
  q: string
  a: string
}

const CATEGORIES: { id: CategoryId; label: string }[] = [
  { id: 'all', label: 'All questions (13)' },
  { id: 'privacy', label: 'Privacy & rings' },
  { id: 'swaps', label: 'Swaps & tokens' },
  { id: 'crypto', label: 'Proofs & scanning' },
  { id: 'custody', label: 'Custody, fees & audits' },
]

const FAQS: readonly FaqItem[] = [
  {
    id: 'boundaries',
    category: 'privacy',
    catLabel: 'Privacy & rings',
    q: 'Are public deposits, withdrawals and optional relayers design choices?',
    a: 'Yes. Deposits expose the funding account, token, amount and new record. Withdrawals expose the destination, token and amount; ordinary external DEX execution exposes trade details. Audren aims to conceal which candidate note funds a spend, rather than hide public token movements. Anyone can operate a compatible relayer, and clients can submit directly. A relay pays fees without receiving spending keys, but can observe requests and network metadata. Direct submission exposes the wallet used as fee payer. These are intentional boundaries, not evidence of a broken proof.',
  },
  {
    id: 'tvl',
    category: 'privacy',
    catLabel: 'Privacy & rings',
    q: 'Does more TVL or a larger ring guarantee more anonymity?',
    a: 'No. Ring sizes of 32, 64 or 128 describe slot capacity, not a count of independent users or equally plausible inputs. Empty slots add no candidates. Publicly known records, candidate selection, amounts, timing and outside information can narrow the possibilities. More independent, plausible activity may help; TVL alone does not guarantee that. The demo defaults to 32 slots, can fall back when insufficient decoy pages exist, and caps swap rings at 64. Effective anonymity means the candidates an observer still considers plausible, not the number printed on the selector.',
  },
  {
    id: 'solvency',
    category: 'custody',
    catLabel: 'Custody, fees & audits',
    q: 'Do public vault balances prove solvency?',
    a: 'No. Vault accounts show assets held by the protocol. They do not independently reveal all private liabilities or prove that every claim is covered. Net-receipt accounting and balance/range proofs enforce specific accounting rules under the implementation and cryptographic assumptions. They are not a substitute for independent review, and the program remains pre-audit and upgradeable.',
  },
  {
    id: 'solscan',
    category: 'privacy',
    catLabel: 'Privacy & rings',
    q: 'What appears on Solscan for the shared pool vault (vault_auth) versus my personal wallet?',
    a: 'Vault holdings are public; individual ownership is represented by private records. A private Transfer conceals its input record and blinds its output asset and value. Recipient keys are one-time. The fee payer, candidate pages and transaction metadata remain public. Deposits, external swaps and withdrawals expose their tokens and amounts; public withdrawals expose the destination too. A separate fee payer avoids directly adding your wallet to a private spend, but network metadata, timing and external information can still link activity. Privacy depends on usable candidate sets and activity patterns, not TVL alone.',
  },
  {
    id: 'compare',
    category: 'privacy',
    catLabel: 'Privacy & rings',
    q: 'How does Audren differ from Helius Privacy Rings or Token-2022 Confidential Transfers?',
    a: 'Native Token-2022 Confidential Balances hide amounts while account relationships and the mint remain public. Helius Privacy Rings support existing assets and self-custody; default confidential transfers expose sender and recipient, while custom rings can provide anonymity. Audren private transfers conceal the spent record, use fresh recipient keys and blind the token and amount, with local proofs, no trusted setup and standard Solana account RPC discovery. See the Compare page for sources and boundaries; privacy is not an absolute anonymity guarantee.',
  },
  {
    id: 'dex',
    category: 'swaps',
    catLabel: 'Swaps & tokens',
    q: 'Which Solana DEX aggregators and AMMs work with SwapViaRouter?',
    a: 'SwapViaRouter is router-agnostic: it accepts any compatible PDA-signing Solana DEX aggregator or AMM instruction (such as Titan, DFlow, OKX DEX, Jupiter, Raydium, Orca, Meteora, or a custom router) and checks escrow ownership, delegates, lamports, and slippage before settling to a fresh private record. Integrators choose whichever aggregator their relay or client routes through; the hosted demo currently uses Jupiter (collecting small swap fees to help cover relay sponsorship). Router adapters in source do not imply every venue or hosted service is enabled, and external DEX tokens and trade amounts remain public.',
  },
  {
    id: 'tokens',
    category: 'swaps',
    catLabel: 'Swaps & tokens',
    q: 'Which tokens and Token-2022 extensions does Audren support?',
    a: 'Audren accepts native SOL, classic SPL and transferable Token-2022 assets without an Audren wrapper token. Deposits use the net received vault delta for fee-on-transfer accounting; transfer hooks receive sanitized trailing accounts. NonTransferable mints cannot transfer. Issuer freeze controls, permanent delegates, hook policies and other token restrictions still apply. Integration support is not a guarantee that every mint can move in every state.',
  },
  {
    id: 'third-party-deposit',
    category: 'swaps',
    catLabel: 'Swaps & tokens',
    q: 'Can third parties or payment gateways deposit directly to a user’s shielded address?',
    a: 'Yes. Tag 2 (Deposit) requires zero user spend keys and zero ZK proofs from the depositor. Any wallet, treasury desk, or regulated payment gateway derives a fresh one-time stealth pubkey from the recipient’s public Audren address and calls Deposit; the on-chain program computes G_mint and V = net_received * G_mint directly.',
  },
  {
    id: 'single-tx',
    category: 'crypto',
    catLabel: 'Proofs & scanning',
    q: 'How do Triptych + Bulletproof proofs fit in a single Solana transaction?',
    a: 'Audren uses Solana Transaction Version 1 (SIMD-0385, 0x81 prefix), which expands the transaction size limit to 4,096 bytes and carries compute-unit limits and priority fees inline inside the v1 header without separate ComputeBudget instructions. Deposit (~300 B), Transfer (m=5/6, ~2.4 KiB), Withdraw (~2.1 KiB), and SwapViaRouter (full ~2.3 KiB, or partial with shielded change ~3.2 KiB) all settle directly in ONE Solana v1 transaction. For oversized payloads exceeding 4,096 bytes (such as complex multi-hop swaps or large rings), Tag 8 (WriteProofBuffer) and Tag 9 (ExecBuffered) upload chunks and atomically refund 100% of buffer rent back to the payer.',
  },
  {
    id: 'scanning',
    category: 'crypto',
    catLabel: 'Proofs & scanning',
    q: 'How do wallets discover incoming notes and check spend status?',
    a: 'Shielded notes live inside fixed 6,240-byte EpochPage PDAs (32 notes/page) laid out in Structure-of-Arrays order. Wallets call standard Solana RPC getMultipleAccounts or programSubscribe WebSocket with dataSlice: { offset: 64, length: 1056 } to fetch view_tags[32] and ephemeral_pks[32] across 100 pages (3,200 notes) in ~106 KB. View tags reject 255/256 non-owned notes in one byte, and spent status is checked directly via 0-byte NullifierPDA account existence.',
  },
  {
    id: 'scaling',
    category: 'crypto',
    catLabel: 'Proofs & scanning',
    q: 'How does Audren scale write throughput and wallet scanning as pages grow?',
    a: 'Up to 16 append lanes reduce contention on the append state; lanes 1..15 keep PoolState read-only. They still share custody vaults and nullifier state, so this is not lock-free execution or unlimited throughput. Sealed pages are not modified by the current instructions and support caching. Wallets scan compact slices and can use local checkpoints or encrypted backups; restore cost still depends on the history scanned.',
  },
  {
    id: 'auditor',
    category: 'custody',
    catLabel: 'Custody, fees & audits',
    q: 'Can an institutional auditor freeze or move funds in InstitutionalAudited pools?',
    a: 'No. The auditor holds only a read-only decryption scalar k_aud matching PoolState::auditor_pk. Every spend in an audited pool proves valid ElGamal encryption of the spent stealth pubkey P_l under K_aud inside Triptych Equations 6–7, and hidden-asset spends (Transfer and Merge) additionally verify AuditorAssetProof encrypting G_mint (whereas SwapViaRouter and Withdraw expose their mints as public accounts) — giving verifiable provenance with zero custody or spend authority.',
  },
  {
    id: 'pause-fees',
    category: 'custody',
    catLabel: 'Custody, fees & audits',
    q: 'Can the pool authority block withdrawals, is upgrade authority frozen, and what are the fees?',
    a: 'Full-note withdrawals with has_change = false bypass the pool pause in the current program; partial withdrawals remain pause-gated. A valid proof, unspent note, fees, sufficient vault assets, a functioning network and token transfer permissions are still required. The deployment is pre-audit and upgradeable; an upgrade can change these rules, so do not treat the program as immutable. The program charges no protocol service fee — transactions pay Solana network fees, applicable account rent (including permanent 0-byte nullifier PDAs and any new ATAs), and any selected relayer or DEX fees; temporary ProofBuffer rent is refunded on execution or closure.',
  },
]

export function FaqExperience() {
  const [cat, setCat] = useState<CategoryId>('all')
  const [openIds, setOpenIds] = useState<Set<string>>(() => new Set(['boundaries', 'tvl', 'solvency']))

  const visible = cat === 'all' ? FAQS : FAQS.filter((f) => f.category === cat)
  const allOpen = visible.every((f) => openIds.has(f.id))

  const toggle = (id: string) => {
    setOpenIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const toggleAll = () => {
    if (allOpen) {
      setOpenIds(new Set())
    } else {
      setOpenIds(new Set(visible.map((f) => f.id)))
    }
  }

  return (
    <div className={`page-shell ${styles.page}`}>
      <SiteHeader current="faq" />

      <main>
        {/* HERO */}
        <section className={`container ${styles.hero}`}>
          <Link href="/" className={styles.backLink}>
            <ArrowLeft size={12} /> audren.xyz
          </Link>
          <div className={styles.heroSingle}>
            <h1>Frequently Asked Questions</h1>
            <p className={styles.heroLead}>
              Direct engineering answers on privacy boundaries, cryptography, Solana v1 execution,
              router isolation, and audit status.
            </p>
          </div>

          {/* 3-card instant-answer strip */}
          <div className={styles.heroMetaStrip}>
            <div className={styles.heroMetaCell}>
              <span>TVL &amp; ring capacity</span>
              <strong>More TVL alone does not establish more privacy</strong>
            </div>
            <div className={styles.heroMetaCell}>
              <span>Public vault balances</span>
              <strong>Visible assets do not independently prove all liabilities</strong>
            </div>
            <div className={styles.heroMetaCell}>
              <span>Relayers &amp; custody</span>
              <strong>Optional, permissionless, zero user spend keys</strong>
            </div>
            <div className={styles.heroMetaCell}>
              <span>Audit status</span>
              <strong>Apache-2.0 · Pre-audit &amp; upgradeable</strong>
            </div>
          </div>
        </section>

        {/* FILTERABLE ACCORDION */}
        <section className={`container ${styles.section}`}>
          <div className={styles.faqControls}>
            <div className={styles.tabBar} style={{ marginBottom: 0, flex: 1 }} role="tablist" aria-label="FAQ categories">
              {CATEGORIES.map((c) => (
                <button
                  key={c.id}
                  type="button"
                  role="tab"
                  aria-selected={cat === c.id}
                  onClick={() => setCat(c.id)}
                  className={`${styles.tabBtn} ${cat === c.id ? styles.tabBtnActive : ''}`}
                >
                  {c.label}
                </button>
              ))}
            </div>
            <button type="button" className={styles.faqToggleBtn} onClick={toggleAll}>
              {allOpen ? 'COLLAPSE ALL' : 'EXPAND ALL'}
            </button>
          </div>

          <div className={styles.faqList}>
            {visible.map((item) => {
              const isOpen = openIds.has(item.id)
              return (
                <div key={item.id} className={styles.faqItem}>
                  <button
                    type="button"
                    className={styles.faqQ}
                    aria-expanded={isOpen}
                    onClick={() => toggle(item.id)}
                  >
                    <span>
                      <span className={styles.faqCatTag}>{item.catLabel}</span>
                      {item.q}
                    </span>
                    <ChevronDown
                      size={18}
                      style={{
                        flexShrink: 0,
                        transform: isOpen ? 'rotate(180deg)' : 'none',
                        transition: 'transform 160ms ease',
                        color: '#55574e',
                      }}
                    />
                  </button>
                  {isOpen && <div className={styles.faqA}>{item.a}</div>}
                </div>
              )
            })}
          </div>
        </section>

        {/* CLOSING */}
        <section className={styles.closing}>
          <div className={`container ${styles.closingInner}`}>
            <div>
              <h2>Want the full comparison or byte-level spec?</h2>
              <p>
                Compare Audren side-by-side against other Solana privacy approaches or read the
                cryptographic specification directly.
              </p>
            </div>
            <div className={styles.closingActions}>
              <Link href="/compare" className="btn-paper">
                Compare privacy models
              </Link>
              <Link href="/architecture" className={styles.closingLink}>
                Protocol specification <ArrowRight size={15} />
              </Link>
            </div>
          </div>
        </section>
      </main>

      <SiteFooter current="faq" />
    </div>
  )
}
