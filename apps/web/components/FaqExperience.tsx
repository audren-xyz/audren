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
  { id: 'all', label: 'All questions (12)' },
  { id: 'privacy', label: 'Privacy & global MASP' },
  { id: 'swaps', label: 'DeFi & tokens' },
  { id: 'crypto', label: 'Groth16 & RPC sync' },
  { id: 'custody', label: 'Custody, MPC & audits' },
]

const FAQS: readonly FaqItem[] = [
  {
    id: 'boundaries',
    category: 'privacy',
    catLabel: 'Privacy & global MASP',
    q: 'Are public deposits, withdrawals and optional relayers design choices?',
    a: 'Yes. Deposits expose the funding account, token, amount, and appended leaf. Withdrawals expose the destination, token, and amount; external DeFi CPIs expose the target program, mints, and routed amounts. Audren conceals which historical note(s) in the global 4^20 Multi-Asset Shielded Pool fund a spend. Anyone can run a compatible relayer, or submit directly via any Solana RPC.',
  },
  {
    id: 'tvl',
    category: 'privacy',
    catLabel: 'Privacy & global MASP',
    q: 'Does a global Merkle tree or high TVL guarantee absolute anonymity?',
    a: 'No. Proving membership over the entire historical 4^20 global pool eliminates small ring-selection leaks, but timing correlation, public entry/exit amounts, IP/RPC metadata, and input-count selection (padded 2-nullifier mode vs economic 1-nullifier omit_nf1 mode) still narrow practical anonymity. More independent, plausible pool activity helps; raw TVL alone does not establish anonymity.',
  },
  {
    id: 'solvency',
    category: 'custody',
    catLabel: 'Custody, MPC & audits',
    q: 'Do public vault balances prove solvency?',
    a: 'No. Inspectable SOL and SPL vault accounts show held assets, not all private liabilities. The 17,861-R1CS Groth16 conservation/range constraints and net-receipt accounting enforce on-chain accounting rules under the circuit and implementation assumptions, but are not a substitute for independent review and a public Phase-2 MPC ceremony.',
  },
  {
    id: 'solscan',
    category: 'privacy',
    catLabel: 'Privacy & global MASP',
    q: 'What appears on Solscan for a private JoinSplit transfer versus a deposit or exit?',
    a: 'A private JoinSplit (Tag 6, ASSET_MODE_PRIVATE) reveals only the checkpoint root, output append lane, 1–2 nullifiers, opaque 32 B commitments, 90 B encrypted memos, and the fee payer (relayer). Sender identity, recipient stealth owner, token mint, and amount remain hidden. Deposits, public withdrawals, and external DeFi CPIs expose their public boundary mints and amounts.',
  },
  {
    id: 'dex',
    category: 'swaps',
    catLabel: 'DeFi & tokens',
    q: 'What Solana DeFi protocols work with ExecViaEscrow (Tag 7)?',
    a: 'ExecViaEscrow is protocol-agnostic: any compatible PDA-signing Token A → Token B Solana CPI — DEX aggregators/AMMs (Jupiter, Titan, DFlow, OKX DEX, Raydium, Orca, Meteora), lending reserve deposits (kUSDC/kSOL), yield vaults, liquid staking (JitoSOL, INF), perp LP (JLP), or permissionless RWA mint/redeem — executes atomically through 16 sharded escrow PDAs (~158k CU, leaving >1.2M CU for DeFi). It binds router_program and every router account in ctx_hash, enforces pre/post WatchedEscrowBuf owner/delegate/lamport checks, supports EXEC_FLAG_FEE_ON_OUTPUT, and commits the exact measured net vault delta.',
  },
  {
    id: 'defi-sessions',
    category: 'swaps',
    catLabel: 'DeFi & tokens',
    q: 'How do self-paying WSOL unwrap and deterministic Private DeFi Sessions work?',
    a: 'For stateful DeFi protocols requiring a persistent user account (borrowing, perp margin, CLMM LP), SDKs derive deterministic Ed25519 session keypairs (B_0, B_1…) via HKDF-SHA256("audren/v2/defi_session"). You fund a 0-SOL session wallet in one relayed Tag 6 JoinSplit using WITHDRAW_FLAG_UNWRAP_WSOL (unwrapping WSOL atomically into Native SOL via audren_v2_unwrap PDA, pause-immune on full exit), and sweep every remaining lamport back with Tag 3 DepositSol(DEPOSIT_FLAG_FEE_FROM_AMOUNT) leaving zero dust. Important: all positions and transactions executed by B_i on external DeFi protocols remain public on Solana.',
  },
  {
    id: 'tokens',
    category: 'swaps',
    catLabel: 'DeFi & tokens',
    q: 'Which tokens and Token-2022 extensions does Audren support?',
    a: 'Native SOL, Classic SPL, and transferable Token-2022 mints all share the single global 4^20 MASP with no Audren wrapper token. Deposits and ExecViaEscrow measure exact net vault balance deltas (safe for TransferFeeConfig), and trailing TransferHook accounts are sanitized before CPI. Issuer controls (freeze authority, permanent delegate, hook policies) still apply.',
  },
  {
    id: 'single-tx',
    category: 'crypto',
    catLabel: 'Groth16 & RPC sync',
    q: 'Why does every Audren instruction fit in a single Solana Transaction v1?',
    a: 'A compressed BN254 Groth16 proof is only 192 bytes (verified via Solana native alt_bn128 pairing syscalls in ~103k–160k CU). Together with Solana Transaction v1 (SIMD-0385, 0x81, 4,096 B limit and inline compute budget), every instruction — including JoinSplit and complex multi-hop ExecViaEscrow CPIs — settles atomically in one transaction without multi-step proof uploads.',
  },
  {
    id: 'scanning',
    category: 'crypto',
    catLabel: 'Groth16 & RPC sync',
    q: 'How do wallets sync and build Merkle proofs with zero mandatory indexer?',
    a: 'CompactWalletStore fetches sequential SubtreePage (8,256 B), MemoPage (10,144 B, 112 × 90 B SoA entries), and NullifierPage (9,664 B, 600 × 16 B prefixes) PDAs via ordinary Solana RPC getMultipleAccounts. A 2-byte view tag skips 65,535/65,536 stranger notes instantly, every decrypted memo is verified against SubtreePage to block forged memos, sealed pages freeze 12 intra-subtree siblings and are discarded permanently (1.28 MB local store at 10M pool notes), and Merkle proofs are built 100% offline with zero targeted per-note RPC queries.',
  },
  {
    id: 'scaling',
    category: 'crypto',
    catLabel: 'Groth16 & RPC sync',
    q: 'How do 4 → 8 → 16 append lanes scale throughput without changing the circuit?',
    a: 'The frozen 4-ary Depth-20 circuit permanently reserves 16 lane slots (2 top super-root levels over 16 Depth-18 lane trees). Pools launch with 4 active lanes (~48M CU/slot aggregate lane ceiling) and expand monotonically to 8 or 16 lanes via InitLane with zero circuit changes, zero ceremony re-runs, and zero migration of existing notes.',
  },
  {
    id: 'compliance',
    category: 'custody',
    catLabel: 'Custody, MPC & audits',
    q: 'How do Mode 1 Selective Disclosure and Mode 2 Full Viewing Keys work?',
    a: 'Mode 1 SelectiveDisclosureProof exports (stealth_owner, mint, amount, blinding) for a single chosen note and verifies in 1 Poseidon5 hash directly against SubtreePage while revealing zero keys. Mode 2 FullViewingKey (spend_pk, nk, view_sk, view_pk) uses key separation (nk = Poseidon2(10, spend_sk)) so watch-only wallets, hardware-signer setups, relayers, and auditors can track both incoming notes AND spent nullifiers with zero spend authority.',
  },
  {
    id: 'pause-mpc',
    category: 'custody',
    catLabel: 'Custody, MPC & audits',
    q: 'What is the Groth16 trusted-setup status, pause escape hatch, and audit status?',
    a: 'Development and Devnet builds use DEV_DETERMINISTIC_VK over the frozen 17,861-R1CS circuit. Before Mainnet launch, vk_generated.rs must be replaced by a public Phase-2 MPC ceremony artifact alongside an independent program and circuit audit. Full 100% withdrawals (output_mask == 0, including WSOL unwrap) bypass SetPaused, while the BPF upgrade authority remains mutable during pre-audit releases.',
  },
]

export function FaqExperience() {
  const [cat, setCat] = useState<CategoryId>('all')
  const [openIds, setOpenIds] = useState<Set<string>>(() => new Set(['boundaries', 'tvl', 'scanning']))

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
    if (allOpen) setOpenIds(new Set())
    else setOpenIds(new Set(visible.map((f) => f.id)))
  }

  return (
    <div className={`page-shell ${styles.page}`}>
      <SiteHeader current="faq" />

      <main>
        <section className={`container ${styles.hero}`}>
          <Link href="/" className={styles.backLink}>
            <ArrowLeft size={12} /> audren.xyz
          </Link>
          <div className={styles.heroSingle}>
            <h1>Frequently Asked Questions</h1>
            <p className={styles.heroLead}>
              Direct engineering answers on Audren privacy boundaries, BN254 Groth16 proving,
              zero-indexer ordinary RPC sync, DeFi escrow isolation, and ceremony status.
            </p>
          </div>

          <div className={styles.heroMetaStrip}>
            <div className={styles.heroMetaCell}>
              <span>Global MASP</span>
              <strong>4²⁰ tree · TVL alone does not prove anonymity</strong>
            </div>
            <div className={styles.heroMetaCell}>
              <span>Zero indexer</span>
              <strong>Ordinary Solana RPC · 1.28 MB @ 10M notes</strong>
            </div>
            <div className={styles.heroMetaCell}>
              <span>Relayers &amp; custody</span>
              <strong>Optional, permissionless, zero user spend keys</strong>
            </div>
            <div className={styles.heroMetaCell}>
              <span>Ceremony &amp; audit</span>
              <strong>Apache-2.0 · Pre-audit &amp; MPC pending</strong>
            </div>
          </div>
        </section>

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
