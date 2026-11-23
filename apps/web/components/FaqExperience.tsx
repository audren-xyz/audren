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
    a: 'No. Proving membership over the entire historical 4^20 global pool eliminates small ring-selection leaks, and private transfers default to a uniform padded shape (2 nullifiers, 3 encrypted outputs with output_mask = 0b111, randomized append lane, automatic 2-input coin selection, and up to 4 parallel 2 → 1 private Transact merges per Solana Transaction v1), with an opt-in omit_nf1 economy mode that saves rent while exposing 1-input arity. Timing correlation, public entry/exit amounts, and IP/RPC metadata still narrow practical anonymity. More independent, plausible pool activity helps; raw TVL alone does not establish anonymity.',
  },
  {
    id: 'solvency',
    category: 'custody',
    catLabel: 'Custody, MPC & audits',
    q: 'Do public vault balances prove solvency?',
    a: 'No. Inspectable WSOL and SPL vault accounts show held assets, not all private liabilities. The 17,861-R1CS Groth16 conservation/range constraints and net-receipt accounting enforce on-chain accounting rules under the circuit and implementation assumptions, but are not a substitute for an independent third-party audit and broader community Phase-2 ceremony contributions.',
  },
  {
    id: 'solscan',
    category: 'privacy',
    catLabel: 'Privacy & global MASP',
    q: 'What appears on Solscan for a private Transact transfer versus a deposit or exit?',
    a: 'A default private Transact (Tag 5, ASSET_MODE_PRIVATE) emits a uniform padded footprint: checkpoint root, randomized output append lane, 2 nullifiers, 3 opaque 32 B commitments, 3 × 106 B encrypted SoA memos (72 B ChaCha20-Poly1305 AEAD ciphertexts), and the fee payer (relayer, which quotes flat per-mint fees without seeing transfer amounts). Opt-in omit_nf1 mode uses 1 nullifier on single-input spends to reduce rent. Sender identity, recipient stealth owner, token mint, and amount remain hidden. Deposits, public withdrawals, and external DeFi CPIs expose their public boundary mints and amounts.',
  },
  {
    id: 'dex',
    category: 'swaps',
    catLabel: 'DeFi & tokens',
    q: 'What Solana DeFi protocols work with ExecViaEscrow (Tag 6)?',
    a: 'ExecViaEscrow is protocol-agnostic across SPL and Token-2022. Any compatible PDA-signing Token A → Token B Solana CPI, including DEX aggregators and AMMs (Jupiter, Titan, DFlow, OKX DEX, Raydium, Orca, Meteora), lending reserve deposits (kUSDC/kSOL), yield vaults, liquid staking (JitoSOL, INF), perp LP (JLP), or permissionless RWA mint/redeem, executes atomically through a randomly selected shard across 16 sharded audren_escrow PDAs (~158k CU, leaving >1.2M CU for DeFi). It binds router_program and every router account in ctx_hash, enforces pre/post WatchedEscrowBuf owner/delegate/lamport checks, supports EXEC_FLAG_FEE_ON_OUTPUT, and commits the exact measured net vault delta.',
  },
  {
    id: 'defi-sessions',
    category: 'swaps',
    catLabel: 'DeFi & tokens',
    q: 'How do self-paying WSOL unwrap and deterministic Private DeFi Sessions work?',
    a: 'For stateful DeFi protocols requiring a persistent user account (borrowing, perp margin, CLMM LP), SDKs derive deterministic Ed25519 session keypairs (B_0, B_1…) via HKDF-SHA256("audren/v1/defi_session"). You fund a 0-SOL session wallet in one relayed Tag 5 Transact using WITHDRAW_FLAG_UNWRAP_WSOL (unwrapping WSOL atomically into Native SOL via audren_unwrap PDA, pause-immune on full exit), and sweep every remaining lamport back with unified Tag 3 Deposit (DEPOSIT_FLAG_NATIVE_SOL | DEPOSIT_FLAG_FEE_FROM_AMOUNT) leaving zero dust. Important: all positions and transactions executed by B_i on external DeFi protocols remain public on Solana.',
  },
  {
    id: 'tokens',
    category: 'swaps',
    catLabel: 'DeFi & tokens',
    q: 'Which tokens and Token-2022 extensions does Audren support?',
    a: 'Native SOL, Classic SPL, and transferable Token-2022 mints all share the single global 4^20 MASP with no Audren wrapper token. Native SOL wraps atomically via SyncNative on Deposit into the canonical WSOL vault ATA and unwraps atomically on Transact (WITHDRAW_FLAG_UNWRAP_WSOL), giving SOL the exact same unified SPL custody model as USDC and Token-2022. Deposits and ExecViaEscrow measure exact net vault balance deltas (safe for TransferFeeConfig), and trailing TransferHook accounts are sanitized before CPI. Issuer controls (freeze authority, permanent delegate, hook policies) still apply.',
  },
  {
    id: 'single-tx',
    category: 'crypto',
    catLabel: 'Groth16 & RPC sync',
    q: 'Why does every Audren instruction fit in a single Solana Transaction v1?',
    a: 'One frozen 17,861-R1CS circuit (3.93 MB compressed proving key) produces a 192-byte compressed BN254 Groth16 proof generated locally in a dedicated browser Web Worker or native mobile SDK and verified on-chain via Solana native alt_bn128 pairing syscalls in ~103k–160k CU. Together with Solana Transaction v1 (SIMD-0385, 0x81, 4,096 B limit and inline compute budget), every instruction, including Transact (with up to 4 parallel 2 → 1 private merges per transaction) and complex multi-hop ExecViaEscrow CPIs, settles atomically in one transaction without multi-step proof uploads.',
  },
  {
    id: 'scanning',
    category: 'crypto',
    catLabel: 'Groth16 & RPC sync',
    q: 'How do wallets sync and build Merkle proofs with zero mandatory indexer?',
    a: 'CompactWalletStore runs a 2-pass sync over ordinary Solana RPC getMultipleAccounts with zero mandatory indexer or Forester. In default strict privacy mode, Pass 1 reads SubtreeRootPage (9,664 B, 300 finalized subtree roots = 126 KB per 1M notes), fetches full 10,240 B MemoPages (96 notes/page) in uniform batches (with uniform newly-synced SubtreePage fetches on incremental syncs of 25 pages or fewer, and deterministic wallet-keyed decoy-padded SubtreePage batches on larger catch-up and witness reconstruction), and verifies commitments to freeze 12 intra-subtree siblings without letting the RPC learn which page matched. Pass 2 always streams NullifierPages (9,664 B, 600 × 16 B prefixes) unconditionally to lane head without early-exit, matching only the wallet’s own unspent note prefixes and discarding stranger prefixes immediately, keeping local storage bounded at 1.28 MB at 10M pool notes while building Merkle proofs 100% offline. For bandwidth-constrained cold recovery over a self-hosted or trusted RPC, opt-in fast mode enables 3,328 B SoA dataSlice ([0..3,328]) scanning on catch-ups exceeding 25 pages, with the explicit tradeoff that targeted hit re-fetches reveal matched pages to the RPC.',
  },
  {
    id: 'rent-checkpoints',
    category: 'crypto',
    catLabel: 'Groth16 & RPC sync',
    q: 'How fast are checkpoints, and what does NullifierPDA rent cost?',
    a: 'New deposits and notes become spendable after the next RootCheckpoint publication. Because PoolState sets ckpt_interval = 16 slots (~6.4 seconds), the open-source relayer exposes permissionless on-demand POST /v1/checkpoint (plus a 2-minute maintenance crank), so fresh notes checkpoint in ~6.4 seconds without waiting on a slow cron or linking your personal wallet as fee payer. On rent, Audren avoids a permissioned Forester by storing permanent 0-byte NullifierPDAs plus amortized page rent (~0.002–0.0046 SOL/tx depending on 1 vs 2 nullifiers and output count, compared to ~5,000 lamports with Forester-compressed nullifiers); on-chain checks read SysvarRent dynamically, so per-transaction cost scales down automatically if Solana lowers rent.',
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
    a: 'Mode 1 SelectiveDisclosureProof exports (stealth_owner, mint, amount, blinding) for a single chosen note and verifies in 1 Poseidon5 hash directly against SubtreePage while revealing zero keys. Mode 2 FullViewingKey (spend_pk, nk, view_sk, view_pk) uses key separation (nk = Poseidon2(10, spend_sk)) so watch-only wallets, hardware-signer setups, relayers, and auditors can track both incoming notes and spent nullifiers with zero spend authority.',
  },
  {
    id: 'pause-mpc',
    category: 'custody',
    catLabel: 'Custody, MPC & audits',
    q: 'What is the Groth16 trusted-setup status, pause escape hatch, and audit status?',
    a: 'Audren freezes one minimal 17,861-R1CS circuit and anchors vk_id = 0 to the official Hermez/PSE Perpetual Powers of Tau (powersOfTau28_hez_final_15.ptau, 71+ independent public contributors) plus Audren’s verifiable BGM17 Phase-2 ceremony (zeroized OS CSPRNG + live drand Quicknet #34194203 and Solana Mainnet finalized blockhash beacon, published in ceremony/transcript.json). Additional community Phase-2 contributions remain open, full 100% withdrawals (output_mask == 0, including WSOL unwrap) bypass SetPaused, and an independent third-party audit is pending prior to revoking BPF upgrade authority.',
  },
]

const CATEGORIES: { id: CategoryId; label: string }[] = [
  { id: 'all', label: `All questions (${FAQS.length})` },
  { id: 'privacy', label: 'Privacy & global MASP' },
  { id: 'swaps', label: 'DeFi & tokens' },
  { id: 'crypto', label: 'Groth16 & RPC sync' },
  { id: 'custody', label: 'Custody, MPC & audits' },
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
            <ArrowLeft size={13} /> audren.xyz
          </Link>
          <div className={styles.heroSingle}>
            <h1>Frequently asked questions</h1>
            <p className={styles.heroLead}>
              Direct engineering answers on Audren privacy boundaries, BN254 Groth16 proving,
              zero-indexer ordinary RPC sync, DeFi escrow isolation, and ceremony status.
            </p>
          </div>

          <div className={styles.heroMetaStrip}>
            <div className={styles.heroMetaCell}>
              <span className={styles.heroMetaLabel}>Global MASP</span>
              <span className={styles.heroMetaValue}>4²⁰ tree · TVL alone does not prove anonymity</span>
            </div>
            <div className={styles.heroMetaCell}>
              <span className={styles.heroMetaLabel}>Zero indexer</span>
              <span className={styles.heroMetaValue}>Ordinary Solana RPC · 1.28 MB @ 10M notes</span>
            </div>
            <div className={styles.heroMetaCell}>
              <span className={styles.heroMetaLabel}>Relayers &amp; checkpoints</span>
              <span className={styles.heroMetaValue}>Optional, ~6.4s POST /v1/checkpoint, zero spend keys</span>
            </div>
            <div className={styles.heroMetaCell}>
              <span className={styles.heroMetaLabel}>Ceremony &amp; audit</span>
              <span className={styles.heroMetaValue}>Apache-2.0 · PPoT + BGM17 · Pre-audit</span>
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
              {allOpen ? 'Collapse all' : 'Expand all'}
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
                        color: '#696b61',
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
