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
    catLabel: 'Privacy',
    q: 'What does Audren hide, and what stays public?',
    a: 'In a private transfer, observers cannot see which notes you spent, who receives, which token, or how much. Some things stay public by design: a deposit shows the depositing wallet, token, and amount; a withdrawal shows the destination, token, and amount; a DeFi call shows the external program, tokens, and routed amounts; and every transaction shows its fee payer and timing. If you pay fees from your own wallet instead of through a relayer, your wallet appears as the fee payer. Audren hides which earlier note in the shared pool funded a spend.',
  },
  {
    id: 'tvl',
    category: 'privacy',
    catLabel: 'Privacy',
    q: 'How large is my anonymity set? Does a big pool or high TVL guarantee anonymity?',
    a: 'No. Your anonymity set is the real notes in the pool that could plausibly be yours, not the tree’s capacity (4^20, about 1.1 trillion leaves) or the pool’s TVL. The pool is young, so that set is small today; the live note count is at audren.xyz/api/pool. Private transfers default to one uniform shape (2 nullifiers, 3 outputs, random append lane) so 1-input and 2-input spends look alike. Opt-in economy mode (omit_nf1) saves rent but shows a 1-input spend, and a transaction holding several merges is recognizable as a consolidation. Timing, public entry and exit amounts, and IP or RPC metadata can still narrow the set. More independent activity helps; TVL alone does not.',
  },
  {
    id: 'solscan',
    category: 'privacy',
    catLabel: 'Privacy',
    q: 'What appears on Solscan for a private transfer?',
    a: 'A default private Transact (Tag 5) shows the GlobalRootHistory ring index it proves against, a randomly chosen append lane, 2 nullifiers, 3 opaque 32-byte commitments, 3 encrypted 106-byte memos, the 192-byte proof, and the fee payer. The sender, recipient, token, and amount are not shown. The relayer you use is not blind: it sees your IP address and transaction metadata, and on a fee-charging relayer the fee quote names the token (never the transfer amount) while checking any fee note owed to it. On the hosted sponsored relayer (which has no shielded FVK configured), private transfers skip /v1/fee-quote so even the token mint is not sent.',
  },
  {
    id: 'relayer-down',
    category: 'privacy',
    catLabel: 'Privacy',
    q: 'What if the relayer is down or out of funds?',
    a: 'Relayers are optional and replaceable. You can point the wallet at any compatible relay, self-host the open-source relay in apps/relay, or submit with your own wallet as fee payer (Direct Self-Pay), which publicly shows your wallet as the fee payer. GlobalRootHistory updates inline on every deposit and spend, and wallets auto-prepend idempotent OpenPage instructions on Direct Self-Pay, so zero external cranks are required. Direct wallet transactions use Solana’s smaller v0 format (1,232 B), so very large swap routes or merge batches may need a relay, which submits Transaction v1 (4,096 B).',
  },
  {
    id: 'authority',
    category: 'custody',
    catLabel: 'Custody, setup & audits',
    q: 'What can the pool authority and the upgrade authority do?',
    a: 'Today both roles are held by one operator key (3WzAUV…67bV; full address on the Terms page), not a multisig. Neither authority can spend your notes under the deployed program. The pool authority can pause the pool, which blocks deposits, private transfers, partial withdrawals, and ExecViaEscrow; full withdrawals (output_mask == 0, read-only GlobalRootHistory, including WSOL unwrap; the app drops its padding note while paused) and page openings keep working. Because GlobalRootHistory updates inline with zero idle wall-clock expiry and root_epoch_interval is immutable after initialization, no authority can delay or block full exits. The authority can update on-chain rent-fee charge caps within fixed bounds (the program still caps actual charges at deterministic SysvarRent), activate lanes, transfer authority in two steps, or renounce it (only while unpaused). The program upgrade authority is stronger: it can replace the program code, including its custody logic. It stays mutable during pre-audit releases; any decision to revoke it will be announced separately. You can check the deployed build hash on the Terms page.',
  },
  {
    id: 'pause-mpc',
    category: 'custody',
    catLabel: 'Custody, setup & audits',
    q: 'Is Audren audited, and how was the trusted setup run?',
    a: 'Audren has no independent third-party audit yet. Its Groth16 setup has two phases. Phase 1 reuses the Hermez Perpetual Powers of Tau (powersOfTau28_hez_final_15.ptau: 54 public contributions plus a beacon). Phase 2, specific to Audren’s circuit, so far has two contributions generated by the Audren release environment, sealed with a public drand Quicknet and Solana Mainnet beacon (ceremony/transcript.json). A beacon adds no secrecy, so until independent contributors join, Phase-2 soundness relies on Audren having discarded its contribution secrets; a leaked secret would allow forged proofs. Anyone can verify the transcript and contribute (ceremony/README.md); a new contribution produces a new verifying key, which protects the live pool only after a program upgrade adopts it.',
  },
  {
    id: 'signing',
    category: 'custody',
    catLabel: 'Custody, setup & audits',
    q: 'Is it safe to sign the Audren vault message?',
    a: 'Only on audren.xyz or a copy you host yourself. When you unlock with a browser wallet, the signature over the Audren Vault Key Derivation message becomes your Audren key. The message names the cluster and your wallet but not the website, so any site that gets you to sign the same text can derive the same keys and spend your private notes.',
  },
  {
    id: 'recovery',
    category: 'custody',
    catLabel: 'Custody, setup & audits',
    q: 'How do I recover my funds?',
    a: 'Your notes live on-chain; recovering means re-deriving your keys and rescanning. A vault unlocked with a browser wallet is re-derived by signing the same Audren message with the same wallet on the same cluster (Devnet and Mainnet keys differ). A vault created in the browser is recoverable from its encrypted backup file and passphrase (PBKDF2-SHA256 with 600,000 iterations, then AES-256-GCM) or from its 64-hex recovery seed; the seed is never stored in the browser. Wallet-derived keys are SHA-256 of that signature, so they only come back if your wallet signs the same message identically every time: unlock twice and compare your aud1… address before depositing, and export an encrypted backup right after unlocking. Wallet-derived vaults rescan the whole pool; a browser vault rescans from its birthday slot. Download a browser vault’s backup before depositing, because closing the tab without it loses the keys. Rescanning uses ordinary RPC; no server stores your notes or keys.',
  },
  {
    id: 'solvency',
    category: 'custody',
    catLabel: 'Custody, setup & audits',
    q: 'Do public vault balances prove solvency?',
    a: 'No. Anyone can inspect the WSOL and SPL vault accounts, but they show assets held, not every private liability. The circuit’s conservation and range checks and the program’s net-receipt accounting enforce the rules on-chain, but only under the circuit, implementation, and trusted-setup assumptions above, and they are not a substitute for an independent audit.',
  },
  {
    id: 'compliance',
    category: 'custody',
    catLabel: 'Custody, setup & audits',
    q: 'How do receipts (Mode 1) and full viewing keys (Mode 2) work?',
    a: 'A Mode 1 SelectiveDisclosureProof opens one chosen note (token, amount, one-time owner key, blinding, and its position in the pool), and anyone can check it with one Poseidon5 hash against the commitment on-chain, with no keys shared. It proves that payment exists on-chain; it does not prove who holds the note now or that it is unspent, and the sender knows the same opening. A Mode 2 FullViewingKey (spend_pk, nk, view_sk, view_pk) lets a watch-only wallet, auditor, or relayer see every incoming note and spend of that key, past and future, with no ability to spend. It cannot be revoked once shared.',
  },
  {
    id: 'dex',
    category: 'swaps',
    catLabel: 'DeFi & tokens',
    q: 'Which DeFi protocols work with ExecViaEscrow (Tag 6)?',
    a: 'Today the hosted relay quotes swaps through DEX aggregators (Jupiter, DFlow, and OKX), direct self-pay in the app uses Jupiter, and self-hosted relays can also enable Titan or Bedrock. Those aggregators reach AMMs such as Raydium, Orca, and Meteora and can buy LSTs (such as JitoSOL) or JLP. The instruction itself is completely permissionless and protocol-agnostic: any wallet, frontend, or raw client can build Tag 6 ExecViaEscrow directly from the open binary wire spec and Groth16 circuit without needing an Audren SDK (our 4-language SDKs simply make integration easier). Kamino Lending supply/redeem (KLend2g3c…, USDC ⇄ cUSDC with zero-signer refreshReserve) and Kamino Yield Vault deposit/withdraw (KvauGMsp…, Prime USDC shares) are both live and verified on Mainnet via Tag 6 and the hosted relay (the reference web demo UI focuses on swaps). The program binds the router program, every router account, the minimum output, and the relayer fee into ctx_hash, checks that the escrow accounts were not altered, and reshields exactly what arrived (~165k–238k CU base / 285k budget, leaving >1.11M CU for the route).',
  },
  {
    id: 'defi-sessions',
    category: 'swaps',
    catLabel: 'DeFi & tokens',
    q: 'How do session wallets work for borrowing or perps?',
    a: 'Protocols that keep a per-user account (borrowing, perp margin, concentrated LP) need a persistent signer, so the SDKs derive deterministic session wallets (B_0, B_1…) from your seed via HKDF-SHA256("audren/v1/defi_session"). You fund a 0-SOL session wallet with one relayed withdrawal that unwraps WSOL to SOL atomically (WITHDRAW_FLAG_UNWRAP_WSOL), use it in public, then sweep the rest back with a Deposit (DEPOSIT_FLAG_NATIVE_SOL | DEPOSIT_FLAG_FEE_FROM_AMOUNT) that leaves no dust. These wallets are pseudonymous, not private: the funding withdrawal, every position, and the sweep are public and linked through the session wallet, and amounts and timing can tie them back to your pool activity.',
  },
  {
    id: 'tokens',
    category: 'swaps',
    catLabel: 'DeFi & tokens',
    q: 'Which tokens work, and which carry extra risk?',
    a: 'Native SOL (held as WSOL), classic SPL tokens, and transferable Token-2022 tokens share one pool with no Audren wrapper token. Deposits credit the amount the vault actually received, so fee-on-transfer tokens are safe, and transfer-hook accounts are sanitized before any CPI. One caveat matters for every holder: all deposits of a token sit in one shared vault account, and Audren does not block mints whose issuer keeps a freeze authority (USDC has one), a permanent delegate, a pausable mint, or an upgradable transfer hook. If an issuer uses those powers on the vault, every Audren holder of that token is affected at once. Non-transferable tokens cannot move, and fee-on-transfer tokens deliver less than the requested amount on withdrawal.',
  },
  {
    id: 'scanning',
    category: 'crypto',
    catLabel: 'Proofs, sync & costs',
    q: 'How does a wallet find its payments without an indexer?',
    a: 'Your device reads the pool’s pages directly with ordinary Solana RPC getMultipleAccounts. It downloads full 10,240 B MemoPages (96 encrypted memos each), checks each memo’s 2-byte view tag, decrypts only the matches, and re-hashes every decrypted note against the commitment on-chain so a forged memo cannot add balance. It then streams NullifierPages to see which of its notes were spent. In the default strict mode, full pages hide which memo is yours, and on large catch-ups the tree page you need is fetched inside a fixed batch of 16 pages (or every sealed page, while fewer than 16 exist). Local storage stays small (~1.28 MB at 10M notes), but a cold sync from the beginning downloads every memo and nullifier page; a birthday slot skips pages older than your wallet. Opt-in fast mode reads only the first 3,328 B of each page on catch-ups over 25 pages, at the cost of revealing which pages matched to the RPC. In the web app, those RPC requests pass through the audren.xyz worker.',
  },
  {
    id: 'spendability-rent',
    category: 'crypto',
    catLabel: 'Proofs, sync & costs',
    q: 'When does a new note become spendable, and what does each spend cost in rent?',
    a: 'Immediately upon confirmation (~150ms Alpenglow finality), with zero external root-update wait, zero cranks, and zero crank fees. Every note-appending Deposit, Transact, and ExecViaEscrow updates the pool’s inline GlobalRootHistory (AUD1RT01, 10,216 B PDA) in the same instruction. Its dual ring holds a 128-entry recent slot_ring (retaining 64–128 active slots / ~13.8s–27.5s under saturation, since same_slot_bumped allows up to two advances per slot) for instant spends plus an 89-entry stable epoch_ring (2,848 active slots, ~9.5–10.5 min estimated at ~200–215 ms slots under saturation) with zero idle wall-clock expiry. Clients read GlobalRootHistory at finalized commitment first (falling back to confirmed only for brand-new notes), while page scanning uses confirmed commitment. Each spend also pays permanent rent: 0-byte NullifierPDAs plus amortized page rent (auto-prepended idempotent OpenPage draws from LaneRentVault), roughly 0.0007 SOL for a 1-nullifier full exit up to about 0.0036 SOL for a default 2-nullifier, 3-output transfer at current Mainnet rent. The program reads SysvarRent live, so the cost follows Solana’s rent.',
  },
  {
    id: 'costs',
    category: 'crypto',
    catLabel: 'Proofs, sync & costs',
    q: 'What does using Audren cost?',
    a: 'The protocol charges no fee of its own. Every transaction pays Solana’s network fee, and every spend pays permanent rent for its nullifier and note accounts (see the rent answer above); a native SOL deposit with DEPOSIT_FLAG_FEE_FROM_AMOUNT must exceed the per-note rent fee of about 0.0007 SOL (standard deposits without that flag pay note rent from the depositor’s SOL balance alongside any amount). Relays set their own prices and the wallet shows the quote before you sign. The hosted relay’s current policy is published at relay.audren.xyz/v1/info: private transfers are sponsored with no fee, limited to 4 per hour and 8 per day per IP on Mainnet with a 12s cooldown within a 0.05 SOL daily sponsorship budget; self-paying swaps and relayed withdrawals carry a relay fee starting at 0.25% and rising to cover the relay’s rent and gas (capped at 4.5%), small subsidized micro-swaps carry a 0.50% fee under sponsor rate limits, and small withdrawals may be sponsored instead. Aggregator routes add their own price impact.',
  },
  {
    id: 'single-tx',
    category: 'crypto',
    catLabel: 'Proofs, sync & costs',
    q: 'Does every Audren action fit in one transaction?',
    a: 'Audren uses one frozen 17,861-constraint circuit (3.93 MB proving key) that produces a 192-byte BN254 Groth16 proof on your device, in a browser Web Worker or a native SDK. Solana verifies it with its native alt_bn128 syscalls in ~116k–121k CU (full exit with read-only roots, zero global write-lock contention across 100M CU blocks, 165k budget), ~145k–217k CU (withdraw, 255k budget), or ~205k CU (2-in/3-out private transfer with inline root update, 235k budget). Inside Solana’s 100M CU blocks (where the per-writable-account lock ceiling on GlobalRootHistory remains 12M CU/slot), a single pool sustains ~51–58 private transfers/slot (~237–270 TPS at ~215ms Alpenglow slots) or ~160–222 deposits/slot (~744–1,033 TPS at ~215ms Alpenglow slots), while 0-output full exits lock GlobalRootHistory read-only. Through a relayer, which submits Solana Transaction v1 (4,096 B with inline compute budget), every instruction settles in one transaction with no multi-step proof upload, including multi-hop ExecViaEscrow routes and up to 4 parallel 2 → 1 merges across distinct lanes on relayers configured with a read-only FVK for shielded cm2 fee verification (sponsored relayers without an FVK advertise maxBatchSize = 1). Direct wallet submission uses v0 (1,232 B), where padded 2-nullifier or multi-hop swap routes and merge batches need a relay.',
  },
  {
    id: 'scaling',
    category: 'crypto',
    catLabel: 'Proofs, sync & costs',
    q: 'How do append lanes scale capacity and rollovers without changing the circuit?',
    a: 'The frozen 4-ary depth-20 tree reserves 16 lane slots: two top levels over 16 depth-18 lane trees. Every note-appending write (Deposit, Transact with outputs, and ExecViaEscrow) write-locks the single GlobalRootHistory PDA (accounts[2]) for instant inline root updates, so single-pool write throughput follows Solana’s 12M CU/slot per-account ceiling inside 100M CU blocks (~51–58 private transfers/slot or ~237–270 TPS; ~160–222 deposits/slot or ~744–1,033 TPS at ~215ms Alpenglow slots). Pools launch with 4 active lanes and expand monotonically to 8 or 16 via InitLane with no circuit change, no new ceremony, and no migration of existing notes: more lanes scale global tree capacity to 4^20 (1.099T notes), isolate per-lane page rollovers (enabling 4-merge Tx v1 batches across distinct lanes), and parallelize read-only Full Exits (output_mask == 0, which lock GlobalRootHistory read-only across 100M CU blocks). Nullifiers are pool-wide, so a note cannot be spent twice through different lanes.',
  },
]

const CATEGORIES: { id: CategoryId; label: string }[] = [
  { id: 'all', label: `All questions (${FAQS.length})` },
  { id: 'privacy', label: 'Privacy' },
  { id: 'custody', label: 'Custody, setup & audits' },
  { id: 'swaps', label: 'DeFi & tokens' },
  { id: 'crypto', label: 'Proofs, sync & costs' },
]

export function FaqExperience() {
  const [cat, setCat] = useState<CategoryId>('all')
  const [openIds, setOpenIds] = useState<Set<string>>(() => new Set(['boundaries', 'tvl', 'pause-mpc']))

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
              Straight answers on what Audren hides and what it does not, how proofs and wallet sync
              work, DeFi through the escrow, recovery, authorities, and audit status.
            </p>
          </div>

          <div className={styles.heroMetaStrip}>
            <div className={styles.heroMetaCell}>
              <span className={styles.heroMetaLabel}>Anonymity set</span>
              <span className={styles.heroMetaValue}>Real pool notes, not 4²⁰ capacity or TVL</span>
            </div>
            <div className={styles.heroMetaCell}>
              <span className={styles.heroMetaLabel}>Zero indexer</span>
              <span className={styles.heroMetaValue}>Ordinary Solana RPC · ~1.28 MB kept @ 10M notes</span>
            </div>
            <div className={styles.heroMetaCell}>
              <span className={styles.heroMetaLabel}>Zero-crank &amp; instant</span>
              <span className={styles.heroMetaValue}>~150ms Alpenglow finality · Inline GlobalRootHistory · Auto-OpenPage</span>
            </div>
            <div className={styles.heroMetaCell}>
              <span className={styles.heroMetaLabel}>Ceremony &amp; audit</span>
              <span className={styles.heroMetaValue}>Apache-2.0 · Phase 2 Audren-only so far · No audit yet</span>
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
                    aria-controls={`faq-a-${item.id}`}
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
                        transition: 'transform 280ms cubic-bezier(0.22, 1, 0.36, 1)',
                        color: '#696b61',
                      }}
                    />
                  </button>
                  <div
                    id={`faq-a-${item.id}`}
                    className={styles.faqPanel}
                    data-open={isOpen ? 'true' : 'false'}
                    inert={!isOpen}
                  >
                    <div className={styles.faqPanelInner}>
                      <div className={styles.faqA}>{item.a}</div>
                    </div>
                  </div>
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
