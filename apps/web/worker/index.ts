import { ed25519 } from '@noble/curves/ed25519.js'
import {
  AUDREN_PROGRAM_ID,
  CHECKPOINT_RING_SLOTS,
  CLASSIC_TOKEN_PROGRAM_ID,
  MEMO_NOTES_PER_PAGE,
  MEMO_PAGE_LEN,
  NATIVE_SOL_MINT_BYTES,
  NUM_ESCROW_SHARDS,
  OPEN_PAGE_KIND_MEMO,
  OPEN_PAGE_KIND_SUBROOT,
  OPEN_PAGE_KIND_SUBTREE,
  SUBROOTS_PER_PAGE,
  SUBROOT_PAGE_LEN,
  SUBTREE_LEAVES,
  SUBTREE_PAGE_LEN,
  TAG_EXEC_VIA_ESCROW,
  TAG_JOINSPLIT,
  TOKEN_2022_PROGRAM_ID,
  audrenInstructionToSolana,
  base58Decode,
  base58Encode,
  buildDepositSolInstruction,
  buildOpenPageInstruction,
  buildPublishCheckpointInstruction,
  compileV1Message,
  computeNoteCommitment,
  decodeLaneHeader,
  decodePoolState,
  decodeRootCheckpoint,
  deriveAssetId,
  deriveAssociatedTokenAddressSync,
  deriveCheckpointPdaSync,
  deriveEscrowPdaSync,
  deriveLanePdaSync,
  deriveMemoPdaSync,
  derivePoolPdaSync,
  deriveSolVaultPdaSync,
  deriveStealthOwner,
  deriveSubrootPdaSync,
  deriveSubtreePdaSync,
  deriveVaultAuthPdaSync,
  encryptNoteMemo,
  frFromBeBytesStrict,
  frToBeBytes,
  fromBase64,
  parseAudrenAddress,
  serializeV1Transaction,
  toBase64,
  toHex,
  type AudrenInstruction,
  type V1Instruction,
} from '../lib/audren-crypto'

interface ServiceBinding {
  fetch(input: Request | URL | string, init?: RequestInit): Promise<Response>
}

interface Env {
  ASSETS: ServiceBinding
  GATEWAY?: ServiceBinding
  GATEWAY_SEARCH?: ServiceBinding
  TOKEN_GATEWAY_ORIGIN?: string
  CANONICAL_HOST?: string
  DEVNET_RPC_URL?: string
  DEVNET_DEMO_SECRET_B64?: string
  MAINNET_RPC_URL?: string
  JUPITER_API_URL?: string
  JUPITER_API_KEY?: string
}

type Cluster = 'mainnet' | 'devnet'

const DEFAULT_GATEWAY_ORIGIN = 'https://gateway.internal'
const MAX_DEMO_DEPOSIT_LAMPORTS = 5_000_000n
const MIN_DEMO_DEPOSIT_LAMPORTS = 100_000n
const RATE_WINDOW_MS = 10 * 60 * 1000
const RATE_MAX_REQUESTS = 8
const RELAY_RATE_MAX = 8

// Kept byte-for-byte in sync with crates/client/src/router.rs,
// packages/sdk/src/swap.ts, and apps/relay/src/aggregators/jupiter.ts.
const JUPITER_CPI_EXCLUDED_DEXES = [
  'Kipseli',
  'Quantum',
  'BisonFi',
  'BisonFi Predict',
  'BinaryFi',
  'Obsidian',
  'VaultLiquidUnstake',
  'Sanctum Prop S',
]

const SHA256_RE = /^[0-9a-f]{64}$/
const MINT_ICON_CACHE = new Map<string, { iconUrl: string; symbol: string }>()
const RATE_BUCKETS = new Map<string, { count: number; resetAt: number }>()

const POPULAR_TOKEN_MINTS = [
  'So11111111111111111111111111111111111111112',
  'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
  'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB',
  'JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN',
  '2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo',
  'J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn',
  'DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263',
  'EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm',
  '4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R',
  'cbbtcf3aa214zXHbiAZQwf4122FBYbraNdFqgw4iMij',
]

interface GatewayTokenCard {
  mint: string
  symbol: string | null
  name: string | null
  decimals: number | null
  logo: string | null
  tokenProgram: 'spl-token' | 'token-2022' | null
  trust?: { tier: number | null; flags?: string[] | null }
  price?: { mid?: number } | null
  liquidityUsd?: number | null
}

interface ResolvedTokenInfo {
  mint: string
  symbol: string
  name: string
  decimals: number | null
  tokenProgram: string
  logoUrl: string | null
  priceUsd: number | null
  liquidityUsd: number | null
  verified: boolean
  flagged: boolean
}

interface JupiterTokenV2 {
  id: string
  name?: string | null
  symbol?: string | null
  icon?: string | null
  decimals?: number | null
  tokenProgram?: string | null
  usdPrice?: number | null
  liquidity?: number | null
  isVerified?: boolean | null
  audit?: { isSus?: boolean | null } | null
}

interface InitializedPoolSnapshot {
  initialized: true
  cluster: Cluster
  protocolVersion: 2
  programId: string
  poolId: number
  poolPda: string
  solVaultPda: string
  vaultAuthPda: string
  solVaultLamports: number
  paused: boolean
  activeLanes: number
  ckptInterval: string
  maxCkptAge: string
  noteRentFee: string
  deterministicNoteRentFee: string
  nfRentFee: string
  currentSlot: string
  totalNotes: string
  totalNullifiers: string
  lanes: Array<{
    laneId: number
    lanePda: string
    nextLeaf: string
    nfCount: string
    currentRootHex: string
  } | null>
  latestCheckpoint: {
    slotIndex: number
    pda: string
    epochId: string
    publishedSlot: string
    superRootHex: string
    laneCounts: string[]
  } | null
}

interface UninitializedPoolSnapshot {
  initialized: false
  cluster: Cluster
  protocolVersion: 2
  programId: string
  poolId: number
  poolPda: string
  solVaultPda: string
  vaultAuthPda: string
  solVaultLamports: number
}

function jsonResponse(body: unknown, status = 200, extraHeaders?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...extraHeaders,
    },
  })
}

function shortMint(mint: string): string {
  return mint.length > 10 ? `${mint.slice(0, 4)}…${mint.slice(-4)}` : mint
}

function isSafeExternalIconUrl(raw: string): boolean {
  try {
    const u = new URL(raw)
    if (u.protocol !== 'https:') return false
    const h = u.hostname.toLowerCase()
    if (h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal')) return false
    if (/^\d+\.\d+\.\d+\.\d+$/.test(h) || h.includes(':')) return false
    return true
  } catch {
    return false
  }
}

function checkRateLimit(ip: string, bucket: string, maxRequests: number): boolean {
  const key = `${bucket}:${ip}`
  const now = Date.now()
  const cur = RATE_BUCKETS.get(key)
  if (!cur || cur.resetAt <= now) {
    RATE_BUCKETS.set(key, { count: 1, resetAt: now + RATE_WINDOW_MS })
    return true
  }
  if (cur.count >= maxRequests) return false
  cur.count += 1
  return true
}

function getClientIp(request: Request): string {
  return request.headers.get('cf-connecting-ip') ?? request.headers.get('x-forwarded-for') ?? 'local'
}

function parseCluster(raw: string | null | undefined): Cluster {
  return raw === 'devnet' ? 'devnet' : 'mainnet'
}

function getRpcUrl(env: Env, cluster: Cluster): string {
  const url = cluster === 'devnet' ? env.DEVNET_RPC_URL?.trim() : env.MAINNET_RPC_URL?.trim()
  if (!url) {
    throw new Error(
      cluster === 'devnet'
        ? 'DEVNET_RPC_URL secret is not configured on this Worker'
        : 'MAINNET_RPC_URL secret is not configured on this Worker',
    )
  }
  return url
}

async function solanaRpc<T>(env: Env, cluster: Cluster, method: string, params: unknown[]): Promise<T> {
  const res = await fetch(getRpcUrl(env, cluster), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  })
  if (!res.ok) throw new Error(`Solana RPC ${method} HTTP ${res.status}`)
  const json = (await res.json()) as { result?: T; error?: { message?: string } }
  if (json.error) throw new Error(`Solana RPC ${method}: ${json.error.message ?? 'unknown error'}`)
  return json.result as T
}

function decodeDemoKeypair(env: Env): { secretSeed: Uint8Array; pubkeyBytes: Uint8Array; pubkeyStr: string } | null {
  const raw = env.DEVNET_DEMO_SECRET_B64?.trim()
  if (!raw) return null
  const bytes = fromBase64(raw)
  const secretSeed = bytes.byteLength >= 32 ? bytes.subarray(0, 32) : null
  if (!secretSeed) return null
  const pubkeyBytes = ed25519.getPublicKey(secretSeed)
  return { secretSeed, pubkeyBytes, pubkeyStr: base58Encode(pubkeyBytes) }
}

function toV1Ix(ix: AudrenInstruction): V1Instruction {
  const sol = audrenInstructionToSolana(ix)
  return {
    programId: sol.programId,
    accounts: sol.accounts,
    data: sol.data,
  }
}

async function sendAndConfirmV1(
  env: Env,
  cluster: Cluster,
  signer: { secretSeed: Uint8Array; pubkeyBytes: Uint8Array },
  instructions: V1Instruction[],
  computeUnitLimit: number,
): Promise<{ signature: string; slot: number; wireBytes: number }> {
  const bh = await solanaRpc<{ value: { blockhash: string } }>(env, cluster, 'getLatestBlockhash', [
    { commitment: 'confirmed' },
  ])
  const compiled = compileV1Message({
    feePayer: signer.pubkeyBytes,
    recentBlockhash: base58Decode(bh.value.blockhash),
    instructions,
    config: { computeUnitLimit, priorityFeeLamports: 1_000n },
  })
  const sig = ed25519.sign(compiled.messageBytes, signer.secretSeed)
  const wire = serializeV1Transaction(compiled, [sig])
  const txSig = await solanaRpc<string>(env, cluster, 'sendTransaction', [
    toBase64(wire),
    { encoding: 'base64', preflightCommitment: 'confirmed', maxRetries: 3 },
  ])

  let slot = 0
  for (let i = 0; i < 30; i++) {
    await new Promise((r) => setTimeout(r, 800))
    const st = await solanaRpc<{
      value: Array<{ confirmationStatus?: string | null; err?: unknown; slot?: number } | null>
    }>(env, cluster, 'getSignatureStatuses', [[txSig]])
    const cur = st.value[0]
    if (cur?.err) throw new Error(`Transaction failed on-chain: ${JSON.stringify(cur.err)}`)
    if (cur?.confirmationStatus === 'confirmed' || cur?.confirmationStatus === 'finalized') {
      slot = cur.slot ?? 0
      break
    }
  }
  return { signature: txSig, slot, wireBytes: wire.byteLength }
}

async function fetchPoolSnapshot(
  env: Env,
  cluster: Cluster,
  poolId: number,
): Promise<InitializedPoolSnapshot | UninitializedPoolSnapshot> {
  const poolPda = derivePoolPdaSync(poolId, AUDREN_PROGRAM_ID).address
  const solVaultPda = deriveSolVaultPdaSync(poolId, AUDREN_PROGRAM_ID).address
  const vaultAuthPda = deriveVaultAuthPdaSync(poolId, AUDREN_PROGRAM_ID).address

  const head = await solanaRpc<{
    value: Array<{ data: [string, string]; lamports: number } | null>
  }>(env, cluster, 'getMultipleAccounts', [[poolPda, solVaultPda], { encoding: 'base64', commitment: 'confirmed' }])

  const poolAcc = head.value[0]
  if (!poolAcc?.data?.[0]) {
    return {
      initialized: false,
      cluster,
      protocolVersion: 2,
      programId: AUDREN_PROGRAM_ID,
      poolId,
      poolPda,
      solVaultPda,
      vaultAuthPda,
      solVaultLamports: head.value[1]?.lamports ?? 0,
    }
  }

  const pool = decodePoolState(fromBase64(poolAcc.data[0]))
  const [currentSlot, subRent, srRent, memoRent] = await Promise.all([
    solanaRpc<number>(env, cluster, 'getSlot', [{ commitment: 'confirmed' }]),
    solanaRpc<number>(env, cluster, 'getMinimumBalanceForRentExemption', [SUBTREE_PAGE_LEN]),
    solanaRpc<number>(env, cluster, 'getMinimumBalanceForRentExemption', [SUBROOT_PAGE_LEN]),
    solanaRpc<number>(env, cluster, 'getMinimumBalanceForRentExemption', [MEMO_PAGE_LEN]),
  ])
  const divCeil = (a: bigint, b: bigint) => (a + b - 1n) / b
  const livePerNote =
    divCeil(BigInt(subRent), BigInt(SUBTREE_LEAVES)) +
    divCeil(BigInt(srRent), BigInt(SUBTREE_LEAVES * SUBROOTS_PER_PAGE)) +
    divCeil(BigInt(memoRent), BigInt(MEMO_NOTES_PER_PAGE))
  const deterministicNoteRentFee =
    pool.noteRentFee === 0n ? 0n : pool.noteRentFee < livePerNote ? pool.noteRentFee : livePerNote

  const curEpoch = BigInt(currentSlot) / (pool.ckptInterval > 0n ? pool.ckptInterval : 1n)

  const lanePdas: string[] = []
  for (let l = 0; l < pool.activeLanes; l++) {
    lanePdas.push(deriveLanePdaSync(poolId, l, AUDREN_PROGRAM_ID).address)
  }

  // Probe the 80 most recent ring slots in the first batch alongside lanes (<= 96 accounts).
  // If no non-expired checkpoint is found in those 80 slots, scan the remaining ring slots.
  const orderedSlots: number[] = []
  const orderedPdas: string[] = []
  for (let back = 0; back < CHECKPOINT_RING_SLOTS; back++) {
    const ep = curEpoch >= BigInt(back) ? curEpoch - BigInt(back) : 0n
    const slotIdx = Number(ep % BigInt(CHECKPOINT_RING_SLOTS))
    if (!orderedSlots.includes(slotIdx)) {
      orderedSlots.push(slotIdx)
      orderedPdas.push(deriveCheckpointPdaSync(poolId, slotIdx, AUDREN_PROGRAM_ID).address)
    }
  }
  const firstBatchCount = Math.min(orderedPdas.length, 100 - lanePdas.length)
  const firstCkptPdas = orderedPdas.slice(0, firstBatchCount)

  const laneAndCkpt = await solanaRpc<{
    value: Array<{ data: [string, string]; lamports: number } | null>
  }>(env, cluster, 'getMultipleAccounts', [
    [...lanePdas, ...firstCkptPdas],
    { encoding: 'base64', commitment: 'confirmed' },
  ])

  const lanes = lanePdas.map((pda, idx) => {
    const acc = laneAndCkpt.value[idx]
    if (!acc?.data?.[0]) return null
    const hdr = decodeLaneHeader(fromBase64(acc.data[0]))
    return {
      laneId: hdr.laneId,
      lanePda: pda,
      nextLeaf: hdr.nextLeaf.toString(),
      nfCount: hdr.nfCount.toString(),
      currentRootHex: toHex(hdr.currentRoot),
    }
  })

  let latestCheckpoint: InitializedPoolSnapshot['latestCheckpoint'] = null
  let bestSlot = -1n
  const scanCkptAccounts = (pdas: string[], vals: Array<{ data: [string, string] } | null>) => {
    for (let i = 0; i < pdas.length; i++) {
      const acc = vals[i]
      if (!acc?.data?.[0]) continue
      const ck = decodeRootCheckpoint(fromBase64(acc.data[0]))
      if (ck.publishedSlot > bestSlot) {
        bestSlot = ck.publishedSlot
        latestCheckpoint = {
          slotIndex: ck.slotIdx,
          pda: pdas[i]!,
          epochId: ck.epochId.toString(),
          publishedSlot: ck.publishedSlot.toString(),
          superRootHex: toHex(ck.superRoot),
          laneCounts: ck.laneCounts.map((c) => c.toString()),
        }
      }
    }
  }

  scanCkptAccounts(firstCkptPdas, laneAndCkpt.value.slice(lanePdas.length))
  if (!latestCheckpoint && orderedPdas.length > firstBatchCount) {
    const restPdas = orderedPdas.slice(firstBatchCount)
    const chunks: string[][] = []
    for (let off = 0; off < restPdas.length; off += 100) {
      chunks.push(restPdas.slice(off, off + 100))
    }
    const restRes = await Promise.all(
      chunks.map((c) =>
        solanaRpc<{ value: Array<{ data: [string, string] } | null> }>(env, cluster, 'getMultipleAccounts', [
          c,
          { encoding: 'base64', commitment: 'confirmed' },
        ]),
      ),
    )
    for (let ci = 0; ci < chunks.length; ci++) {
      scanCkptAccounts(chunks[ci]!, restRes[ci]!.value)
    }
  }

  const totalNotes = lanes.reduce((acc, l) => acc + BigInt(l?.nextLeaf ?? '0'), 0n)
  const totalNullifiers = lanes.reduce((acc, l) => acc + BigInt(l?.nfCount ?? '0'), 0n)

  return {
    initialized: true,
    cluster,
    protocolVersion: 2,
    programId: AUDREN_PROGRAM_ID,
    poolId,
    poolPda,
    solVaultPda,
    vaultAuthPda,
    solVaultLamports: head.value[1]?.lamports ?? 0,
    paused: pool.paused,
    activeLanes: pool.activeLanes,
    ckptInterval: pool.ckptInterval.toString(),
    maxCkptAge: pool.maxCkptAge.toString(),
    noteRentFee: pool.noteRentFee.toString(),
    deterministicNoteRentFee: deterministicNoteRentFee.toString(),
    nfRentFee: pool.nfRentFee.toString(),
    currentSlot: String(currentSlot),
    totalNotes: totalNotes.toString(),
    totalNullifiers: totalNullifiers.toString(),
    lanes,
    latestCheckpoint,
  }
}

async function handleRpcAccounts(request: Request, env: Env): Promise<Response> {
  const body = (await request.json().catch(() => null)) as {
    cluster?: string
    addresses?: unknown
    commitment?: 'confirmed' | 'finalized'
  } | null
  if (!body || !Array.isArray(body.addresses) || body.addresses.length === 0 || body.addresses.length > 200) {
    return jsonResponse({ error: 'addresses must be a non-empty array of <= 200 Solana pubkeys' }, 400)
  }
  const cluster = parseCluster(body.cluster)
  const commitment = body.commitment === 'finalized' ? 'finalized' : 'confirmed'
  const addresses = body.addresses.map((a) => String(a))
  const out: Array<string | null> = []
  for (let off = 0; off < addresses.length; off += 100) {
    const chunk = addresses.slice(off, off + 100)
    const res = await solanaRpc<{
      value: Array<{ data: [string, string] } | null>
    }>(env, cluster, 'getMultipleAccounts', [chunk, { encoding: 'base64', commitment }])
    for (let i = 0; i < chunk.length; i++) {
      out.push(res.value[i]?.data?.[0] ?? null)
    }
  }
  return jsonResponse({ cluster, accounts: out })
}

async function handleWalletBalances(url: URL, env: Env): Promise<Response> {
  const cluster = parseCluster(url.searchParams.get('cluster'))
  const owner = url.searchParams.get('owner')?.trim()
  if (!owner) return jsonResponse({ error: 'owner query parameter is required' }, 400)
  try {
    base58Decode(owner)
  } catch {
    return jsonResponse({ error: 'Invalid owner Solana pubkey' }, 400)
  }

  const [balRes, splRes, t22Res] = await Promise.all([
    solanaRpc<{ value: number }>(env, cluster, 'getBalance', [owner, { commitment: 'confirmed' }]),
    solanaRpc<{
      value: Array<{
        pubkey: string
        account: { data: { parsed: { info: { mint: string; tokenAmount: { amount: string; decimals: number; uiAmountString: string } } } } }
      }>
    }>(env, cluster, 'getTokenAccountsByOwner', [
      owner,
      { programId: CLASSIC_TOKEN_PROGRAM_ID },
      { encoding: 'jsonParsed', commitment: 'confirmed' },
    ]),
    solanaRpc<{
      value: Array<{
        pubkey: string
        account: { data: { parsed: { info: { mint: string; tokenAmount: { amount: string; decimals: number; uiAmountString: string } } } } }
      }>
    }>(env, cluster, 'getTokenAccountsByOwner', [
      owner,
      { programId: TOKEN_2022_PROGRAM_ID },
      { encoding: 'jsonParsed', commitment: 'confirmed' },
    ]),
  ])

  const tokens = [
    ...splRes.value.map((row) => ({
      ata: row.pubkey,
      mint: row.account.data.parsed.info.mint,
      amount: row.account.data.parsed.info.tokenAmount.amount,
      decimals: row.account.data.parsed.info.tokenAmount.decimals,
      uiAmountString: row.account.data.parsed.info.tokenAmount.uiAmountString,
      tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    })),
    ...t22Res.value.map((row) => ({
      ata: row.pubkey,
      mint: row.account.data.parsed.info.mint,
      amount: row.account.data.parsed.info.tokenAmount.amount,
      decimals: row.account.data.parsed.info.tokenAmount.decimals,
      uiAmountString: row.account.data.parsed.info.tokenAmount.uiAmountString,
      tokenProgram: TOKEN_2022_PROGRAM_ID,
    })),
  ].filter((t) => BigInt(t.amount) > 0n)

  return jsonResponse({
    cluster,
    owner,
    solLamports: String(balRes.value ?? 0),
    tokens,
  })
}

async function handleRpcBlockhash(url: URL, env: Env): Promise<Response> {
  const cluster = parseCluster(url.searchParams.get('cluster'))
  const res = await solanaRpc<{ value: { blockhash: string; lastValidBlockHeight: number } }>(
    env,
    cluster,
    'getLatestBlockhash',
    [{ commitment: 'confirmed' }],
  )
  return jsonResponse({
    cluster,
    blockhash: res.value.blockhash,
    lastValidBlockHeight: String(res.value.lastValidBlockHeight),
  })
}

async function handleRpcSend(request: Request, env: Env): Promise<Response> {
  const body = (await request.json().catch(() => null)) as {
    cluster?: string
    transactionB64?: string
  } | null
  if (!body?.transactionB64) return jsonResponse({ error: 'transactionB64 is required' }, 400)
  const cluster = parseCluster(body.cluster)
  const signature = await solanaRpc<string>(env, cluster, 'sendTransaction', [
    body.transactionB64,
    { encoding: 'base64', preflightCommitment: 'confirmed', maxRetries: 3 },
  ])
  let slot = 0
  for (let i = 0; i < 30; i++) {
    await new Promise((r) => setTimeout(r, 800))
    const st = await solanaRpc<{
      value: Array<{ confirmationStatus?: string | null; err?: unknown; slot?: number } | null>
    }>(env, cluster, 'getSignatureStatuses', [[signature]])
    const cur = st.value[0]
    if (cur?.err) return jsonResponse({ error: `On-chain error: ${JSON.stringify(cur.err)}`, signature }, 400)
    if (cur?.confirmationStatus === 'confirmed' || cur?.confirmationStatus === 'finalized') {
      slot = cur.slot ?? 0
      break
    }
  }
  return jsonResponse({ cluster, signature, slot })
}

async function handleTxInspect(url: URL, env: Env): Promise<Response> {
  const cluster = parseCluster(url.searchParams.get('cluster'))
  const signature = url.searchParams.get('signature')?.trim()
  if (!signature) return jsonResponse({ error: 'signature is required' }, 400)
  const tx = await solanaRpc<{
    slot: number
    blockTime: number | null
    meta: {
      err: unknown
      fee: number
      computeUnitsConsumed?: number
      logMessages?: string[]
    } | null
  } | null>(env, cluster, 'getTransaction', [
    signature,
    { encoding: 'jsonParsed', maxSupportedTransactionVersion: 1, commitment: 'confirmed' },
  ])
  if (!tx) return jsonResponse({ error: 'Transaction not found yet' }, 404)
  return jsonResponse({
    cluster,
    signature,
    slot: tx.slot,
    blockTime: tx.blockTime,
    feeLamports: tx.meta?.fee ?? 0,
    computeUnitsConsumed: tx.meta?.computeUnitsConsumed ?? null,
    err: tx.meta?.err ?? null,
    logs: tx.meta?.logMessages ?? [],
  })
}

function normalizeGatewayCard(mint: string, card: GatewayTokenCard): ResolvedTokenInfo {
  const flagged = Array.isArray(card.trust?.flags) && card.trust!.flags!.length > 0
  const tier = typeof card.trust?.tier === 'number' ? card.trust.tier : null
  const logoSha = !flagged && typeof card.logo === 'string' && SHA256_RE.test(card.logo) ? card.logo : null
  return {
    mint,
    symbol: !flagged && card.symbol?.trim() ? card.symbol.trim() : shortMint(mint),
    name: !flagged && card.name?.trim() ? card.name.trim() : 'Solana Token',
    decimals: typeof card.decimals === 'number' ? card.decimals : null,
    tokenProgram: card.tokenProgram === 'token-2022' ? TOKEN_2022_PROGRAM_ID : CLASSIC_TOKEN_PROGRAM_ID,
    logoUrl: logoSha ? `/api/tokens/logo/${logoSha}.webp` : null,
    priceUsd: typeof card.price?.mid === 'number' && card.price.mid > 0 ? card.price.mid : null,
    liquidityUsd: typeof card.liquidityUsd === 'number' && card.liquidityUsd > 0 ? card.liquidityUsd : null,
    verified: !flagged && tier !== null && tier <= 2,
    flagged,
  }
}

function normalizeJupiterToken(tok: JupiterTokenV2): ResolvedTokenInfo {
  const flagged = tok.audit?.isSus === true
  const symbol = !flagged && tok.symbol?.trim() ? tok.symbol.trim() : shortMint(tok.id)
  const hasIcon = !flagged && typeof tok.icon === 'string' && isSafeExternalIconUrl(tok.icon)
  if (hasIcon && tok.icon) {
    MINT_ICON_CACHE.set(tok.id, { iconUrl: tok.icon, symbol })
  }
  const symParam = encodeURIComponent(symbol.replace(/[^A-Za-z0-9]/g, '').slice(0, 4) || tok.id.slice(0, 2))
  return {
    mint: tok.id,
    symbol,
    name: !flagged && tok.name?.trim() ? tok.name.trim() : 'Solana Token',
    decimals: typeof tok.decimals === 'number' ? tok.decimals : null,
    tokenProgram: tok.tokenProgram === TOKEN_2022_PROGRAM_ID ? TOKEN_2022_PROGRAM_ID : CLASSIC_TOKEN_PROGRAM_ID,
    logoUrl: hasIcon ? `/api/tokens/mint-logo/${tok.id}.webp?s=${symParam}` : null,
    priceUsd: typeof tok.usdPrice === 'number' && tok.usdPrice > 0 ? tok.usdPrice : null,
    liquidityUsd: typeof tok.liquidity === 'number' && tok.liquidity > 0 ? tok.liquidity : null,
    verified: !flagged && tok.isVerified === true,
    flagged,
  }
}

async function fetchJupiterTokens(env: Env, pathAndQuery: string): Promise<JupiterTokenV2[]> {
  if (!env.JUPITER_API_KEY?.trim() && !env.JUPITER_API_URL?.trim()) return []
  const base = (env.JUPITER_API_URL?.trim() || 'https://api.jup.ag').replace(/\/+$/, '').replace(/\/swap\/v1$/, '')
  const headers: Record<string, string> = {
    accept: 'application/json',
    ...(env.JUPITER_API_KEY?.trim() ? { 'x-api-key': env.JUPITER_API_KEY.trim() } : {}),
  }
  try {
    const res = await fetch(`${base}/tokens/v2/${pathAndQuery}`, { headers })
    if (!res.ok) return []
    const data = (await res.json()) as unknown
    return Array.isArray(data) ? (data as JupiterTokenV2[]) : []
  } catch {
    return []
  }
}

async function handleTokensSearch(url: URL, env: Env): Promise<Response> {
  const q = (url.searchParams.get('q') ?? '').trim()
  if (env.GATEWAY_SEARCH) {
    try {
      const origin = env.TOKEN_GATEWAY_ORIGIN?.trim() || DEFAULT_GATEWAY_ORIGIN
      const res = await env.GATEWAY_SEARCH.fetch(`${origin}/search?q=${encodeURIComponent(q)}&limit=12`)
      if (res.ok) {
        const cards = (await res.json()) as GatewayTokenCard[]
        if (Array.isArray(cards) && cards.length > 0) {
          return jsonResponse({ tokens: cards.map((c) => normalizeGatewayCard(c.mint, c)) })
        }
      }
    } catch {
      // fall through to authenticated Jupiter tokens API
    }
  }
  const path = q ? `search?query=${encodeURIComponent(q)}` : `search?query=${encodeURIComponent(POPULAR_TOKEN_MINTS.join(','))}`
  const rows = await fetchJupiterTokens(env, path)
  return jsonResponse({ tokens: rows.slice(0, 15).map(normalizeJupiterToken) })
}

async function handleTokensResolve(request: Request, env: Env): Promise<Response> {
  const body = (await request.json().catch(() => null)) as { mints?: unknown } | null
  const mints = Array.isArray(body?.mints) ? body!.mints.map(String).slice(0, 40) : []
  if (mints.length === 0) return jsonResponse({ tokens: {} })
  const out: Record<string, ResolvedTokenInfo> = {}
  if (env.GATEWAY) {
    try {
      const origin = env.TOKEN_GATEWAY_ORIGIN?.trim() || DEFAULT_GATEWAY_ORIGIN
      const res = await env.GATEWAY.fetch(`${origin}/tokens?mints=${encodeURIComponent(mints.join(','))}`)
      if (res.ok) {
        const map = (await res.json()) as Record<string, GatewayTokenCard>
        for (const [m, card] of Object.entries(map)) out[m] = normalizeGatewayCard(m, card)
      }
    } catch {
      // fall through
    }
  }
  const missing = mints.filter((m) => !out[m])
  if (missing.length > 0) {
    const rows = await fetchJupiterTokens(env, `search?query=${encodeURIComponent(missing.join(','))}`)
    for (const r of rows) out[r.id] = normalizeJupiterToken(r)
  }
  return jsonResponse({ tokens: out })
}

function buildMonogramSvg(symbolHint: string | null | undefined, mint: string): string {
  const clean = (symbolHint ?? '').replace(/[^A-Za-z0-9]/g, '').toUpperCase()
  const label = (clean || mint.slice(0, 2).toUpperCase()).slice(0, 3) || '?'
  const fontSize = label.length >= 3 ? 11 : 13
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40"><rect width="40" height="40" rx="20" fill="#eef1ec"/><rect x="0.75" y="0.75" width="38.5" height="38.5" rx="19.25" fill="none" stroke="#c8d0c6" stroke-width="1.5"/><text x="50%" y="53%" text-anchor="middle" dominant-baseline="middle" font-family="ui-monospace,SFMono-Regular,Menlo,monospace" font-size="${fontSize}" font-weight="700" fill="#18221b">${label}</text></svg>`
}

async function handleJupiterQuote(request: Request, env: Env): Promise<Response> {
  const body = (await request.json().catch(() => null)) as {
    inputMint?: string
    outputMint?: string
    amount?: string
    slippageBps?: number
    maxAccounts?: number
    onlyDirectRoutes?: boolean
  } | null
  if (!body?.inputMint || !body.outputMint || !body.amount) {
    return jsonResponse({ error: 'inputMint, outputMint, and amount are required' }, 400)
  }
  const base = (env.JUPITER_API_URL?.trim() || 'https://api.jup.ag').replace(/\/+$/, '').replace(/\/swap\/v1$/, '')
  const qs = new URLSearchParams({
    inputMint: body.inputMint,
    outputMint: body.outputMint,
    amount: body.amount,
    slippageBps: String(body.slippageBps ?? 100),
    maxAccounts: String(Math.min(28, body.maxAccounts ?? 28)),
    excludeDexes: JUPITER_CPI_EXCLUDED_DEXES.join(','),
    ...(body.onlyDirectRoutes ? { onlyDirectRoutes: 'true' } : {}),
  })
  const headers: Record<string, string> = {
    accept: 'application/json',
    ...(env.JUPITER_API_KEY?.trim() ? { 'x-api-key': env.JUPITER_API_KEY.trim() } : {}),
  }
  const res = await fetch(`${base}/swap/v1/quote?${qs.toString()}`, { headers })
  const data = await res.json().catch(() => ({ error: `Jupiter HTTP ${res.status}` }))
  return jsonResponse(data, res.status)
}

async function handleJupiterSwapInstructions(request: Request, env: Env): Promise<Response> {
  const body = (await request.json().catch(() => null)) as {
    quoteResponse?: unknown
    poolId?: number
    shardId?: number
    inputMint?: string
    outputMint?: string
    tokenProgramIn?: string
    tokenProgramOut?: string
  } | null
  if (!body?.quoteResponse || !body.inputMint || !body.outputMint) {
    return jsonResponse({ error: 'quoteResponse, inputMint, and outputMint are required' }, 400)
  }
  const poolId = body.poolId ?? 0
  const shardId = (body.shardId ?? 0) % NUM_ESCROW_SHARDS
  const escrowPda = deriveEscrowPdaSync(poolId, shardId, AUDREN_PROGRAM_ID).address
  const vaultAuth = deriveVaultAuthPdaSync(poolId, AUDREN_PROGRAM_ID).address
  const tpIn = body.tokenProgramIn ?? CLASSIC_TOKEN_PROGRAM_ID
  const tpOut = body.tokenProgramOut ?? CLASSIC_TOKEN_PROGRAM_ID
  const escrowInAta = deriveAssociatedTokenAddressSync(escrowPda, body.inputMint, tpIn).address
  const escrowOutAta = deriveAssociatedTokenAddressSync(escrowPda, body.outputMint, tpOut).address
  const vaultInAta = deriveAssociatedTokenAddressSync(vaultAuth, body.inputMint, tpIn).address
  const vaultOutAta = deriveAssociatedTokenAddressSync(vaultAuth, body.outputMint, tpOut).address

  const base = (env.JUPITER_API_URL?.trim() || 'https://api.jup.ag').replace(/\/+$/, '').replace(/\/swap\/v1$/, '')
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    accept: 'application/json',
    ...(env.JUPITER_API_KEY?.trim() ? { 'x-api-key': env.JUPITER_API_KEY.trim() } : {}),
  }
  const res = await fetch(`${base}/swap/v1/swap-instructions`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      quoteResponse: body.quoteResponse,
      userPublicKey: escrowPda,
      wrapAndUnwrapSol: false,
      useSharedAccounts: false,
      skipUserAccountsRpcCalls: true,
      dynamicComputeUnitLimit: false,
    }),
  })
  const jup = (await res.json().catch(() => ({ error: `Jupiter HTTP ${res.status}` }))) as {
    swapInstruction?: unknown
    addressLookupTableAddresses?: string[]
    error?: string
  }
  if (!res.ok || !jup.swapInstruction) {
    return jsonResponse({ error: jup.error ?? `Jupiter swap-instructions HTTP ${res.status}` }, res.status)
  }
  return jsonResponse({
    provider: 'jupiter',
    escrowPda,
    vaultAuth,
    escrowInAta,
    escrowOutAta,
    vaultInAta,
    vaultOutAta,
    swapInstruction: jup.swapInstruction,
    addressLookupTableAddresses: jup.addressLookupTableAddresses ?? [],
    excludedDexes: JUPITER_CPI_EXCLUDED_DEXES,
  })
}

async function handleDevnetDeposit(request: Request, env: Env): Promise<Response> {
  const demo = decodeDemoKeypair(env)
  if (!demo) return jsonResponse({ error: 'Devnet sandbox faucet is not configured on this Worker' }, 503)
  if (!checkRateLimit(getClientIp(request), 'devnet_deposit', RATE_MAX_REQUESTS)) {
    return jsonResponse({ error: 'Devnet sandbox rate limit exceeded; retry in a few minutes' }, 429)
  }

  const body = (await request.json().catch(() => null)) as {
    recipientAddress?: string
    amountLamports?: string
    poolId?: number
  } | null
  if (!body?.recipientAddress) return jsonResponse({ error: 'recipientAddress (aud1...) is required' }, 400)
  const parsedAddr = parseAudrenAddress(body.recipientAddress)
  const amount = BigInt(body.amountLamports ?? '1000000')
  if (amount < MIN_DEMO_DEPOSIT_LAMPORTS || amount > MAX_DEMO_DEPOSIT_LAMPORTS) {
    return jsonResponse({ error: 'Devnet sandbox deposit must be 0.0001..0.005 SOL' }, 400)
  }

  const poolId = body.poolId ?? 0
  const snap = await fetchPoolSnapshot(env, 'devnet', poolId)
  if (!snap.initialized) {
    return jsonResponse({ error: 'Devnet Pool #0 is not initialized yet' }, 503)
  }
  const laneId = Number(BigInt(snap.totalNotes) % BigInt(snap.activeLanes))
  const lane = snap.lanes[laneId]
  if (!lane) return jsonResponse({ error: `Lane #${laneId} missing` }, 503)

  const nextLeaf = BigInt(lane.nextLeaf)
  const subPageSeq = nextLeaf / BigInt(SUBTREE_LEAVES)
  const rootPageSeq = subPageSeq / BigInt(SUBROOTS_PER_PAGE)
  const memoPageSeq = nextLeaf / BigInt(MEMO_NOTES_PER_PAGE)

  const reqPages = [
    deriveSubtreePdaSync(poolId, laneId, subPageSeq, AUDREN_PROGRAM_ID).address,
    deriveSubrootPdaSync(poolId, laneId, rootPageSeq, AUDREN_PROGRAM_ID).address,
    deriveMemoPdaSync(poolId, laneId, memoPageSeq, AUDREN_PROGRAM_ID).address,
  ]
  const pageCheck = await solanaRpc<{ value: Array<unknown | null> }>(env, 'devnet', 'getMultipleAccounts', [
    reqPages,
    { encoding: 'base64', commitment: 'confirmed' },
  ])

  const ixs: V1Instruction[] = []
  if (!pageCheck.value[0]) {
    ixs.push(
      toV1Ix(
        buildOpenPageInstruction({
          poolId,
          laneId,
          pageKind: OPEN_PAGE_KIND_SUBTREE,
          pageSeq: subPageSeq,
          payer: demo.pubkeyStr,
        }),
      ),
    )
  }
  if (!pageCheck.value[1]) {
    ixs.push(
      toV1Ix(
        buildOpenPageInstruction({
          poolId,
          laneId,
          pageKind: OPEN_PAGE_KIND_SUBROOT,
          pageSeq: rootPageSeq,
          payer: demo.pubkeyStr,
        }),
      ),
    )
  }
  if (!pageCheck.value[2]) {
    ixs.push(
      toV1Ix(
        buildOpenPageInstruction({
          poolId,
          laneId,
          pageKind: OPEN_PAGE_KIND_MEMO,
          pageSeq: memoPageSeq,
          payer: demo.pubkeyStr,
        }),
      ),
    )
  }

  const mintBytes = NATIVE_SOL_MINT_BYTES
  const { tweak, blinding, memo90 } = encryptNoteMemo(
    parsedAddr.viewPk,
    crypto.getRandomValues(new Uint8Array(32)),
    amount,
    mintBytes,
  )
  const spendPkFr = frFromBeBytesStrict(parsedAddr.spendPk)
  const stealthOwner = deriveStealthOwner(spendPkFr, tweak)
  const assetId = deriveAssetId(mintBytes)
  const commitment = computeNoteCommitment(stealthOwner, assetId, amount, blinding)

  ixs.push(
    toV1Ix(
      buildDepositSolInstruction({
        poolId,
        laneId,
        subPageSeq,
        rootPageSeq,
        memoPageSeq,
        depositor: demo.pubkeyStr,
        amount,
        stealthOwner,
        blinding,
        memo90,
      }),
    ),
  )

  const tx = await sendAndConfirmV1(env, 'devnet', demo, ixs, 250_000)

  // Best-effort RootCheckpoint publish after DepositSol settles (never fails the deposit on CheckpointTooSoon)
  let checkpointSignature: string | null = null
  try {
    const curSlot = await solanaRpc<number>(env, 'devnet', 'getSlot', [{ commitment: 'confirmed' }])
    const ckptInterval = BigInt(snap.ckptInterval) > 0n ? BigInt(snap.ckptInterval) : 1n
    const slotIdx = Number((BigInt(curSlot) / ckptInterval) % BigInt(CHECKPOINT_RING_SLOTS))
    const ckIx = toV1Ix(
      buildPublishCheckpointInstruction({
        poolId,
        slotIdx,
        activeLanes: snap.activeLanes,
        payer: demo.pubkeyStr,
      }),
    )
    const ckTx = await sendAndConfirmV1(env, 'devnet', demo, [ckIx], 120_000)
    checkpointSignature = ckTx.signature
  } catch {
    // Checkpoint already published in this epoch or slot advanced — deposit succeeded cleanly.
  }

  return jsonResponse({
    cluster: 'devnet',
    poolId,
    laneId,
    leafIndex: nextLeaf.toString(),
    amountLamports: amount.toString(),
    commitmentHex: toHex(frToBeBytes(commitment)),
    checkpointSignature,
    ...tx,
  })
}

async function handleDevnetRelaySubmit(request: Request, env: Env): Promise<Response> {
  const demo = decodeDemoKeypair(env)
  if (!demo) return jsonResponse({ error: 'Devnet sandbox relayer is not configured on this Worker' }, 503)
  if (!checkRateLimit(getClientIp(request), 'devnet_relay', RELAY_RATE_MAX)) {
    return jsonResponse({ error: 'Devnet sandbox relay rate limit exceeded' }, 429)
  }

  const body = (await request.json().catch(() => null)) as {
    cluster?: string
    instructionDataB64?: string
    accounts?: Array<{ pubkey: string; isSigner: boolean; isWritable: boolean }>
    computeUnitLimit?: number
  } | null
  if (body?.cluster && body.cluster !== 'devnet') {
    return jsonResponse({ error: 'apps/web only relays Devnet sandbox transactions; use relay.audren.xyz for Mainnet' }, 403)
  }
  if (!body?.instructionDataB64 || !Array.isArray(body.accounts)) {
    return jsonResponse({ error: 'instructionDataB64 and accounts are required' }, 400)
  }
  const ixData = fromBase64(body.instructionDataB64)
  if (ixData.byteLength === 0 || (ixData[0] !== TAG_JOINSPLIT && ixData[0] !== TAG_EXEC_VIA_ESCROW)) {
    return jsonResponse({ error: 'Only Audren JoinSplit (Tag 6) and ExecViaEscrow (Tag 7) may be relayed' }, 400)
  }
  if (!body.accounts.some((a) => a.pubkey === demo.pubkeyStr && a.isSigner)) {
    return jsonResponse({ error: `Fee payer account must match Devnet sandbox relayer ${demo.pubkeyStr}` }, 400)
  }
  for (const a of body.accounts) {
    if (a.isSigner && a.pubkey !== demo.pubkeyStr) {
      return jsonResponse({ error: 'Only the relayer fee payer may sign a relayed transaction' }, 400)
    }
  }

  const ix: V1Instruction = {
    programId: base58Decode(AUDREN_PROGRAM_ID),
    accounts: body.accounts.map((a) => ({
      pubkey: base58Decode(a.pubkey),
      isSigner: a.isSigner,
      isWritable: a.isWritable,
    })),
    data: ixData,
  }
  const cuLimit = Math.min(1_200_000, Math.max(200_000, body.computeUnitLimit ?? 400_000))
  const tx = await sendAndConfirmV1(env, 'devnet', demo, [ix], cuLimit)
  return jsonResponse({ cluster: 'devnet', relayerPubkey: demo.pubkeyStr, ...tx })
}

const worker = {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)

    const canonicalHost = env.CANONICAL_HOST?.trim().toLowerCase()
    if (canonicalHost && url.hostname.toLowerCase() === `www.${canonicalHost}`) {
      url.hostname = canonicalHost
      return Response.redirect(url.toString(), 301)
    }

    try {
      if (url.pathname === '/api/pool' && request.method === 'GET') {
        const cluster = parseCluster(url.searchParams.get('cluster'))
        const poolId = Number(url.searchParams.get('poolId') ?? '0')
        return jsonResponse(await fetchPoolSnapshot(env, cluster, Number.isFinite(poolId) ? poolId : 0))
      }

      if (url.pathname === '/api/devnet/pool' && request.method === 'GET') {
        const demo = decodeDemoKeypair(env)
        const snap = await fetchPoolSnapshot(env, 'devnet', 0)
        let faucetLamports: number | null = null
        if (demo && env.DEVNET_RPC_URL?.trim()) {
          const bal = await solanaRpc<{ value: number }>(env, 'devnet', 'getBalance', [
            demo.pubkeyStr,
            { commitment: 'confirmed' },
          ]).catch(() => null)
          faucetLamports = bal?.value ?? null
        }
        return jsonResponse({
          ...snap,
          relayerAvailable: Boolean(demo),
          relayerAddress: demo?.pubkeyStr ?? null,
          faucetLamports,
        })
      }

      if (url.pathname === '/api/devnet/deposit' && request.method === 'POST') {
        return await handleDevnetDeposit(request, env)
      }

      if (url.pathname === '/api/rpc/accounts' && request.method === 'POST') {
        return await handleRpcAccounts(request, env)
      }

      if (url.pathname === '/api/wallet/balances' && request.method === 'GET') {
        return await handleWalletBalances(url, env)
      }

      if (url.pathname === '/api/rpc/blockhash' && request.method === 'GET') {
        return await handleRpcBlockhash(url, env)
      }

      if (url.pathname === '/api/rpc/send' && request.method === 'POST') {
        return await handleRpcSend(request, env)
      }

      if (url.pathname === '/api/tx/inspect' && request.method === 'GET') {
        return await handleTxInspect(url, env)
      }

      if (url.pathname === '/api/tokens/search' && request.method === 'GET') {
        return await handleTokensSearch(url, env)
      }

      if (url.pathname === '/api/tokens/resolve' && request.method === 'POST') {
        return await handleTokensResolve(request, env)
      }

      if (url.pathname.startsWith('/api/tokens/logo/') && request.method === 'GET') {
        const sha = url.pathname.slice('/api/tokens/logo/'.length).replace(/\.webp$/, '')
        if (env.GATEWAY && SHA256_RE.test(sha)) {
          const origin = env.TOKEN_GATEWAY_ORIGIN?.trim() || DEFAULT_GATEWAY_ORIGIN
          const res = await env.GATEWAY.fetch(`${origin}/logo/${sha}.webp`)
          if (res.ok) return res
        }
        return new Response(buildMonogramSvg(url.searchParams.get('s'), sha), {
          headers: { 'content-type': 'image/svg+xml; charset=utf-8', 'cache-control': 'public, max-age=86400' },
        })
      }

      if (url.pathname.startsWith('/api/tokens/mint-logo/') && request.method === 'GET') {
        const mint = url.pathname.slice('/api/tokens/mint-logo/'.length).replace(/\.webp$/, '')
        const cached = MINT_ICON_CACHE.get(mint)
        if (cached && isSafeExternalIconUrl(cached.iconUrl)) {
          try {
            const img = await fetch(cached.iconUrl)
            if (img.ok && (img.headers.get('content-type') ?? '').startsWith('image/')) {
              return new Response(img.body, {
                headers: {
                  'content-type': img.headers.get('content-type') ?? 'image/png',
                  'cache-control': 'public, max-age=86400',
                },
              })
            }
          } catch {
            // fall back to SVG monogram
          }
        }
        return new Response(buildMonogramSvg(url.searchParams.get('s'), mint), {
          headers: { 'content-type': 'image/svg+xml; charset=utf-8', 'cache-control': 'public, max-age=86400' },
        })
      }

      if (url.pathname === '/api/jupiter/quote' && request.method === 'POST') {
        return await handleJupiterQuote(request, env)
      }

      if (url.pathname === '/api/jupiter/swap-instructions' && request.method === 'POST') {
        return await handleJupiterSwapInstructions(request, env)
      }

      if (url.pathname === '/api/relay/submit' && request.method === 'POST') {
        return await handleDevnetRelaySubmit(request, env)
      }

      return env.ASSETS.fetch(request)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      return jsonResponse({ error: msg }, 500)
    }
  },
}

export default worker
