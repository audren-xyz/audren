import { ed25519 } from '@noble/curves/ed25519.js'
import {
  AUDREN_PROGRAM_ID,
  CHECKPOINT_RING_SLOTS,
  CLASSIC_TOKEN_PROGRAM_ID,
  MEMO_NOTES_PER_PAGE,
  MEMO_PAGE_LEN,
  NATIVE_SOL_MINT_BYTES,
  NF_PER_PAGE,
  NUM_ESCROW_SHARDS,
  OPEN_PAGE_KIND_MEMO,
  OPEN_PAGE_KIND_NULLIFIER,
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
  deriveNfPagePdaSync,
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

const RATE_BUCKETS = new Map<string, { count: number; resetAt: number }>()

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
  currentEpoch: string
  lastPublishedSlot: string | null
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
  const [epochInfo, subRent, srRent, memoRent] = await Promise.all([
    solanaRpc<{ epoch: number; absoluteSlot: number }>(env, cluster, 'getEpochInfo', [
      { commitment: 'confirmed' },
    ]),
    solanaRpc<number>(env, cluster, 'getMinimumBalanceForRentExemption', [SUBTREE_PAGE_LEN]),
    solanaRpc<number>(env, cluster, 'getMinimumBalanceForRentExemption', [SUBROOT_PAGE_LEN]),
    solanaRpc<number>(env, cluster, 'getMinimumBalanceForRentExemption', [MEMO_PAGE_LEN]),
  ])
  const currentSlot = epochInfo.absoluteSlot
  const currentEpoch = epochInfo.epoch
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
  let bestAnySlot = -1n
  const curSlotBig = BigInt(currentSlot)
  const scanCkptAccounts = (pdas: string[], vals: Array<{ data: [string, string] } | null>) => {
    for (let i = 0; i < pdas.length; i++) {
      const acc = vals[i]
      if (!acc?.data?.[0]) continue
      const ck = decodeRootCheckpoint(fromBase64(acc.data[0]))
      if (ck.publishedSlot > bestAnySlot) bestAnySlot = ck.publishedSlot
      const age = curSlotBig >= ck.publishedSlot ? curSlotBig - ck.publishedSlot : 0n
      if (age <= pool.maxCkptAge && ck.publishedSlot > bestSlot) {
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
    currentEpoch: String(currentEpoch),
    lastPublishedSlot: bestAnySlot >= 0n ? bestAnySlot.toString() : null,
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
  const owners: Array<string | null> = []
  for (let off = 0; off < addresses.length; off += 100) {
    const chunk = addresses.slice(off, off + 100)
    const res = await solanaRpc<{
      value: Array<{ data: [string, string]; owner?: string } | null>
    }>(env, cluster, 'getMultipleAccounts', [chunk, { encoding: 'base64', commitment }])
    for (let i = 0; i < chunk.length; i++) {
      out.push(res.value[i]?.data?.[0] ?? null)
      owners.push(res.value[i]?.owner ?? null)
    }
  }
  return jsonResponse({ cluster, accounts: out, owners })
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

function normalizeGatewayCard(mint: string, card: GatewayTokenCard): ResolvedTokenInfo {
  const flagged = Array.isArray(card.trust?.flags) && card.trust!.flags!.length > 0
  const tier = typeof card.trust?.tier === 'number' ? card.trust.tier : null
  return {
    mint,
    symbol: !flagged && card.symbol?.trim() ? card.symbol.trim() : shortMint(mint),
    name: !flagged && card.name?.trim() ? card.name.trim() : 'Solana Token',
    decimals: typeof card.decimals === 'number' ? card.decimals : null,
    tokenProgram: card.tokenProgram === 'token-2022' ? TOKEN_2022_PROGRAM_ID : CLASSIC_TOKEN_PROGRAM_ID,
    logoUrl: null,
    priceUsd: typeof card.price?.mid === 'number' && card.price.mid > 0 ? card.price.mid : null,
    liquidityUsd: typeof card.liquidityUsd === 'number' && card.liquidityUsd > 0 ? card.liquidityUsd : null,
    verified: !flagged && tier !== null && tier <= 2,
    flagged,
  }
}

function normalizeJupiterToken(tok: JupiterTokenV2): ResolvedTokenInfo {
  const flagged = tok.audit?.isSus === true
  const symbol = !flagged && tok.symbol?.trim() ? tok.symbol.trim() : shortMint(tok.id)
  return {
    mint: tok.id,
    symbol,
    name: !flagged && tok.name?.trim() ? tok.name.trim() : 'Solana Token',
    decimals: typeof tok.decimals === 'number' ? tok.decimals : null,
    tokenProgram: tok.tokenProgram === TOKEN_2022_PROGRAM_ID ? TOKEN_2022_PROGRAM_ID : CLASSIC_TOKEN_PROGRAM_ID,
    logoUrl: null,
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

async function handleTokensResolve(request: Request, env: Env): Promise<Response> {
  const body = (await request.json().catch(() => null)) as { mints?: unknown; cluster?: string } | null
  const mints = Array.isArray(body?.mints) ? body!.mints.map(String).slice(0, 40) : []
  const cluster = parseCluster(body?.cluster)
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
  const missingMeta = mints.filter((m) => !out[m])
  if (missingMeta.length > 0) {
    const rows = await fetchJupiterTokens(env, `search?query=${encodeURIComponent(missingMeta.join(','))}`)
    for (const r of rows) out[r.id] = normalizeJupiterToken(r)
  }
  // Always hydrate on-chain decimals & tokenProgram for any mint still missing metadata or decimals
  const needsChain = mints.filter((m) => !out[m] || out[m]!.decimals === null)
  if (needsChain.length > 0) {
    try {
      const res = await solanaRpc<{
        value: Array<{ data: [string, string]; owner: string } | null>
      }>(env, cluster, 'getMultipleAccounts', [needsChain, { encoding: 'base64', commitment: 'confirmed' }])
      needsChain.forEach((mint, idx) => {
        const acc = res.value[idx]
        if (!acc?.data?.[0]) return
        const bytes = fromBase64(acc.data[0])
        if (bytes.byteLength < 45) return
        const decimals = bytes[44]!
        const tokenProgram = acc.owner === TOKEN_2022_PROGRAM_ID ? TOKEN_2022_PROGRAM_ID : CLASSIC_TOKEN_PROGRAM_ID
        const prev = out[mint]
        out[mint] = prev
          ? { ...prev, decimals: prev.decimals ?? decimals, tokenProgram }
          : {
              mint,
              symbol: shortMint(mint),
              name: 'Solana Token',
              decimals,
              tokenProgram,
              logoUrl: null,
              priceUsd: null,
              liquidityUsd: null,
              verified: false,
              flagged: false,
            }
      })
    } catch {
      // Cluster RPC may be unconfigured in local preview
    }
  }
  return jsonResponse({ tokens: out })
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
    cluster?: string
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
  const cluster = parseCluster(body.cluster)
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

  // Resolve Address Lookup Tables for Direct Self-Pay v0 transaction compression
  const altAddresses = (jup.addressLookupTableAddresses ?? []).slice(0, 8)
  const lookupTables: Record<string, string[]> = {}
  if (altAddresses.length > 0) {
    try {
      const altRes = await solanaRpc<{
        value: Array<{ data: [string, string] } | null>
      }>(env, cluster, 'getMultipleAccounts', [altAddresses, { encoding: 'base64', commitment: 'confirmed' }])
      altAddresses.forEach((altAddr, idx) => {
        const raw = altRes.value[idx]?.data?.[0]
        if (!raw) return
        const bytes = fromBase64(raw)
        if (bytes.byteLength < 56) return
        const addrs: string[] = []
        for (let off = 56; off + 32 <= bytes.byteLength; off += 32) {
          addrs.push(base58Encode(bytes.subarray(off, off + 32)))
        }
        if (addrs.length > 0) lookupTables[altAddr] = addrs
      })
    } catch {
      // Proceed without resolved ALTs if RPC lookup fails
    }
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
    lookupTables,
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
  let checkpointSlotIndex: number | null = null
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
    checkpointSlotIndex = slotIdx
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
    memo90B64: toBase64(memo90),
    checkpointSignature,
    checkpointSlotIndex,
    ...tx,
  })
}

async function handleDevnetCheckpoint(request: Request, env: Env): Promise<Response> {
  const demo = decodeDemoKeypair(env)
  if (!demo) return jsonResponse({ error: 'Devnet sandbox relayer is not configured on this Worker' }, 503)
  if (!checkRateLimit(getClientIp(request), 'devnet_ckpt', RATE_MAX_REQUESTS)) {
    return jsonResponse({ error: 'Devnet checkpoint rate limit exceeded; retry shortly' }, 429)
  }
  const snap = await fetchPoolSnapshot(env, 'devnet', 0)
  if (!snap.initialized) {
    return jsonResponse({ error: 'Devnet Pool #0 is not initialized yet' }, 503)
  }
  const curSlot = await solanaRpc<number>(env, 'devnet', 'getSlot', [{ commitment: 'confirmed' }])
  const ckptInterval = BigInt(snap.ckptInterval) > 0n ? BigInt(snap.ckptInterval) : 1n
  const slotIdx = Number((BigInt(curSlot) / ckptInterval) % BigInt(CHECKPOINT_RING_SLOTS))
  const ckIx = toV1Ix(
    buildPublishCheckpointInstruction({
      poolId: 0,
      slotIdx,
      activeLanes: snap.activeLanes,
      payer: demo.pubkeyStr,
    }),
  )
  const ckTx = await sendAndConfirmV1(env, 'devnet', demo, [ckIx], 120_000)
  return jsonResponse({
    cluster: 'devnet',
    slotIdx,
    ...ckTx,
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
  if (
    !body?.instructionDataB64 ||
    typeof body.instructionDataB64 !== 'string' ||
    body.instructionDataB64.length > 5_400 ||
    !Array.isArray(body.accounts) ||
    body.accounts.length < 12 ||
    body.accounts.length > 62
  ) {
    return jsonResponse({ error: 'Valid instructionDataB64 and 12..62 accounts are required' }, 400)
  }

  let ixData: Uint8Array
  try {
    ixData = fromBase64(body.instructionDataB64)
  } catch {
    return jsonResponse({ error: 'instructionDataB64 must be valid base64' }, 400)
  }
  const tag = ixData[0]
  if (tag !== TAG_JOINSPLIT && tag !== TAG_EXEC_VIA_ESCROW) {
    return jsonResponse({ error: 'Only Audren JoinSplit (Tag 6) and ExecViaEscrow (Tag 7) may be relayed' }, 400)
  }
  const minDataLen = tag === TAG_JOINSPLIT ? 378 : 544
  if (ixData.byteLength < minDataLen) {
    return jsonResponse({ error: `Instruction data too short (${ixData.byteLength} < ${minDataLen})` }, 400)
  }

  const payerAcc = body.accounts[0]
  if (!payerAcc || payerAcc.pubkey !== demo.pubkeyStr || !payerAcc.isSigner || !payerAcc.isWritable) {
    return jsonResponse(
      { error: `accounts[0] must be Devnet sandbox relayer ${demo.pubkeyStr} (writable signer)` },
      400,
    )
  }
  const pool0Pda = derivePoolPdaSync(0, AUDREN_PROGRAM_ID).address
  if (body.accounts[1]?.pubkey !== pool0Pda) {
    return jsonResponse({ error: `accounts[1] must be canonical Pool #0 (${pool0Pda})` }, 400)
  }

  const decodedAccounts: V1Instruction['accounts'] = []
  for (let i = 0; i < body.accounts.length; i++) {
    const a = body.accounts[i]
    if (!a || typeof a.pubkey !== 'string') {
      return jsonResponse({ error: `Missing pubkey at accounts[${i}]` }, 400)
    }
    if (i > 0 && a.isSigner) {
      return jsonResponse({ error: 'Only accounts[0] (relayer fee payer) may sign a relayed transaction' }, 400)
    }
    let pk: Uint8Array
    try {
      pk = base58Decode(a.pubkey)
    } catch {
      return jsonResponse({ error: `Invalid base58 pubkey at accounts[${i}]` }, 400)
    }
    if (pk.byteLength !== 32) {
      return jsonResponse({ error: `accounts[${i}] must be a 32-byte Solana pubkey` }, 400)
    }
    decodedAccounts.push({ pubkey: pk, isSigner: Boolean(a.isSigner), isWritable: Boolean(a.isWritable) })
  }

  // Ensure output/nullifier pages exist on Devnet Pool #0 outLaneId before Tag 6 JoinSplit
  const preIxs: V1Instruction[] = []
  if (tag === TAG_JOINSPLIT) {
    const outLaneId = ixData[6]!
    const lanePda = deriveLanePdaSync(0, outLaneId, AUDREN_PROGRAM_ID).address
    const laneRes = await solanaRpc<{ value: Array<{ data: [string, string] } | null> }>(
      env,
      'devnet',
      'getMultipleAccounts',
      [[lanePda], { encoding: 'base64', commitment: 'confirmed' }],
    )
    const laneRaw = laneRes.value[0]?.data?.[0]
    if (laneRaw) {
      const hdr = decodeLaneHeader(fromBase64(laneRaw))
      const subSeq = hdr.nextLeaf / BigInt(SUBTREE_LEAVES)
      const rootSeq = subSeq / BigInt(SUBROOTS_PER_PAGE)
      const memoSeq = hdr.nextLeaf / BigInt(MEMO_NOTES_PER_PAGE)
      const nfSeq = hdr.nfCount / BigInt(NF_PER_PAGE)
      const pageAddrs = [
        deriveSubtreePdaSync(0, outLaneId, subSeq, AUDREN_PROGRAM_ID).address,
        deriveSubrootPdaSync(0, outLaneId, rootSeq, AUDREN_PROGRAM_ID).address,
        deriveMemoPdaSync(0, outLaneId, memoSeq, AUDREN_PROGRAM_ID).address,
        deriveNfPagePdaSync(0, outLaneId, nfSeq, AUDREN_PROGRAM_ID).address,
      ]
      const pageCheck = await solanaRpc<{ value: Array<unknown | null> }>(
        env,
        'devnet',
        'getMultipleAccounts',
        [pageAddrs, { encoding: 'base64', commitment: 'confirmed' }],
      )
      if (!pageCheck.value[0]) {
        preIxs.push(
          toV1Ix(buildOpenPageInstruction({ poolId: 0, laneId: outLaneId, pageKind: OPEN_PAGE_KIND_SUBTREE, pageSeq: subSeq, payer: demo.pubkeyStr })),
        )
      }
      if (!pageCheck.value[1]) {
        preIxs.push(
          toV1Ix(buildOpenPageInstruction({ poolId: 0, laneId: outLaneId, pageKind: OPEN_PAGE_KIND_SUBROOT, pageSeq: rootSeq, payer: demo.pubkeyStr })),
        )
      }
      if (!pageCheck.value[2]) {
        preIxs.push(
          toV1Ix(buildOpenPageInstruction({ poolId: 0, laneId: outLaneId, pageKind: OPEN_PAGE_KIND_MEMO, pageSeq: memoSeq, payer: demo.pubkeyStr })),
        )
      }
      if (!pageCheck.value[3]) {
        preIxs.push(
          toV1Ix(buildOpenPageInstruction({ poolId: 0, laneId: outLaneId, pageKind: OPEN_PAGE_KIND_NULLIFIER, pageSeq: nfSeq, payer: demo.pubkeyStr })),
        )
      }
    }
  }

  const ix: V1Instruction = {
    programId: base58Decode(AUDREN_PROGRAM_ID),
    accounts: decodedAccounts,
    data: ixData,
  }
  const cuLimit = Math.min(1_200_000, Math.max(200_000, body.computeUnitLimit ?? 400_000))
  const tx = await sendAndConfirmV1(env, 'devnet', demo, [...preIxs, ix], cuLimit)
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

      if (url.pathname === '/api/devnet/checkpoint' && request.method === 'POST') {
        return await handleDevnetCheckpoint(request, env)
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

      if (url.pathname === '/api/tokens/resolve' && request.method === 'POST') {
        return await handleTokensResolve(request, env)
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
