import {
  MAX_APPEND_LANES,
  base58Encode,
  fromBase64,
  scalarToBytes32LE,
  sha256,
  toBase64,
  u32le,
  utf8,
  type AudrenKeypair,
  type SpendableAudrenNote,
} from '@audren/sdk/prover'

const decoder = new TextDecoder()

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(u8.byteLength)
  copy.set(u8)
  return copy.buffer
}

// ============================================================================
// Encrypted Persistent Local Vault Inventory (AES-256-GCM keyed from viewSk)
// Keyed by (cluster, poolId, spendPk) so historical notes never disappear on
// page rollover and incremental checkpoint recovery resumes where it left off.
// ============================================================================

export interface VaultInventorySnapshot {
  version: 1
  birthPageId?: bigint | null
  lastSealedPageId: bigint | null
  lastOpenPageId: bigint | null
  lastOpenPageCount: number
  laneSealedThrough?: Record<number, bigint>
  lastVerifiedAtMs: number | null
  notes: SpendableAudrenNote[]
  verifiedDynamicAmounts: Record<string, bigint>
}

interface SerializedSpendableNote {
  pageId: string
  slotIndex: number
  mintB64: string
  mintB58: string
  isNativeSol: boolean
  amount: string
  isDynamicOutput: boolean
  amountResolved: boolean
  memoText: string
  stealthPkB64: string
  assetTagB64: string
  commitmentB64: string
  assetBlinding: string
  valueBlinding: string
  stealthScalar: string
  spendX: string
  nullifierB64: string
  nullifierPdaB58: string
}

interface SerializedVaultInventory {
  version: 1
  birthPageId?: string | null
  lastSealedPageId: string | null
  lastOpenPageId: string | null
  lastOpenPageCount: number
  laneSealedThrough?: Record<string, string>
  lastVerifiedAtMs: number | null
  notes: SerializedSpendableNote[]
  verifiedDynamicAmounts: Record<string, string>
}

function vaultStorageKey(cluster: string, poolId: number, spendPk: Uint8Array): string {
  return `audren_vault_inv_v1:${cluster}:${poolId}:${base58Encode(spendPk)}`
}

async function deriveVaultStorageKey(
  viewSk: bigint,
  cluster: string,
  poolId: number,
): Promise<CryptoKey> {
  const keyBytes = await sha256(
    utf8('audren/v1/local-inventory-key'),
    scalarToBytes32LE(viewSk),
    utf8(cluster),
    u32le(poolId),
  )
  return crypto.subtle.importKey('raw', toArrayBuffer(keyBytes), 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ])
}

export async function loadEncryptedVaultInventory(
  keys: Pick<AudrenKeypair, 'spendPk' | 'viewSk'>,
  cluster: string,
  poolId = 0,
): Promise<VaultInventorySnapshot | null> {
  if (typeof window === 'undefined') return null
  try {
    const raw = window.localStorage.getItem(vaultStorageKey(cluster, poolId, keys.spendPk))
    if (!raw) return null
    const envelope = JSON.parse(raw) as { iv?: string; ct?: string }
    if (!envelope.iv || !envelope.ct) return null
    const aesKey = await deriveVaultStorageKey(keys.viewSk, cluster, poolId)
    const plain = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBuffer(fromBase64(envelope.iv)),
        additionalData: toArrayBuffer(keys.spendPk),
      },
      aesKey,
      toArrayBuffer(fromBase64(envelope.ct)),
    )
    const parsed = JSON.parse(decoder.decode(new Uint8Array(plain))) as SerializedVaultInventory
    if (parsed.version !== 1 || !Array.isArray(parsed.notes)) return null

    const verifiedDynamicAmounts: Record<string, bigint> = {}
    for (const [k, v] of Object.entries(parsed.verifiedDynamicAmounts ?? {})) {
      if (/^\d+$/.test(v)) verifiedDynamicAmounts[k] = BigInt(v)
    }

    const laneSealedThrough: Record<number, bigint> = {}
    for (const [k, v] of Object.entries(parsed.laneSealedThrough ?? {})) {
      const lid = Number(k)
      if (Number.isInteger(lid) && lid >= 0 && lid < MAX_APPEND_LANES && /^\d+$/.test(v)) {
        laneSealedThrough[lid] = BigInt(v)
      }
    }

    const notes: SpendableAudrenNote[] = parsed.notes.map((n) => ({
      pageId: BigInt(n.pageId),
      slotIndex: n.slotIndex,
      mint: fromBase64(n.mintB64),
      mintB58: n.mintB58,
      isNativeSol: n.isNativeSol,
      amount: BigInt(n.amount),
      isDynamicOutput: n.isDynamicOutput,
      amountResolved: n.amountResolved,
      memoText: n.memoText,
      stealthPk: fromBase64(n.stealthPkB64),
      assetTag: fromBase64(n.assetTagB64),
      commitment: fromBase64(n.commitmentB64),
      assetBlinding: BigInt(n.assetBlinding),
      valueBlinding: BigInt(n.valueBlinding),
      stealthScalar: BigInt(n.stealthScalar),
      spendX: BigInt(n.spendX),
      nullifier: fromBase64(n.nullifierB64),
      nullifierPdaB58: n.nullifierPdaB58,
    }))

    return {
      version: 1,
      birthPageId:
        parsed.birthPageId !== undefined && parsed.birthPageId !== null
          ? BigInt(parsed.birthPageId)
          : null,
      lastSealedPageId: parsed.lastSealedPageId !== null ? BigInt(parsed.lastSealedPageId) : null,
      lastOpenPageId: parsed.lastOpenPageId !== null ? BigInt(parsed.lastOpenPageId) : null,
      lastOpenPageCount: parsed.lastOpenPageCount ?? 0,
      laneSealedThrough,
      lastVerifiedAtMs: parsed.lastVerifiedAtMs ?? null,
      notes,
      verifiedDynamicAmounts,
    }
  } catch {
    return null
  }
}

export async function saveEncryptedVaultInventory(
  keys: Pick<AudrenKeypair, 'spendPk' | 'viewSk'>,
  cluster: string,
  poolId: number,
  snapshot: VaultInventorySnapshot,
): Promise<void> {
  if (typeof window === 'undefined') return
  try {
    const serializedDyn: Record<string, string> = {}
    for (const [k, v] of Object.entries(snapshot.verifiedDynamicAmounts)) {
      serializedDyn[k] = v.toString()
    }
    const serializedLanes: Record<string, string> = {}
    for (const [k, v] of Object.entries(snapshot.laneSealedThrough ?? {})) {
      serializedLanes[String(k)] = v.toString()
    }
    const payload: SerializedVaultInventory = {
      version: 1,
      birthPageId:
        snapshot.birthPageId !== undefined && snapshot.birthPageId !== null
          ? snapshot.birthPageId.toString()
          : null,
      lastSealedPageId:
        snapshot.lastSealedPageId !== null ? snapshot.lastSealedPageId.toString() : null,
      lastOpenPageId: snapshot.lastOpenPageId !== null ? snapshot.lastOpenPageId.toString() : null,
      lastOpenPageCount: snapshot.lastOpenPageCount,
      laneSealedThrough: serializedLanes,
      lastVerifiedAtMs: snapshot.lastVerifiedAtMs,
      notes: snapshot.notes.map((n) => ({
        pageId: n.pageId.toString(),
        slotIndex: n.slotIndex,
        mintB64: toBase64(n.mint),
        mintB58: n.mintB58,
        isNativeSol: n.isNativeSol,
        amount: n.amount.toString(),
        isDynamicOutput: n.isDynamicOutput,
        amountResolved: n.amountResolved,
        memoText: n.memoText,
        stealthPkB64: toBase64(n.stealthPk),
        assetTagB64: toBase64(n.assetTag),
        commitmentB64: toBase64(n.commitment),
        assetBlinding: n.assetBlinding.toString(),
        valueBlinding: n.valueBlinding.toString(),
        stealthScalar: n.stealthScalar.toString(),
        spendX: n.spendX.toString(),
        nullifierB64: toBase64(n.nullifier),
        nullifierPdaB58: n.nullifierPdaB58,
      })),
      verifiedDynamicAmounts: serializedDyn,
    }
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const aesKey = await deriveVaultStorageKey(keys.viewSk, cluster, poolId)
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: toArrayBuffer(iv), additionalData: toArrayBuffer(keys.spendPk) },
      aesKey,
      toArrayBuffer(utf8(JSON.stringify(payload))),
    )
    window.localStorage.setItem(
      vaultStorageKey(cluster, poolId, keys.spendPk),
      JSON.stringify({ iv: toBase64(iv), ct: toBase64(new Uint8Array(ct)) }),
    )
  } catch {
    // Ignore storage quota errors
  }
}

export function clearEncryptedVaultInventory(
  spendPk: Uint8Array,
  cluster: string,
  poolId = 0,
): void {
  if (typeof window === 'undefined') return
  try {
    window.localStorage.removeItem(vaultStorageKey(cluster, poolId, spendPk))
  } catch {
    // Ignore
  }
}

// ============================================================================
// PBKDF2-SHA256 + AES-256-GCM Encrypted Portable Vault Backup
// Enables hardware-wallet & cross-device users to back up and restore their
// shielded vault seed + birth checkpoint + verified dynamic swap settlements.
// ============================================================================

export interface AudrenEncryptedBackupFile {
  format: 'audren-vault-backup-v1'
  kdf: 'PBKDF2-SHA256'
  iterations: number
  saltB64: string
  ivB64: string
  ctB64: string
  createdAtIso: string
  cluster: 'devnet' | 'mainnet'
  audrenAddress: string
}

export interface AudrenBackupPayload {
  version: 1
  cluster: 'devnet' | 'mainnet'
  seedB64: string
  birthPageId: string | null
  verifiedDynamicAmounts: Record<string, string>
}

const BACKUP_PBKDF2_ITERATIONS = 600_000

async function deriveBackupAesKey(
  passphrase: string,
  salt: Uint8Array,
  iterations: number,
): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(utf8(passphrase)),
    'PBKDF2',
    false,
    ['deriveKey'],
  )
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: toArrayBuffer(salt),
      iterations,
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

export async function exportEncryptedVaultBackup(params: {
  seed: Uint8Array
  audrenAddress: string
  cluster: 'devnet' | 'mainnet'
  passphrase: string
  birthPageId?: bigint | null
  verifiedDynamicAmounts?: Record<string, bigint>
}): Promise<AudrenEncryptedBackupFile> {
  if (params.passphrase.length < 8) {
    throw new Error('Backup passphrase must be at least 8 characters')
  }
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const aesKey = await deriveBackupAesKey(params.passphrase, salt, BACKUP_PBKDF2_ITERATIONS)

  const dyn: Record<string, string> = {}
  for (const [k, v] of Object.entries(params.verifiedDynamicAmounts ?? {})) {
    dyn[k] = v.toString()
  }

  const payload: AudrenBackupPayload = {
    version: 1,
    cluster: params.cluster,
    seedB64: toBase64(params.seed),
    birthPageId:
      params.birthPageId !== undefined && params.birthPageId !== null
        ? params.birthPageId.toString()
        : null,
    verifiedDynamicAmounts: dyn,
  }

  const aad = utf8(`audren-vault-backup-v1:${params.cluster}:${params.audrenAddress}`)
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv), additionalData: toArrayBuffer(aad) },
    aesKey,
    toArrayBuffer(utf8(JSON.stringify(payload))),
  )

  return {
    format: 'audren-vault-backup-v1',
    kdf: 'PBKDF2-SHA256',
    iterations: BACKUP_PBKDF2_ITERATIONS,
    saltB64: toBase64(salt),
    ivB64: toBase64(iv),
    ctB64: toBase64(new Uint8Array(ct)),
    createdAtIso: new Date().toISOString(),
    cluster: params.cluster,
    audrenAddress: params.audrenAddress,
  }
}

export async function importEncryptedVaultBackup(
  backup: AudrenEncryptedBackupFile,
  passphrase: string,
): Promise<{
  seed: Uint8Array
  cluster: 'devnet' | 'mainnet'
  birthPageId: bigint | null
  verifiedDynamicAmounts: Record<string, bigint>
}> {
  if (backup.format !== 'audren-vault-backup-v1' || backup.kdf !== 'PBKDF2-SHA256') {
    throw new Error('Unsupported Audren vault backup format')
  }
  const iterations = Math.max(100_000, Math.min(2_000_000, Number(backup.iterations) || 600_000))
  const salt = fromBase64(backup.saltB64)
  const iv = fromBase64(backup.ivB64)
  const ct = fromBase64(backup.ctB64)
  const aesKey = await deriveBackupAesKey(passphrase, salt, iterations)
  const aad = utf8(`audren-vault-backup-v1:${backup.cluster}:${backup.audrenAddress}`)

  let plainBuf: ArrayBuffer
  try {
    plainBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: toArrayBuffer(iv), additionalData: toArrayBuffer(aad) },
      aesKey,
      toArrayBuffer(ct),
    )
  } catch {
    throw new Error('Wrong passphrase or tampered vault backup file')
  }

  const parsed = JSON.parse(decoder.decode(new Uint8Array(plainBuf))) as AudrenBackupPayload
  if (parsed.version !== 1 || !parsed.seedB64) {
    throw new Error('Malformed decrypted vault backup payload')
  }
  const seed = fromBase64(parsed.seedB64)
  if (seed.length !== 32) {
    throw new Error('Invalid vault seed length in backup')
  }
  const verifiedDynamicAmounts: Record<string, bigint> = {}
  for (const [k, v] of Object.entries(parsed.verifiedDynamicAmounts ?? {})) {
    if (/^\d+$/.test(v)) verifiedDynamicAmounts[k] = BigInt(v)
  }
  return {
    seed,
    cluster: parsed.cluster,
    birthPageId: parsed.birthPageId !== null ? BigInt(parsed.birthPageId) : null,
    verifiedDynamicAmounts,
  }
}

// ============================================================================
// Persistent Self-Pay ProofBuffer Journal (Rent Recovery for Interrupted Uploads)
// ============================================================================

export interface PendingProofBuffer {
  nonce: string
  bufferPdaB58: string
  label: string
  createdAtMs: number
}

function bufferJournalKey(cluster: string, payerB58: string): string {
  return `audren_pending_bufs_v1:${cluster}:${payerB58}`
}

export function loadPendingProofBuffers(
  cluster: string,
  payerB58: string,
): PendingProofBuffer[] {
  if (typeof window === 'undefined') return []
  try {
    const raw = window.localStorage.getItem(bufferJournalKey(cluster, payerB58))
    if (!raw) return []
    const parsed = JSON.parse(raw) as PendingProofBuffer[]
    if (!Array.isArray(parsed)) return []
    return parsed.filter(
      (b) =>
        typeof b.bufferPdaB58 === 'string' &&
        typeof b.nonce === 'string' &&
        typeof b.createdAtMs === 'number',
    )
  } catch {
    return []
  }
}

export function recordPendingProofBuffer(
  cluster: string,
  payerB58: string,
  entry: PendingProofBuffer,
): void {
  if (typeof window === 'undefined') return
  try {
    const existing = loadPendingProofBuffers(cluster, payerB58).filter(
      (b) => b.bufferPdaB58 !== entry.bufferPdaB58,
    )
    existing.push(entry)
    // Cap journal at 16 most recent entries
    const trimmed = existing.slice(-16)
    window.localStorage.setItem(bufferJournalKey(cluster, payerB58), JSON.stringify(trimmed))
  } catch {
    // Ignore
  }
}

export function removePendingProofBuffer(
  cluster: string,
  payerB58: string,
  bufferPdaB58: string,
): void {
  if (typeof window === 'undefined') return
  try {
    const remaining = loadPendingProofBuffers(cluster, payerB58).filter(
      (b) => b.bufferPdaB58 !== bufferPdaB58,
    )
    if (remaining.length === 0) {
      window.localStorage.removeItem(bufferJournalKey(cluster, payerB58))
    } else {
      window.localStorage.setItem(bufferJournalKey(cluster, payerB58), JSON.stringify(remaining))
    }
  } catch {
    // Ignore
  }
}
