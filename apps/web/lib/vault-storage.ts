import { CompactWalletStore, base58Encode, type AudrenKeys } from '@audren/sdk'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(u8.byteLength)
  copy.set(u8)
  return copy.buffer
}

function toBase64(bytes: Uint8Array): string {
  let bin = ''
  for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]!)
  return btoa(bin)
}

function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

// ============================================================================
// AES-256-GCM Encrypted IndexedDB Persistence for CompactWalletStore
// Discards every sealed SubtreePage/MemoPage immediately; persists only frozen
// intra-subtree siblings, 32 B finalized subroots, frontier leaves, & 16 B nf prefixes.
// ============================================================================

const IDB_NAME = 'audren_vault_store'
const IDB_STORE = 'compact_stores'
const IDB_VERSION = 1

function storeKey(
  cluster: string,
  poolId: number,
  spendPkBytes: Uint8Array,
  walletScope = 'local',
): string {
  return `audren_store:${cluster}:${poolId}:${walletScope}:${base58Encode(spendPkBytes)}`
}

async function openVaultDb(): Promise<IDBDatabase | null> {
  if (typeof window === 'undefined' || !('indexedDB' in window)) return null
  return new Promise((resolve) => {
    try {
      const req = window.indexedDB.open(IDB_NAME, IDB_VERSION)
      req.onupgradeneeded = () => {
        const db = req.result
        if (!db.objectStoreNames.contains(IDB_STORE)) {
          db.createObjectStore(IDB_STORE)
        }
      }
      req.onsuccess = () => resolve(req.result)
      req.onerror = () => resolve(null)
    } catch {
      resolve(null)
    }
  })
}

async function idbGet(key: string): Promise<string | null> {
  const db = await openVaultDb()
  if (!db) {
    try {
      return window.localStorage.getItem(key)
    } catch {
      return null
    }
  }
  return new Promise((resolve) => {
    const tx = db.transaction(IDB_STORE, 'readonly')
    const req = tx.objectStore(IDB_STORE).get(key)
    req.onsuccess = () => resolve(typeof req.result === 'string' ? req.result : null)
    req.onerror = () => resolve(null)
  })
}

async function idbSet(key: string, value: string): Promise<void> {
  const db = await openVaultDb()
  if (!db) {
    try {
      window.localStorage.setItem(key, value)
    } catch {
      // ignore quota errors
    }
    return
  }
  await new Promise<void>((resolve) => {
    const tx = db.transaction(IDB_STORE, 'readwrite')
    tx.objectStore(IDB_STORE).put(value, key)
    tx.oncomplete = () => resolve()
    tx.onerror = () => resolve()
  })
}

async function idbDelete(key: string): Promise<void> {
  const db = await openVaultDb()
  if (!db) {
    try {
      window.localStorage.removeItem(key)
    } catch {
      // ignore
    }
    return
  }
  await new Promise<void>((resolve) => {
    const tx = db.transaction(IDB_STORE, 'readwrite')
    tx.objectStore(IDB_STORE).delete(key)
    tx.oncomplete = () => resolve()
    tx.onerror = () => resolve()
  })
}

async function deriveStoreAesKey(
  viewSk: Uint8Array,
  cluster: string,
  poolId: number,
): Promise<CryptoKey> {
  const info = encoder.encode(`audren/v1/compact-store-key:${cluster}:${poolId}`)
  const preimage = new Uint8Array(viewSk.byteLength + info.byteLength)
  preimage.set(viewSk, 0)
  preimage.set(info, viewSk.byteLength)
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(preimage)))
  return crypto.subtle.importKey('raw', toArrayBuffer(digest), 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ])
}

export async function loadEncryptedCompactStore(
  keys: Pick<AudrenKeys, 'spendPkBytes' | 'viewSk'>,
  cluster: string,
  poolId = 0,
  walletScope = 'local',
): Promise<CompactWalletStore | null> {
  if (typeof window === 'undefined') return null
  try {
    const raw = await idbGet(storeKey(cluster, poolId, keys.spendPkBytes, walletScope))
    if (!raw) return null
    const env = JSON.parse(raw) as { iv?: string; ct?: string }
    if (!env.iv || !env.ct) return null
    const aesKey = await deriveStoreAesKey(keys.viewSk, cluster, poolId)
    const plain = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBuffer(fromBase64(env.iv)),
        additionalData: toArrayBuffer(keys.spendPkBytes),
      },
      aesKey,
      toArrayBuffer(fromBase64(env.ct)),
    )
    return CompactWalletStore.fromJSON(decoder.decode(new Uint8Array(plain)))
  } catch {
    return null
  }
}

export async function saveEncryptedCompactStore(
  keys: Pick<AudrenKeys, 'spendPkBytes' | 'viewSk'>,
  cluster: string,
  poolId: number,
  store: CompactWalletStore,
  walletScope = 'local',
): Promise<void> {
  if (typeof window === 'undefined') return
  try {
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const aesKey = await deriveStoreAesKey(keys.viewSk, cluster, poolId)
    const ct = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBuffer(iv),
        additionalData: toArrayBuffer(keys.spendPkBytes),
      },
      aesKey,
      toArrayBuffer(encoder.encode(store.toJSON())),
    )
    await idbSet(
      storeKey(cluster, poolId, keys.spendPkBytes, walletScope),
      JSON.stringify({ iv: toBase64(iv), ct: toBase64(new Uint8Array(ct)) }),
    )
  } catch {
    // ignore storage quota errors
  }
}

export async function clearEncryptedCompactStore(
  spendPkBytes: Uint8Array,
  cluster: string,
  poolId = 0,
  walletScope = 'local',
): Promise<void> {
  if (typeof window === 'undefined') return
  await idbDelete(storeKey(cluster, poolId, spendPkBytes, walletScope))
}

// ============================================================================
// PBKDF2-SHA256 + AES-256-GCM Portable Encrypted Vault Backup
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
  birthdaySlot?: string
}

const BACKUP_PBKDF2_ITERATIONS = 600_000

async function deriveBackupAesKey(
  passphrase: string,
  salt: Uint8Array,
  iterations: number,
): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(encoder.encode(passphrase)),
    'PBKDF2',
    false,
    ['deriveKey'],
  )
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: toArrayBuffer(salt), iterations },
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
  birthdaySlot?: bigint
}): Promise<AudrenEncryptedBackupFile> {
  if (params.passphrase.length < 8) {
    throw new Error('Backup passphrase must be at least 8 characters')
  }
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const aesKey = await deriveBackupAesKey(params.passphrase, salt, BACKUP_PBKDF2_ITERATIONS)
  const birthdaySlotStr = (params.birthdaySlot ?? 0n).toString()
  const payload = {
    version: 1,
    cluster: params.cluster,
    seedB64: toBase64(params.seed),
    birthdaySlot: birthdaySlotStr,
  }
  const aad = encoder.encode(`audren-vault-backup-v1:${params.cluster}:${params.audrenAddress}`)
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv), additionalData: toArrayBuffer(aad) },
    aesKey,
    toArrayBuffer(encoder.encode(JSON.stringify(payload))),
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
    birthdaySlot: birthdaySlotStr,
  }
}

export async function importEncryptedVaultBackup(
  backup: AudrenEncryptedBackupFile,
  passphrase: string,
): Promise<{ seed: Uint8Array; cluster: 'devnet' | 'mainnet'; birthdaySlot: bigint }> {
  if (backup.format !== 'audren-vault-backup-v1' || backup.kdf !== 'PBKDF2-SHA256') {
    throw new Error('Unsupported Audren vault backup format')
  }
  const iterations = Math.max(100_000, Math.min(2_000_000, Number(backup.iterations) || 600_000))
  const aesKey = await deriveBackupAesKey(passphrase, fromBase64(backup.saltB64), iterations)
  const aad = encoder.encode(`audren-vault-backup-v1:${backup.cluster}:${backup.audrenAddress}`)
  let plainBuf: ArrayBuffer
  try {
    plainBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: toArrayBuffer(fromBase64(backup.ivB64)), additionalData: toArrayBuffer(aad) },
      aesKey,
      toArrayBuffer(fromBase64(backup.ctB64)),
    )
  } catch {
    throw new Error('Wrong passphrase or tampered vault backup file')
  }
  const parsed = JSON.parse(decoder.decode(new Uint8Array(plainBuf))) as {
    version: number
    cluster: 'devnet' | 'mainnet'
    seedB64: string
    birthdaySlot?: string
  }
  if (parsed.version !== 1 || !parsed.seedB64) {
    throw new Error('Malformed decrypted vault backup payload')
  }
  const seed = fromBase64(parsed.seedB64)
  if (seed.byteLength !== 32) throw new Error('Invalid vault seed length in backup')
  const rawSlot = parsed.birthdaySlot ?? backup.birthdaySlot ?? '0'
  const birthdaySlot = /^\d+$/.test(rawSlot) ? BigInt(rawSlot) : 0n
  return {
    seed,
    cluster: parsed.cluster,
    birthdaySlot,
  }
}
