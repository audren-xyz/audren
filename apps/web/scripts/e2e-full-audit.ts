/**
 * DEEP EMPIRICAL END-TO-END AUDIT OF https://audren.xyz
 *
 * Tests EVERY user-facing page, EVERY wallet mode (Relayer + Direct + Custom Relayer),
 * BOTH Solana clusters (Devnet parity on Solana Devnet RPC + Mainnet),
 * Selective Disclosure Viewing Receipts (real ✓ + forged ✕), Live On-Chain Verification strips,
 * and the Free Devnet Sandbox — using real headless Chromium + real Phantom Wallet Standard signing.
 *
 * Run: npx tsx scripts/e2e-full-audit.ts
 */

import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { ed25519 } from '@noble/curves/ed25519.js'
import { base58Encode } from '../lib/audren-crypto'

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..')

function requireEnv(name: string): string {
  const val = process.env[name]?.trim()
  if (!val) throw new Error(`Missing required environment variable: ${name}`)
  return val
}

const BASE_URL = (process.env.AUDREN_BASE_URL ?? 'https://audren.xyz').replace(/\/+$/, '')
const KEYPAIR_PATH =
  process.env.AUDREN_TEST_KEYPAIR ??
  process.env.AUDREN_KEYPAIR_PATH ??
  path.join(REPO_ROOT, '.credentials/funder.json')
const MAINNET_QN_RPC = requireEnv('MAINNET_RPC_URL')
const DEVNET_QN_RPC = requireEnv('DEVNET_RPC_URL')
const RELAYER_DEVNET = 'G3tGgntjaDAcamZX2Jcgn616PrjArKYdGXv5C13MzMP'
const CHROME_PATH = process.env.CHROME_PATH ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
const SCREENSHOT_DIR = '/tmp/audren-full-audit'
const CDP_PORT = 9232
const USER_DATA_DIR = '/tmp/audren-full-audit-chrome'

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms))
}

function banner(title: string) {
  console.log(`\n${'═'.repeat(72)}\n  ${title}\n${'═'.repeat(72)}`)
}

function loadSigner() {
  const raw = Uint8Array.from(JSON.parse(readFileSync(KEYPAIR_PATH, 'utf8')))
  const secret32 = raw.subarray(0, 32)
  const pubkey = ed25519.getPublicKey(secret32)
  return { secret32, pubkey, address: base58Encode(pubkey) }
}

function extractSolanaMessageFromTx(txBytes: Uint8Array): { sigCount: number; msgOffset: number; message: Uint8Array } {
  let sigCount = 0
  let shift = 0
  let pos = 0
  while (true) {
    const b = txBytes[pos++]!
    sigCount |= (b & 0x7f) << shift
    if ((b & 0x80) === 0) break
    shift += 7
  }
  const msgOffset = pos + sigCount * 64
  return { sigCount, msgOffset, message: txBytes.subarray(msgOffset) }
}

function signWireTransaction(secret32: Uint8Array, txBytes: Uint8Array): Uint8Array {
  const { sigCount, msgOffset, message } = extractSolanaMessageFromTx(txBytes)
  assert.ok(sigCount >= 1 && msgOffset < txBytes.length, 'Invalid wire tx format')
  const sig = ed25519.sign(message, secret32)
  const out = new Uint8Array(txBytes)
  const sigStart = msgOffset - sigCount * 64
  out.set(sig, sigStart)
  return out
}

class CdpClient {
  private ws!: WebSocket
  private nextId = 1
  private pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>()
  private listeners = new Map<string, Array<(p: Record<string, unknown>) => void>>()
  sessionId: string | null = null

  async connect(wsUrl: string) {
    await new Promise<void>((resolve, reject) => {
      this.ws = new WebSocket(wsUrl)
      this.ws.onopen = () => resolve()
      this.ws.onerror = () => reject(new Error('CDP WebSocket failed'))
      this.ws.onmessage = (ev) => {
        const msg = JSON.parse(String(ev.data)) as {
          id?: number
          result?: unknown
          error?: { message?: string }
          method?: string
          params?: Record<string, unknown>
        }
        if (msg.id !== undefined) {
          const p = this.pending.get(msg.id)
          if (p) {
            this.pending.delete(msg.id)
            if (msg.error) p.reject(new Error(msg.error.message ?? 'CDP error'))
            else p.resolve(msg.result)
          }
        } else if (msg.method) {
          for (const fn of this.listeners.get(msg.method) ?? []) fn(msg.params ?? {})
        }
      }
    })
  }

  on(method: string, fn: (p: Record<string, unknown>) => void) {
    const arr = this.listeners.get(method) ?? []
    arr.push(fn)
    this.listeners.set(method, arr)
  }

  send<T = Record<string, unknown>>(
    method: string,
    params: Record<string, unknown> = {},
    opts?: { browserLevel?: boolean },
  ): Promise<T> {
    const id = this.nextId++
    const payload: Record<string, unknown> = { id, method, params }
    if (!opts?.browserLevel && this.sessionId) payload.sessionId = this.sessionId
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve: resolve as (v: unknown) => void, reject })
      this.ws.send(JSON.stringify(payload))
    })
  }

  async eval<T = unknown>(expression: string): Promise<T> {
    const res = await this.send<{
      result?: { value?: T }
      exceptionDetails?: { text?: string; exception?: { description?: string } }
    }>('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true })
    if (res.exceptionDetails) {
      throw new Error(
        `Page eval error: ${res.exceptionDetails.exception?.description ?? res.exceptionDetails.text ?? 'unknown'}`,
      )
    }
    return res.result?.value as T
  }

  close() {
    try {
      this.ws?.close()
    } catch {}
  }
}

async function waitFor<T>(fn: () => Promise<T | false | null | undefined>, desc: string, timeoutMs = 95_000): Promise<T> {
  const t0 = Date.now()
  let lastErr: unknown = null
  while (Date.now() - t0 < timeoutMs) {
    try {
      const val = await fn()
      if (val) return val
    } catch (e) {
      lastErr = e
    }
    await sleep(350)
  }
  throw new Error(`Timed out waiting for: ${desc}${lastErr ? ` (lastErr: ${String(lastErr)})` : ''}`)
}

async function clickButton(cdp: CdpClient, textMatch: string, selector = 'button'): Promise<string> {
  const clicked = await cdp.eval<string | null>(`(() => {
    const els = Array.from(document.querySelectorAll(${JSON.stringify(selector)}));
    const needle = ${JSON.stringify(textMatch)}.toLowerCase();
    const el = els.find((b) => !b.disabled && (b.textContent || '').trim().toLowerCase().includes(needle));
    if (!el) return null;
    el.scrollIntoView({ block: 'center', behavior: 'instant' });
    el.click();
    return (el.textContent || '').trim().replace(/\\s+/g, ' ');
  })()`)
  if (!clicked) throw new Error(`Button containing "${textMatch}" (${selector}) not found or disabled`)
  return clicked
}

async function setInput(cdp: CdpClient, selector: string, value: string): Promise<void> {
  const ok = await cdp.eval<boolean>(`(() => {
    const el = document.querySelector(${JSON.stringify(selector)});
    if (!el) return false;
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(el, ${JSON.stringify(value)});
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  })()`)
  assert.ok(ok, `Input ${selector} not found`)
}

async function screenshot(cdp: CdpClient, name: string) {
  const { data } = await cdp.send<{ data: string }>('Page.captureScreenshot', { format: 'png' })
  writeFileSync(`${SCREENSHOT_DIR}/${name}`, Buffer.from(data, 'base64'))
  console.log(`  📸 ${SCREENSHOT_DIR}/${name}`)
}

async function getVaultState(cdp: CdpClient) {
  return cdp.eval<{
    errorText: string | null
    busyText: string | null
    privateSub: string
    scanReady: boolean
    noteCount: number
    auditCount: number
    latestAudit: {
      kicker: string
      summary: string
      solscanUrl: string
      proofText: string
    } | null
    mergeButtons: string[]
    relayerActiveBadge: string | null
  }>(`(() => {
    const err = document.querySelector('.lv-error-bar')?.textContent?.trim() || null;
    const busy = Array.from(document.querySelectorAll('.lv-submit-btn'))
      .map((b) => b.textContent?.trim() || '')
      .find((t) => t.includes('…') || t.includes('Sending') || t.includes('Creating') || t.includes('Fetching') || t.includes('Confirming')) || null;
    const privateSub = document.querySelector('.lv-private-sub-amt')?.textContent?.trim() || '';
    const noteRows = Array.from(document.querySelectorAll('.lv-private-row'));
    const noteCount = noteRows.length;
    const refresh = Array.from(document.querySelectorAll('button.lv-mini-btn')).find(b => b.textContent.trim() === 'REFRESH');
    const scanReady = Boolean(refresh && !refresh.disabled && privateSub && !err && !busy && !/Scanning|Checking|Verifying|failed/i.test(privateSub) && noteRows.every(row => {
      const amount = row.querySelector('.lv-balance-amt')?.textContent.trim() || '';
      if (parseFloat(amount) === 0) return true;
      const send = Array.from(row.querySelectorAll('button')).find(b => b.textContent.trim() === 'Private Send');
      return Boolean(send && !send.disabled);
    }));
    const cards = Array.from(document.querySelectorAll('.lv-audit-card'));
    const first = cards[0];
    const latestAudit = first ? {
      kicker: first.querySelector('.kicker')?.textContent?.trim() || '',
      summary: first.querySelector('h4')?.textContent?.trim() || '',
      solscanUrl: first.querySelector('a[href*="solscan.io/tx/"]')?.getAttribute('href') || '',
      proofText: first.querySelector('.lv-onchain-proof')?.textContent?.trim().replace(/\\s+/g, ' ') || '',
    } : null;
    const mergeButtons = Array.from(document.querySelectorAll('.lv-merge-bar button')).map((b) => b.textContent?.trim() || '');
    const relayerActiveBadge = Array.from(document.querySelectorAll('.lv-mode-top span'))[0]?.textContent?.trim() || null;
    return { errorText: err, busyText: busy, privateSub, scanReady, noteCount, auditCount: cards.length, latestAudit, mergeButtons, relayerActiveBadge };
  })()`)
}

// Read the visible receipt identifier, never wallet internals or spending keys.
// Test-owned DOM annotations let later actions target that exact page/slot row.
async function identifyAuditNotes(cdp: CdpClient): Promise<Array<{ key: string; amount: string }>> {
  await waitFor(async () => (await getVaultState(cdp)).scanReady, 'Verified private vault before note inventory')
  const count = await cdp.eval<number>(`document.querySelectorAll('.lv-private-row').length`)
  const notes: Array<{ key: string; amount: string }> = []
  for (let index = 0; index < count; index++) {
    await cdp.eval(`(() => {
      const row = document.querySelectorAll('.lv-private-row')[${index}];
      const receipt = Array.from(row.querySelectorAll('button')).find(b => b.textContent.trim() === 'Receipt');
      if (!receipt) throw new Error('Expected a receipt control for every audit note');
      if (!row.querySelector('.lv-receipt-drawer')) receipt.click();
    })()`)
    const note = await waitFor(() => cdp.eval<{ key: string; amount: string } | false>(`(() => {
      const row = document.querySelectorAll('.lv-private-row')[${index}];
      const match = row?.querySelector('.lv-receipt-head')?.textContent.match(/PAGE #([0-9]+) SLOT #([0-9]+)/);
      if (!match) return false;
      const key = match[1] + ':' + match[2];
      row.dataset.auditNoteKey = key;
      return { key, amount: row.querySelector('.lv-balance-amt')?.textContent.trim() || '' };
    })()`), `Identify private note ${index}`)
    notes.push(note)
    await cdp.eval(`(() => {
      const row = document.querySelectorAll('.lv-private-row')[${index}];
      Array.from(row.querySelectorAll('button')).find(b => b.textContent.trim() === 'Receipt').click();
    })()`)
    await waitFor(() => cdp.eval<boolean>(`!document.querySelectorAll('.lv-private-row')[${index}]?.querySelector('.lv-receipt-drawer')`), 'Close inspected receipt')
  }
  assert.equal(new Set(notes.map(note => note.key)).size, count, 'Duplicate receipt identifiers')
  return notes
}

async function clickAuditNote(cdp: CdpClient, key: string, action: string) {
  const clicked = await cdp.eval<boolean>(`(() => {
    const row = Array.from(document.querySelectorAll('.lv-private-row')).find(r => r.dataset.auditNoteKey === ${JSON.stringify(key)});
    const button = row && Array.from(row.querySelectorAll('.lv-private-row-actions button')).find(b => b.textContent.trim() === ${JSON.stringify(action)});
    if (!button || button.disabled) return false;
    button.click(); return true;
  })()`)
  assert.ok(clicked, `Expected ${action} on this audit's note ${key}`)
}

async function submitAuditNote(cdp: CdpClient, key: string, amount: string, kind: 'xfer' | 'wd', expected: Array<{ key: string; amount: string }>) {
  assert.ok((await getVaultState(cdp)).scanReady, 'Vault must be settled before audit submission')
  const expectedRows = expected.map(note => `${note.key}=${note.amount}`).sort()
  const result = await cdp.eval<string>(`(() => {
    const rows = Array.from(document.querySelectorAll('.lv-private-row'));
    const current = rows.map(row => row.dataset.auditNoteKey + '=' + (row.querySelector('.lv-balance-amt')?.textContent.trim() || '')).sort();
    if (JSON.stringify(current) !== ${JSON.stringify(JSON.stringify(expectedRows))}) return 'Private note inventory changed';
    const spendable = rows.filter(row => Array.from(row.querySelectorAll('.lv-private-row-actions button')).some(b => b.textContent.trim() === 'Private Send' && !b.disabled));
    const select = document.querySelector('#lv-${kind}-note');
    if (!select || spendable[Number(select.value)]?.dataset.auditNoteKey !== ${JSON.stringify(key)}) return 'Selected note does not match audit ID';
    if (document.querySelector('#lv-${kind}-amt')?.value !== ${JSON.stringify(amount)}) return 'Unexpected submit amount';
    const self = Array.from(document.querySelectorAll('.lv-chip-btn.is-active')).some(b => ${kind === 'xfer' ? "b.textContent.includes('Send to Myself')" : "b.textContent.includes('Back to My')"});
    if (!self) return 'Self recipient is not selected';
    const refresh = Array.from(document.querySelectorAll('button.lv-mini-btn')).find(b => b.textContent.trim() === 'REFRESH');
    if (!refresh || refresh.disabled || document.querySelector('.lv-error-bar')) return 'Vault changed before submit';
    const button = Array.from(document.querySelectorAll('.lv-submit-btn')).find(b => b.textContent.includes(${JSON.stringify(kind === 'xfer' ? `Send ${amount} SOL Privately` : 'Go Public with')}));
    if (!button || button.disabled) return 'Submit is unavailable';
    button.click(); return 'submitted';
  })()`)
  assert.equal(result, 'submitted', `Refused audit submit: ${result}`)
}

async function verifyRpcTx(rpcUrl: string, sig: string, expectedSigner: string, userWallet: string, expectUserAbsent: boolean) {
  for (let i = 0; i < 12; i++) {
    const res = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'getTransaction',
        params: [sig, { encoding: 'jsonParsed', commitment: 'confirmed', maxSupportedTransactionVersion: 1 }],
      }),
    })
    const j = (await res.json()) as {
      result?: {
        version?: number | string
        transaction?: { message?: { accountKeys?: Array<string | { pubkey: string; signer?: boolean }> } }
        meta?: { err?: unknown; loadedAddresses?: { writable?: string[]; readonly?: string[] } }
      } | null
    }
    if (j.result?.transaction?.message?.accountKeys) {
      assert.equal(j.result.meta?.err ?? null, null, `Tx ${sig} had on-chain err`)
      const ks = j.result.transaction.message.accountKeys
      const signers = ks.filter((k): k is { pubkey: string; signer?: boolean } => typeof k !== 'string' && Boolean(k.signer)).map((k) => k.pubkey)
      const allKeys = [
        ...ks.map((k) => (typeof k === 'string' ? k : k.pubkey)),
        ...(j.result.meta?.loadedAddresses?.writable ?? []),
        ...(j.result.meta?.loadedAddresses?.readonly ?? []),
      ]
      assert.ok(signers.includes(expectedSigner), `Expected signer ${expectedSigner}, got ${signers.join(',')}`)
      const present = allKeys.includes(userWallet)
      if (expectUserAbsent) {
        assert.equal(present, false, `PRIVACY LEAK: user wallet ${userWallet} appeared in ${sig}!`)
      }
      console.log(`  ✓ RPC VERIFIED (${sig.slice(0, 10)}…): v${j.result.version}, signer=${signers[0]?.slice(0, 8)}…, userWalletPresent=${present}`)
      return
    }
    await sleep(600)
  }
  throw new Error(`Could not fetch tx ${sig} from RPC`)
}

function walletBridgeInitScript(pubkeyBytes: number[], addressB58: string) {
  return `(() => {
    if (window.__AUDREN_WALLET_INSTALLED__) return;
    window.__AUDREN_WALLET_INSTALLED__ = true;
    const pubkey = new Uint8Array(${JSON.stringify(pubkeyBytes)});
    const account = {
      address: ${JSON.stringify(addressB58)},
      publicKey: pubkey,
      chains: ['solana:mainnet', 'solana:devnet'],
      features: ['standard:connect', 'standard:disconnect', 'solana:signMessage', 'solana:signTransaction'],
    };
    let reqSeq = 1;
    const pending = new Map();
    window.__audrenResolveWallet = (id, res, err) => {
      const p = pending.get(id);
      if (!p) return;
      pending.delete(id);
      if (err) p.reject(new Error(err));
      else p.resolve(res);
    };
    const callNode = (type, payload) => new Promise((resolve, reject) => {
      const id = reqSeq++;
      pending.set(id, { resolve, reject });
      window.__audrenWalletBridge(JSON.stringify({ id, type, payload }));
    });
    const toB64 = (u8) => { let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s); };
    const fromB64 = (b64) => { const s = atob(b64); const u = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i); return u; };
    const wallet = {
      version: '1.0.0',
      name: 'Phantom',
      icon: 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIvPg==',
      chains: ['solana:mainnet', 'solana:devnet'],
      accounts: [account],
      features: {
        'standard:connect': { version: '1.0.0', connect: async () => ({ accounts: [account] }) },
        'standard:disconnect': { version: '1.0.0', disconnect: async () => {} },
        'standard:events': { version: '1.0.0', on: () => () => {} },
        'solana:signMessage': {
          version: '1.0.0',
          signMessage: async (...inputs) => {
            const out = [];
            for (const inp of inputs) {
              const sigB64 = await callNode('signMessage', { messageB64: toB64(inp.message) });
              out.push({ signedMessage: inp.message, signature: fromB64(sigB64) });
            }
            return out;
          },
        },
        'solana:signTransaction': {
          version: '1.0.0',
          supportedTransactionVersions: ['legacy', 0],
          signTransaction: async (...inputs) => {
            const signedB64s = await callNode('signTransaction', { txsB64: inputs.map((i) => toB64(i.transaction)) });
            return signedB64s.map((b64) => ({ signedTransaction: fromB64(b64) }));
          },
        },
      },
    };
    const registerAll = () => {
      try {
        window.dispatchEvent(new CustomEvent('wallet-standard:register-wallet', {
          detail: Object.freeze((api) => api.register(wallet)),
        }));
      } catch {}
    };
    window.addEventListener('wallet-standard:app-ready', (ev) => {
      try { ev.detail?.register?.(wallet); } catch {}
    });
    window.addEventListener('DOMContentLoaded', registerAll);
    setTimeout(registerAll, 50);
  })();`
}

async function main() {
  const tStart = Date.now()
  const signer = loadSigner()
  mkdirSync(SCREENSHOT_DIR, { recursive: true })
  if (existsSync(USER_DATA_DIR)) rmSync(USER_DATA_DIR, { recursive: true, force: true })

  let chrome: ChildProcess | null = null
  let cdp: CdpClient | null = null
  const consoleErrors: string[] = []
  const pageExceptions: string[] = []
  const failedRequests: string[] = []
  let allowExpectedCustomRelayFailure = false
  let signedMsgCount = 0
  let signedTxCount = 0

  try {
    chrome = spawn(CHROME_PATH, [
      '--headless=new',
      `--remote-debugging-port=${CDP_PORT}`,
      `--user-data-dir=${USER_DATA_DIR}`,
      '--no-first-run',
      '--no-default-browser-check',
      '--window-size=1360,960',
      'about:blank',
    ], { stdio: 'ignore' })

    const wsUrl = await waitFor(async () => {
      const r = await fetch(`http://127.0.0.1:${CDP_PORT}/json/version`)
      if (!r.ok) return false
      return ((await r.json()) as { webSocketDebuggerUrl?: string }).webSocketDebuggerUrl ?? false
    }, 'Chrome CDP ready', 15_000)

    cdp = new CdpClient()
    await cdp.connect(wsUrl)
    const { targetId } = await cdp.send<{ targetId: string }>('Target.createTarget', { url: 'about:blank' }, { browserLevel: true })
    const { sessionId } = await cdp.send<{ sessionId: string }>('Target.attachToTarget', { targetId, flatten: true }, { browserLevel: true })
    cdp.sessionId = sessionId

    await cdp.send('Page.enable')
    await cdp.send('Runtime.enable')
    await cdp.send('Network.enable')
    await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1360, height: 960, deviceScaleFactor: 1, mobile: false })
    await cdp.send('Runtime.addBinding', { name: '__audrenWalletBridge' })
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
      source: walletBridgeInitScript(Array.from(signer.pubkey), signer.address),
    })

    cdp.on('Runtime.bindingCalled', async (params) => {
      if (params.name !== '__audrenWalletBridge') return
      const req = JSON.parse(String(params.payload)) as { id: number; type: string; payload: { messageB64?: string; txsB64?: string[] } }
      try {
        if (req.type === 'signMessage') {
          signedMsgCount++
          const msg = Buffer.from(req.payload.messageB64!, 'base64')
          const sig = ed25519.sign(msg, signer.secret32)
          await cdp!.eval(`window.__audrenResolveWallet(${req.id}, ${JSON.stringify(Buffer.from(sig).toString('base64'))}, null)`)
        } else if (req.type === 'signTransaction') {
          const txs = req.payload.txsB64 ?? []
          signedTxCount += txs.length
          console.log(`  ✍️  Phantom signed ${txs.length} tx(s) (total signed=${signedTxCount})`)
          const signed = txs.map((b64) => Buffer.from(signWireTransaction(signer.secret32, Buffer.from(b64, 'base64'))).toString('base64'))
          await cdp!.eval(`window.__audrenResolveWallet(${req.id}, ${JSON.stringify(signed)}, null)`)
        }
      } catch (e) {
        await cdp!.eval(`window.__audrenResolveWallet(${req.id}, null, ${JSON.stringify(String(e))})`)
      }
    })

    cdp.on('Runtime.consoleAPICalled', (p) => {
      if (p.type === 'error') {
        const text = ((p.args as Array<{ value?: string; description?: string }>) ?? []).map((a) => a.value ?? a.description ?? '').join(' ')
        if (allowExpectedCustomRelayFailure && text.includes('nonexistent.invalid')) return
        consoleErrors.push(text)
      }
    })
    cdp.on('Runtime.exceptionThrown', (p) => {
      const d = p.exceptionDetails as { text?: string; exception?: { description?: string } }
      pageExceptions.push(d?.exception?.description ?? d?.text ?? 'exception')
    })
    cdp.on('Network.responseReceived', (p) => {
      const resp = p.response as { url?: string; status?: number }
      if ((resp.status ?? 200) >= 400 && !resp.url?.includes('nonexistent.invalid')) {
        failedRequests.push(`HTTP ${resp.status} ${resp.url}`)
      }
    })

    // =========================================================================
    // PART 1: AUDIT PUBLIC PAGES & PRIVACY ILLUSTRATIONS
    // =========================================================================
    banner('PART 1: Public Pages + Privacy Illustrations')
    for (const route of ['/', '/how-it-works', '/compare', '/developers', '/architecture', '/faq', '/privacy', '/terms']) {
      await cdp.send('Page.navigate', { url: `${BASE_URL}${route}` })
      await waitFor(() => cdp!.eval<boolean>(`document.readyState === 'complete' && (document.body?.innerText?.length || 0) > 200`), `route ${route}`)
      const title = await cdp.eval<string>(`document.title`)
      console.log(`  ✓ ${route} loaded ("${title}")`)
    }

    await cdp.send('Page.navigate', { url: `${BASE_URL}/` })
    await waitFor(() => cdp!.eval<boolean>(`document.querySelectorAll('[aria-label="What you can do inside the ring"] button').length === 4`), 'Homepage use cases')
    for (const label of ['Pay someone', 'Swap on DEX', 'Pay public wallet', 'Share 1 receipt']) {
      await clickButton(cdp, label, '[aria-label="What you can do inside the ring"] button')
      await waitFor(() => cdp!.eval<boolean>(`document.querySelector('[aria-label="What you can do inside the ring"] [aria-selected="true"]')?.textContent?.includes(${JSON.stringify(label)})`), `Selected ${label}`)
      const boundary = await cdp.eval<string>(`document.querySelector('#use-cases')?.textContent || ''`)
      assert.ok(boundary.includes('CONCEALED') && boundary.includes('PUBLIC'), 'Use-case diagram must show concealed vs. public boundary')
    }
    await cdp.send('Page.navigate', { url: `${BASE_URL}/how-it-works/` })
    await waitFor(() => cdp!.eval<boolean>(`document.querySelectorAll('.flow-tab-btn').length === 4`), 'Landing animated flows')

    // Verify reusable aud1… address anatomy + all 4 animated privacy flows + soundness matrix
    const addrText = await cdp.eval<string>(`document.querySelector('.aud-addr-card')?.textContent || ''`)
    assert.ok(addrText.includes('aud1') && addrText.includes('SPEND PUBLIC KEY') && addrText.includes('VIEW PUBLIC KEY'), 'aud1 address anatomy missing')
    await cdp.eval(`document.querySelector('#how-it-works')?.scrollIntoView({ behavior: 'instant', block: 'start' })`)
    await sleep(200)
    for (const flowLabel of ['Public → Private', 'Private → Private', 'Private DEX Swap', 'Prove Receipt / Exit']) {
      await clickButton(cdp, flowLabel, '.flow-tab-btn')
      await sleep(160)
      const theaterText = await cdp.eval<string>(`document.querySelector('.flow-theater')?.textContent || ''`)
      assert.ok(theaterText.includes('WHAT A STRANGER SEES ON SOLSCAN'), `Flow "${flowLabel}" missing Solscan visibility pane`)
      console.log(`  ✓ Animated Flow "${flowLabel}" verified`)
    }
    await clickButton(cdp, 'Private → Private', '.flow-tab-btn')
    await sleep(180)
    await cdp.eval(`document.querySelectorAll('.flow-node')[2]?.click()`)
    await sleep(260)
    await cdp.eval(`document.querySelector('.flow-theater')?.scrollIntoView({ behavior: 'instant', block: 'center' })`)
    await sleep(180)
    await screenshot(cdp, 'part1-animated-flows.png')

    await cdp.eval(`document.querySelector('#security')?.scrollIntoView({ behavior: 'instant', block: 'start' })`)
    await sleep(200)
    const soundnessCount = await cdp.eval<number>(`document.querySelectorAll('.soundness-cell').length`)
    assert.equal(soundnessCount, 6, `Expected 6 cryptographic soundness pillars, got ${soundnessCount}`)
    console.log(`  ✓ Cryptographic Soundness Matrix verified (${soundnessCount} pillars)`)
    await screenshot(cdp, 'part1-soundness.png')

    await cdp.send('Page.navigate', { url: `${BASE_URL}/developers/` })
    await waitFor(() => cdp!.eval<boolean>(`document.body.innerText.includes('TypeScript') && document.body.innerText.includes('Rust') && document.body.innerText.includes('Swift') && document.body.innerText.includes('Kotlin')`), '4-language Developer SDK scope')
    const developerText = await cdp.eval<string>(`document.body.innerText`)
    assert.ok(developerText.includes('spec/test-vectors.json'), 'Developers page must reference canonical conformance vectors')
    assert.ok(!developerText.includes('npm install @audren/sdk'), 'Unpublished registry package advertised')
    await screenshot(cdp, 'part1-developers.png')

    // =========================================================================
    // PART 2: FULL DEVNET WALLET VAULT PARITY (Relayer + Receipt + Custom Relay + Direct!)
    // =========================================================================
    banner('PART 2: LIVE DEVNET WALLET VAULT — FULL PARITY (Devnet RPC + relay.audren.xyz)')
    await cdp.send('Page.navigate', { url: `${BASE_URL}/demo/` })
    await waitFor(() => cdp!.eval<boolean>(`Array.from(document.querySelectorAll('button')).some((b) => (b.textContent || '').includes('Phantom'))`), 'Phantom connect button')
    await clickButton(cdp, 'Phantom')
    await waitFor(() => cdp!.eval<boolean>(`Array.from(document.querySelectorAll('button')).some((b) => (b.textContent || '').includes('DEVNET'))`), 'DEVNET toggle')
    await clickButton(cdp, 'DEVNET')
    await sleep(1500)
    await waitFor(() => cdp!.eval<boolean>(`Array.from(document.querySelectorAll('button')).some((b) => (b.textContent || '').includes('Unlock Private Balance'))`), 'Unlock button on Devnet')
    await clickButton(cdp, 'Unlock Private Balance')
    await waitFor(() => cdp!.eval<boolean>(`(document.querySelector('.lv-addr-row code')?.textContent?.trim() || '').startsWith('aud1')`), 'Devnet Private Address')
    await sleep(2000)
    await waitFor(async () => {
      const st = await getVaultState(cdp!)
      if (st.errorText || st.privateSub.includes('failed')) throw new Error(st.errorText || st.privateSub)
      return st.scanReady ? st : false
    }, 'Devnet initial vault scan')

    assert.equal((await getVaultState(cdp)).noteCount, 0, 'Live audit requires an empty Devnet private vault; refusing to touch existing notes')

    // Step 2A: Devnet Go Private (0.01 SOL Native SOL)
    console.log('\n--- 2A. Devnet Go Private (0.01 SOL) ---')
    await setInput(cdp, '#lv-shield-amt', '0.01')
    const depBefore = (await getVaultState(cdp)).auditCount
    await clickButton(cdp, 'Go Private with', '.lv-submit-btn')
    const afterDevDep = await waitFor(async () => {
      const st = await getVaultState(cdp!)
      if (st.errorText) throw new Error(st.errorText)
      return st.auditCount > depBefore && !st.busyText && st.latestAudit?.proofText.includes('LIVE ON-CHAIN VERIFICATION') ? st : false
    }, 'Devnet Go Private + Live On-Chain Verification strip', 90_000)
    assert.equal(afterDevDep.noteCount, 1, 'Unexpected private notes during this audit; refusing to select unrelated notes')
    console.log(`  ✓ Devnet Deposit confirmed: ${afterDevDep.latestAudit?.summary}`)
    console.log(`  ✓ On-screen proof: ${afterDevDep.latestAudit?.proofText}`)
    assert.ok(afterDevDep.latestAudit?.proofText.includes('YOUR WALLET ON TX: SIGNER'), 'Expected SIGNER on Deposit proof')

    // Step 2B: Devnet Selective Disclosure Viewing Receipt (Real ✓ + Forged ✕)
    console.log('\n--- 2B. Devnet Selective Disclosure Viewing Receipt ---')
    await clickButton(cdp, 'Receipt', '.lv-private-row-actions button')
    await waitFor(() => cdp!.eval<boolean>(`Boolean(document.querySelector('.lv-receipt-drawer'))`), 'Receipt drawer open')
    await clickButton(cdp, 'Verify Real Receipt Against Solana', '.lv-receipt-actions button')
    const realVerdict = await waitFor(
      () => cdp!.eval<string | false>(`(() => { const el = document.querySelector('.lv-receipt-verdict.is-valid'); return el ? el.textContent.trim() : false; })()`),
      'Real receipt VERIFIED BY SOLANA',
    )
    console.log(`  ✓ Real Receipt: ${realVerdict}`)
    await screenshot(cdp, 'part2b-devnet-receipt-verified.png')

    await clickButton(cdp, 'Test Tampered Amount', '.lv-receipt-actions button')
    const forgedVerdict = await waitFor(
      () => cdp!.eval<string | false>(`(() => { const el = document.querySelector('.lv-receipt-verdict.is-forged'); return el ? el.textContent.trim() : false; })()`),
      'Forged receipt FORGERY CAUGHT',
    )
    console.log(`  ✓ Forged Receipt: ${forgedVerdict}`)
    await clickButton(cdp, 'Receipt', '.lv-private-row-actions button') // close drawer

    // Step 2C: Devnet Private Send (0.004 SOL) via relay.audren.xyz Devnet Relayer (0 Phantom popups!)
    console.log('\n--- 2C. Devnet Private Send via relay.audren.xyz (0 Phantom popups) ---')
    const signedBeforeSend = signedTxCount
    await clickButton(cdp, 'Private Send', '.lv-private-row-actions button')
    await setInput(cdp, '#lv-xfer-amt', '0.004')
    await clickButton(cdp, 'Send 0.004 SOL Privately', '.lv-submit-btn')
    const afterDevSend = await waitFor(async () => {
      const st = await getVaultState(cdp!)
      if (st.errorText) throw new Error(st.errorText)
      return st.auditCount > afterDevDep.auditCount && !st.busyText && st.latestAudit?.proofText.includes('YOUR WALLET ON TX:') ? st : false
    }, 'Devnet Relayed Private Send + On-Chain Verification strip', 90_000)
    assert.equal(signedTxCount, signedBeforeSend, 'Expected 0 Phantom signatures for relayed Devnet Send!')
    assert.equal(afterDevSend.noteCount, 2, 'Unexpected private notes during this audit; refusing to select unrelated notes')
    console.log(`  ✓ Devnet Private Send: ${afterDevSend.latestAudit?.summary}`)
    console.log(`  ✓ On-screen proof: ${afterDevSend.latestAudit?.proofText}`)
    assert.ok(afterDevSend.latestAudit?.proofText.includes('YOUR WALLET ON TX: ABSENT'), 'Expected ABSENT on Relayed Devnet Send!')
    const sendSig = afterDevSend.latestAudit!.solscanUrl.split('/tx/')[1]!.split('?')[0]!
    await verifyRpcTx(DEVNET_QN_RPC, sendSig, RELAYER_DEVNET, signer.address, true)
    await screenshot(cdp, 'part2c-devnet-relayed-send-proof.png')
    await sleep(3_000) // devnet cooldown is 2s

    // Step 2D: Devnet Combine Notes (2 -> 1) via relay.audren.xyz Devnet Relayer
    console.log('\n--- 2D. Devnet Combine Notes via relay.audren.xyz (0 Phantom popups) ---')
    const signedBeforeMerge = signedTxCount
    await clickButton(cdp, 'Combine 2 of', '.lv-merge-bar button')
    const afterDevMerge = await waitFor(async () => {
      const st = await getVaultState(cdp!)
      if (st.errorText) throw new Error(st.errorText)
      return st.auditCount > afterDevSend.auditCount && !st.busyText && st.latestAudit?.proofText.includes('YOUR WALLET ON TX:') ? st : false
    }, 'Devnet Relayed Combine Notes + On-Chain Proof', 90_000)
    assert.equal(signedTxCount, signedBeforeMerge, 'Expected 0 Phantom signatures for relayed Devnet Merge!')
    assert.equal(afterDevMerge.noteCount, 1, 'Unexpected private notes during this audit; refusing to select unrelated notes')
    console.log(`  ✓ Devnet Combine Notes: ${afterDevMerge.latestAudit?.summary}`)
    console.log(`  ✓ On-screen proof: ${afterDevMerge.latestAudit?.proofText}`)
    assert.ok(afterDevMerge.latestAudit?.proofText.includes('YOUR WALLET ON TX: ABSENT'), 'Expected ABSENT on Relayed Devnet Merge!')

    // Step 2E: Devnet Private Swap tab (must be clean Mainnet-only notice, 0 errors!)
    console.log('\n--- 2E. Devnet Private Swap tab graceful check ---')
    await clickButton(cdp, 'Private Swap', '.lv-verb-tab')
    const swapNotice = await cdp.eval<string>(`document.querySelector('.lv-empty-action')?.textContent?.trim() || ''`)
    assert.ok(swapNotice.includes('Switch to Mainnet'), `Expected graceful Mainnet notice on Devnet Swap tab, got: ${swapNotice}`)
    console.log(`  ✓ Devnet Swap tab clean: "${swapNotice.slice(0, 90)}"`)

    // Step 2F: Custom Relayer URL UX ("Use Your Own Relay")
    console.log('\n--- 2F. Custom Relayer URL UX ("Use Your Own Relay") ---')
    await clickButton(cdp, 'Private Send', '.lv-verb-tab')
    await clickButton(cdp, 'ADVANCED OPTIONS', '.lv-adv-toggle')
    await clickButton(cdp, 'USE YOUR OWN RELAY', '.lv-custom-relay button')
    await setInput(cdp, '.lv-custom-relay-form input', 'http://evil-relay.example.com')
    await clickButton(cdp, 'Apply', '.lv-custom-relay-form button')
    const badUrlErr = await waitFor(
      () => cdp!.eval<string | false>(`document.querySelector('.lv-custom-relay-err')?.textContent?.trim() || false`),
      'Custom relay invalid URL error',
    )
    console.log(`  ✓ Non-HTTPS custom relay blocked cleanly: "${badUrlErr}"`)

    allowExpectedCustomRelayFailure = true
    await setInput(cdp, '.lv-custom-relay-form input', 'https://nonexistent.invalid')
    await clickButton(cdp, 'Apply', '.lv-custom-relay-form button')
    const offlineErr = await waitFor(
      () => cdp!.eval<string | false>(`(() => { const t = document.querySelector('.lv-custom-relay-err')?.textContent?.trim() || ''; return t.includes('Could not reach') ? t : false; })()`),
      'Unreachable custom relay graceful error',
    )
    allowExpectedCustomRelayFailure = false
    console.log(`  ✓ Unreachable custom relay handled gracefully: "${offlineErr}"`)
    await clickButton(cdp, 'Reset Default', '.lv-custom-relay-form button')
    await waitFor(
      () => cdp!.eval<boolean>(`(document.querySelectorAll('.lv-mode-top span')[0]?.textContent || '').includes('ACTIVE · relay.audren.xyz')`),
      'Reset back to relay.audren.xyz ACTIVE',
    )
    console.log(`  ✓ Reset Default restored ACTIVE · relay.audren.xyz`)
    await screenshot(cdp, 'part2f-custom-relayer-controls.png')

    // Step 2G: Direct Self-Pay Mode (NO Relayer!) on Devnet -> Private Send + Relayed Withdraw cleanup
    console.log('\n--- 2G. Devnet Direct Self-Pay Mode (NO Relayer) ---')
    await clickButton(cdp, 'Your Wallet (Direct)', '.lv-mode-card')
    await setInput(cdp, '#lv-xfer-amt', '0.003')
    const signedBeforeDirect = signedTxCount
    await clickButton(cdp, 'Send 0.003 SOL Privately', '.lv-submit-btn')
    const afterDevDirect = await waitFor(async () => {
      const st = await getVaultState(cdp!)
      if (st.errorText) throw new Error(st.errorText)
      return st.auditCount > afterDevMerge.auditCount && !st.busyText && st.latestAudit?.proofText.includes('YOUR WALLET ON TX:') ? st : false
    }, 'Devnet Direct-Mode Private Send', 120_000)
    assert.ok(signedTxCount > signedBeforeDirect, 'Direct Mode must be signed by user wallet!')
    assert.equal(afterDevDirect.noteCount, 2, 'Unexpected private notes during this audit; refusing to select unrelated notes')
    console.log(`  ✓ Devnet Direct Send confirmed: ${afterDevDirect.latestAudit?.summary}`)
    console.log(`  ✓ On-screen proof: ${afterDevDirect.latestAudit?.proofText}`)
    assert.ok(afterDevDirect.latestAudit?.proofText.includes('YOUR WALLET ON TX: SIGNER'), 'Direct Mode must show SIGNER!')

    // Switch back to Relayer and Go Public Withdraw ONLY the 2 Devnet test SOL notes (never touch unrelated notes)
    await clickButton(cdp, 'Privacy Relayer', '.lv-mode-card')
    for (const expectedAmt of ['0.007 SOL', '0.003 SOL']) {
      await sleep(3_000)
      const prevAudits = (await getVaultState(cdp)).auditCount
      const clicked = await cdp.eval<boolean>(`(() => {
        const row = Array.from(document.querySelectorAll('.lv-private-row')).find((r) => (r.textContent || '').includes(${JSON.stringify(expectedAmt)}));
        const btn = row && Array.from(row.querySelectorAll('.lv-private-row-actions button')).find((b) => (b.textContent || '').includes('Go Public'));
        if (!btn) return false;
        btn.click();
        return true;
      })()`)
      assert.ok(clicked, `Expected Devnet test note "${expectedAmt}" to withdraw`)
      await clickButton(cdp, 'Go Public with', '.lv-submit-btn')
      const afterWd = await waitFor(async () => {
        const st = await getVaultState(cdp!)
        if (st.errorText) throw new Error(st.errorText)
        return st.auditCount > prevAudits && !st.busyText && st.latestAudit?.proofText.includes('YOUR WALLET ON TX:') ? st : false
      }, `Devnet Relayed Go Public Withdraw (${expectedAmt})`, 90_000)
      console.log(`  ✓ Devnet Relayed Withdraw: ${afterWd.latestAudit?.summary} | ${afterWd.latestAudit?.proofText}`)
      assert.ok(afterWd.latestAudit?.proofText.includes('RECIPIENT ONLY (NOT SIGNER)'), 'Relayed Withdraw to self must show RECIPIENT ONLY (NOT SIGNER)!')
    }

    // =========================================================================
    // PART 3: LIVE MAINNET — Direct Mode + Selective Disclosure Receipt + On-Screen Proof
    // =========================================================================
    banner('PART 3: LIVE MAINNET — Deposit + Selective Disclosure Receipt + Direct Self-Pay + Withdraw')
    await clickButton(cdp, 'MAINNET')
    await sleep(2500)
    await waitFor(async () => {
      const st = await getVaultState(cdp!)
      if (st.errorText || st.privateSub.includes('failed')) throw new Error(st.errorText || st.privateSub)
      return st.scanReady ? st : false
    }, 'Mainnet vault scan')

    const mainnetBefore = await identifyAuditNotes(cdp)
    const mainnetRepeated = await identifyAuditNotes(cdp)
    assert.deepEqual(mainnetRepeated, mainnetBefore, 'Mainnet baseline changed while inventorying')
    const mainnetExisting = new Set(mainnetBefore.map(note => note.key))

    // Go Private 0.005 SOL on Mainnet
    await clickButton(cdp, 'Go Private', '.lv-verb-tab')
    await setInput(cdp, '#lv-shield-amt', '0.005')
    const mainAudit0 = (await getVaultState(cdp)).auditCount
    await clickButton(cdp, 'Go Private with', '.lv-submit-btn')
    const afterMainDep = await waitFor(async () => {
      const st = await getVaultState(cdp!)
      if (st.errorText) throw new Error(st.errorText)
      return st.auditCount > mainAudit0 && !st.busyText && st.latestAudit?.proofText.includes('LIVE ON-CHAIN VERIFICATION') ? st : false
    }, 'Mainnet Go Private 0.005 SOL', 90_000)
    assert.equal(afterMainDep.noteCount, mainnetBefore.length + 1, 'Unexpected private notes during this audit; refusing to select unrelated notes')
    console.log(`  ✓ Mainnet Deposit confirmed: ${afterMainDep.latestAudit?.summary}`)
    console.log(`  ✓ On-screen proof: ${afterMainDep.latestAudit?.proofText}`)

    const mainnetDeposited = await identifyAuditNotes(cdp)
    assert.ok(mainnetBefore.every(note => mainnetDeposited.some(row => row.key === note.key && row.amount === note.amount)), 'Pre-existing Mainnet notes changed')
    const createdDeposit = mainnetDeposited.filter(note => !mainnetExisting.has(note.key))
    assert.equal(createdDeposit.length, 1, 'Expected exactly one note from this deposit')
    assert.equal(createdDeposit[0]!.amount, '0.005 SOL', 'Unexpected deposit note')
    const depositKey = createdDeposit[0]!.key
    console.log('  Audit-created Mainnet deposit ID:', depositKey)

    // Mainnet Selective Disclosure Viewing Receipt (Real ✓ + Forged ✕)
    await clickAuditNote(cdp, depositKey, 'Receipt')
    await clickButton(cdp, 'Verify Real Receipt Against Solana', '.lv-receipt-actions button')
    const mainReal = await waitFor(
      () => cdp!.eval<string | false>(`(() => { const el = document.querySelector('.lv-receipt-verdict.is-valid'); return el ? el.textContent.trim() : false; })()`),
      'Mainnet Real Receipt VERIFIED BY SOLANA',
    )
    console.log(`  ✓ Mainnet Real Receipt: ${mainReal}`)
    await clickButton(cdp, 'Test Tampered Amount', '.lv-receipt-actions button')
    const mainForged = await waitFor(
      () => cdp!.eval<string | false>(`(() => { const el = document.querySelector('.lv-receipt-verdict.is-forged'); return el ? el.textContent.trim() : false; })()`),
      'Mainnet Forged Receipt FORGERY CAUGHT',
    )
    console.log(`  ✓ Mainnet Forged Receipt: ${mainForged}`)
    await clickAuditNote(cdp, depositKey, 'Receipt')

    // Mainnet Direct Self-Pay Private Send (0.002 SOL — ZERO relayer quota consumed!)
    await clickAuditNote(cdp, depositKey, 'Private Send')
    const advOpen = await cdp.eval<boolean>(`Boolean(document.querySelector('.lv-mode-card'))`)
    if (!advOpen) await clickButton(cdp, 'ADVANCED OPTIONS', '.lv-adv-toggle')
    await clickButton(cdp, 'Your Wallet (Direct)', '.lv-mode-card')
    await setInput(cdp, '#lv-xfer-amt', '0.002')
    await submitAuditNote(cdp, depositKey, '0.002', 'xfer', mainnetDeposited)
    const afterMainDirect = await waitFor(async () => {
      const st = await getVaultState(cdp!)
      if (st.errorText) throw new Error(st.errorText)
      return st.auditCount > afterMainDep.auditCount && !st.busyText && st.latestAudit?.proofText.includes('YOUR WALLET ON TX:') ? st : false
    }, 'Mainnet Direct Private Send (ProofBuffer)', 120_000)
    assert.equal(afterMainDirect.noteCount, mainnetBefore.length + 2, 'Unexpected private notes during this audit; refusing to select unrelated notes')
    console.log(`  ✓ Mainnet Direct Send confirmed: ${afterMainDirect.latestAudit?.summary}`)
    console.log(`  ✓ On-screen proof: ${afterMainDirect.latestAudit?.proofText}`)
    const mainDirectSig = afterMainDirect.latestAudit!.solscanUrl.split('/tx/')[1]!.split('?')[0]!
    await verifyRpcTx(MAINNET_QN_RPC, mainDirectSig, signer.address, signer.address, false)
    await screenshot(cdp, 'part3-mainnet-direct-proof.png')

    // Identify outputs by their receipt IDs, and never select a pre-existing note.
    const mainnetAfterSend = await identifyAuditNotes(cdp)
    assert.ok(mainnetBefore.every(note => mainnetAfterSend.some(row => row.key === note.key && row.amount === note.amount)), 'Pre-existing Mainnet notes changed')
    const createdOutputs = mainnetAfterSend.filter(note => !mainnetExisting.has(note.key))
    assert.equal(createdOutputs.length, 2, 'Expected exactly two outputs from this audit send')
    assert.ok(!createdOutputs.some(note => note.key === depositKey), 'Spent deposit still present')
    assert.deepEqual(createdOutputs.map(note => note.amount).sort(), ['0.002 SOL', '0.003 SOL'])
    console.log('  Audit-created Mainnet output IDs:', createdOutputs.map(note => note.key).join(', '))
    const remainingOutputs = [...createdOutputs]
    for (const output of createdOutputs) {
      const expectedAmt = output.amount
      const prevA = (await getVaultState(cdp)).auditCount
      await identifyAuditNotes(cdp)
      await clickAuditNote(cdp, output.key, 'Go Public')
      await submitAuditNote(cdp, output.key, output.amount.split(' ')[0]!, 'wd', [...mainnetBefore, ...remainingOutputs])
      const afterMainWd = await waitFor(async () => {
        const st = await getVaultState(cdp!)
        if (st.errorText) throw new Error(st.errorText)
        return st.auditCount > prevA && !st.busyText && st.latestAudit?.proofText.includes('YOUR WALLET ON TX:') ? st : false
      }, `Mainnet Direct Go Public Withdraw (${expectedAmt})`, 120_000)
      console.log(`  ✓ Mainnet Direct Withdraw: ${afterMainWd.latestAudit?.summary}`)
      remainingOutputs.splice(remainingOutputs.findIndex(note => note.key === output.key), 1)
    }

    const mainnetAfterCleanup = await identifyAuditNotes(cdp)
    assert.deepEqual(mainnetAfterCleanup.map(note => `${note.key}=${note.amount}`).sort(), mainnetBefore.map(note => `${note.key}=${note.amount}`).sort(), 'Cleanup must preserve every pre-existing Mainnet note exactly')
    console.log(`  ✓ Mainnet cleanup preserved ${mainnetBefore.length} pre-existing notes`)

    // =========================================================================
    // PART 4: FREE DEVNET SANDBOX (NO WALLET, DEVNET RPC)
    // =========================================================================
    banner('PART 4: Free Devnet Sandbox (Devnet RPC, No Wallet)')
    await clickButton(cdp, 'Disconnect')
    await sleep(600)
    await clickButton(cdp, 'TRY FREE DEVNET TEST')
    await waitFor(
      () =>
        cdp!.eval<boolean>(
          `Array.from(document.querySelectorAll('button')).some((b) => (b.textContent || '').includes('Free Test SOL Privately') && !b.disabled)`,
        ),
      'Sandbox Step 1 button ready',
      30_000,
    )
    await clickButton(cdp, 'Free Test SOL Privately')
    await waitFor(
      () =>
        cdp!.eval<boolean>(
          `((document.querySelector('.sb-mini-proof')?.textContent || '').includes('CONFIRMED ON DEVNET')) || Boolean(document.querySelector('.alert-banner.is-error'))`,
        ),
      'Sandbox Step 1 confirmed',
      60_000,
    )
    const sb1Err = await cdp.eval<string | null>(
      `document.querySelector('.alert-banner.is-error')?.textContent?.trim() || null`,
    )
    assert.equal(sb1Err, null, `Sandbox Step 1 error: ${sb1Err}`)
    console.log('  ✓ Sandbox Step 1 (Devnet Deposit via Solana RPC) confirmed')

    await clickButton(cdp, 'Next: Send Privately')
    await sleep(300)
    await clickButton(cdp, 'Send Privately Live')
    await waitFor(
      () =>
        cdp!.eval<boolean>(
          `(document.body?.innerText || '').includes('PRIVATE SPEND CONFIRMED') || Boolean(document.querySelector('.alert-banner.is-error'))`,
        ),
      'Sandbox Step 2 confirmed',
      75_000,
    )
    const sb2Err = await cdp.eval<string | null>(
      `document.querySelector('.alert-banner.is-error')?.textContent?.trim() || null`,
    )
    assert.equal(sb2Err, null, `Sandbox Step 2 error: ${sb2Err}`)
    console.log('  ✓ Sandbox Step 2 (Devnet Private Spend) confirmed')

    await clickButton(cdp, 'Next: 3. Test Tamper-Proof Receipt')
    await sleep(300)
    await clickButton(cdp, 'Create Real Receipt')
    await waitFor(
      () => cdp!.eval<boolean>(`(document.body?.innerText || '').includes('VERIFIED BY SOLANA')`),
      'Sandbox Step 3a real receipt',
    )
    await screenshot(cdp, 'part4-sandbox-verified.png')
    await clickButton(cdp, 'Try Faking the Amount')
    await waitFor(
      () => cdp!.eval<boolean>(`(document.body?.innerText || '').includes('FORGERY CAUGHT')`),
      'Sandbox Step 3b forged receipt',
    )
    console.log('  ✓ Sandbox Step 3 (Real ✓ & Forged ✕ Receipts) verified')

    banner(`DEEP EMPIRICAL AUDIT 100% PASSED in ${((Date.now() - tStart) / 1000).toFixed(1)}s`)
    console.log(`  Wallet signatures:  ${signedMsgCount} signMessage, ${signedTxCount} signed tx(s)`)
    console.log(`  Console errors:     ${consoleErrors.length}`)
    console.log(`  Page exceptions:    ${pageExceptions.length}`)
    console.log(`  HTTP >= 400 errors: ${failedRequests.length}`)
    if (consoleErrors.length) console.error('Console errors:', consoleErrors)
    if (pageExceptions.length) console.error('Page exceptions:', pageExceptions)
    if (failedRequests.length) console.error('Failed HTTP:', failedRequests)

    assert.equal(consoleErrors.length, 0, `Unexpected console errors: ${consoleErrors.join('; ')}`)
    assert.equal(pageExceptions.length, 0, `Unexpected page exceptions: ${pageExceptions.join('; ')}`)
    assert.equal(failedRequests.length, 0, `Unexpected HTTP >= 400: ${failedRequests.join('; ')}`)
  } finally {
    cdp?.close()
    chrome?.kill('SIGKILL')
    try {
      if (existsSync(USER_DATA_DIR)) rmSync(USER_DATA_DIR, { recursive: true, force: true })
    } catch {}
  }
}

main().catch((err) => {
  console.error('\n❌ FULL EMPIRICAL AUDIT FAILED:', err)
  process.exit(1)
})
