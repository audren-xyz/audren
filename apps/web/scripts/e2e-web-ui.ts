#!/usr/bin/env npx tsx
/**
 * Full End-to-End LIVE Web UI Verification Suite for https://audren.xyz/demo/
 *
 * Drives a REAL headless Chromium browser via Chrome DevTools Protocol (zero extra npm deps),
 * injects a Wallet Standard `Phantom` provider backed by a local Ed25519 keypair in Node
 * (private key never enters browser JS), and empirically clicks through EVERY SINGLE FLOW
 * on live production https://audren.xyz/demo/:
 *
 *   1. Connect Phantom + Unlock Private Balance + Public Wallet drawer search + Token Picker
 *   2. Mainnet Go Private (0.01 SOL -> WSOL wrap + Deposit + atomic WSOL ATA close)
 *   3. Mainnet Private Send via relay.audren.xyz (0.004 SOL -> single Solana v1 tx, 0 user wallet signers)
 *   4. Mainnet Combine Notes via relay.audren.xyz (2 split notes -> 1 consolidated 0.01 SOL note, 0 user signers)
 *   5. Mainnet Private Swap on Jupiter via relay.audren.xyz (0.01 SOL -> USDC: Token Search + Live Quote + single Solana v1 ExecViaEscrow + settled fill, 0 user signers)
 *   6. Mainnet Go Public via relay.audren.xyz (Max settled USDC -> back to Public Wallet + exact balance delta check)
 *   7. Stranger View toggle + Encrypted Vault Backup Export + Full Rescan from Page 0
 *   8. Free Devnet Interactive Sandbox (Step 1 Deposit -> Step 2 Private Spend -> Step 3 Real & Forged Receipts)
 *
 * Usage:
 *   cd apps/web && MAINNET_RPC_URL=... AUDREN_KEYPAIR_PATH=... npx tsx scripts/e2e-web-ui.ts
 */

import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { base58Encode } from '../lib/audren-crypto'

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..')

function loadMainnetRpcUrl(): string {
  const url = process.env.MAINNET_RPC_URL?.trim()
  if (!url) throw new Error('Set MAINNET_RPC_URL to a Solana Mainnet RPC endpoint')
  return url
}

const BASE_URL = (process.env.AUDREN_BASE_URL ?? 'https://audren.xyz').replace(/\/+$/, '')
const KEYPAIR_PATH =
  process.env.AUDREN_KEYPAIR_PATH ??
  path.join(REPO_ROOT, '.credentials/funder.json')
const SCREENSHOT_DIR = process.env.AUDREN_SCREENSHOT_DIR ?? '/tmp/audren-web-e2e'

function findChromiumBinary(): string {
  const candidates = [
    process.env.CHROME_PATH,
    path.join(
      os.homedir(),
      'Library/Caches/ms-playwright/chromium-1194/chrome-mac/Chromium.app/Contents/MacOS/Chromium',
    ),
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
  ].filter(Boolean) as string[]
  for (const p of candidates) {
    if (fs.existsSync(p)) return p
  }
  throw new Error(`No Chromium/Chrome binary found. Checked: ${candidates.join(', ')}`)
}

// ---------------------------------------------------------------------------
// Local Node Ed25519 Signer (private key NEVER touches Chromium)
// ---------------------------------------------------------------------------
interface NodeSigner {
  address: string
  pubkey: Uint8Array
  signMessage: (msg: Uint8Array) => Uint8Array
  signTransaction: (wire: Uint8Array) => Uint8Array
}

function loadNodeSigner(keyPath: string): NodeSigner {
  const raw = Buffer.from(JSON.parse(fs.readFileSync(keyPath, 'utf8')) as number[])
  assert.equal(raw.length, 64, 'Solana keypair JSON must be 64 bytes')
  const seed = raw.subarray(0, 32)
  const pub = new Uint8Array(raw.subarray(32, 64))
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed])
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pub])
  const privKey = crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' })
  const pubKey = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' })

  const decodeShortVec = (buf: Uint8Array, off: number): { val: number; next: number } => {
    let val = 0
    let shift = 0
    let i = off
    for (;;) {
      const b = buf[i++]
      val |= (b & 0x7f) << shift
      if ((b & 0x80) === 0) return { val, next: i }
      shift += 7
    }
  }

  return {
    address: base58Encode(pub),
    pubkey: pub,
    signMessage(msg: Uint8Array): Uint8Array {
      const sig = crypto.sign(null, Buffer.from(msg), privKey)
      assert.ok(crypto.verify(null, Buffer.from(msg), pubKey, sig), 'signMessage verify failed')
      return new Uint8Array(sig)
    },
    signTransaction(wire: Uint8Array): Uint8Array {
      const { val: numSigs, next: sigStart } = decodeShortVec(wire, 0)
      assert.ok(numSigs >= 1, `Invalid numSigs=${numSigs}`)
      const msgBytes = wire.subarray(sigStart + numSigs * 64)
      const sig = crypto.sign(null, Buffer.from(msgBytes), privKey)
      assert.ok(crypto.verify(null, Buffer.from(msgBytes), pubKey, sig), 'signTx verify failed')
      const signed = new Uint8Array(wire)
      signed.set(sig, sigStart)
      return signed
    },
  }
}

// ---------------------------------------------------------------------------
// Minimal Zero-Dependency CDP Client over Node native WebSocket
// ---------------------------------------------------------------------------
class CdpClient {
  private ws: WebSocket
  private nextId = 1
  private pending = new Map<
    number,
    { resolve: (v: unknown) => void; reject: (e: Error) => void }
  >()
  private listeners = new Map<string, Set<(params: Record<string, unknown>) => void>>()
  public sessionId: string | undefined

  private constructor(ws: WebSocket) {
    this.ws = ws
    ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(String(ev.data)) as {
        id?: number
        method?: string
        params?: Record<string, unknown>
        result?: unknown
        error?: { code?: number; message?: string }
        sessionId?: string
      }
      if (msg.id !== undefined) {
        const entry = this.pending.get(msg.id)
        if (entry) {
          this.pending.delete(msg.id)
          if (msg.error) {
            entry.reject(new Error(`CDP ${msg.error.code ?? ''}: ${msg.error.message ?? 'error'}`))
          } else {
            entry.resolve(msg.result)
          }
        }
      } else if (msg.method) {
        const set = this.listeners.get(msg.method)
        if (set) {
          for (const fn of set) fn(msg.params ?? {})
        }
      }
    })
  }

  static async connect(wsUrl: string): Promise<CdpClient> {
    const ws = new WebSocket(wsUrl)
    await new Promise<void>((resolve, reject) => {
      ws.addEventListener('open', () => resolve(), { once: true })
      ws.addEventListener('error', (e) => reject(new Error(`CDP WS error: ${String(e)}`)), {
        once: true,
      })
    })
    return new CdpClient(ws)
  }

  on(method: string, handler: (params: Record<string, unknown>) => void): void {
    let set = this.listeners.get(method)
    if (!set) {
      set = new Set()
      this.listeners.set(method, set)
    }
    set.add(handler)
  }

  send<T = Record<string, unknown>>(
    method: string,
    params: Record<string, unknown> = {},
    opts?: { browserLevel?: boolean },
  ): Promise<T> {
    const id = this.nextId++
    const payload: Record<string, unknown> = { id, method, params }
    if (!opts?.browserLevel && this.sessionId) {
      payload.sessionId = this.sessionId
    }
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, {
        resolve: resolve as (v: unknown) => void,
        reject,
      })
      this.ws.send(JSON.stringify(payload))
    })
  }

  async eval<T = unknown>(expression: string): Promise<T> {
    const res = await this.send<{
      result?: { value?: T; description?: string; type?: string }
      exceptionDetails?: { text?: string; exception?: { description?: string } }
    }>('Runtime.evaluate', {
      expression,
      awaitPromise: true,
      returnByValue: true,
    })
    if (res.exceptionDetails) {
      throw new Error(
        `Browser eval exception: ${res.exceptionDetails.exception?.description ?? res.exceptionDetails.text ?? 'unknown'}`,
      )
    }
    return res.result?.value as T
  }

  close(): void {
    try {
      this.ws.close()
    } catch {
      // ignore
    }
  }
}

async function launchChromium(): Promise<{ proc: ChildProcess; wsUrl: string; userDataDir: string }> {
  const bin = findChromiumBinary()
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'audren-e2e-chrome-'))
  const proc = spawn(
    bin,
    [
      '--headless=new',
      '--disable-gpu',
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-background-networking',
      '--disable-component-update',
      '--window-size=1440,1080',
      '--remote-debugging-port=0',
      `--user-data-dir=${userDataDir}`,
      'about:blank',
    ],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  )

  const wsUrl = await new Promise<string>((resolve, reject) => {
    let stderrBuf = ''
    const timer = setTimeout(() => {
      reject(new Error(`Timed out waiting for Chromium CDP WS URL. stderr:\n${stderrBuf}`))
    }, 15_000)

    proc.stderr?.on('data', (chunk) => {
      stderrBuf += String(chunk)
      const match = stderrBuf.match(/DevTools listening on (ws:\/\/[^\s]+)/)
      if (match) {
        clearTimeout(timer)
        resolve(match[1])
      }
    })
    proc.once('exit', (code) => {
      clearTimeout(timer)
      reject(new Error(`Chromium exited early (${code}). stderr:\n${stderrBuf}`))
    })
  })

  return { proc, wsUrl, userDataDir }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms))
}

function banner(step: string): void {
  console.log(`\n════════════════════════════════════════════════════════════════`)
  console.log(`  ${step}`)
  console.log(`════════════════════════════════════════════════════════════════`)
}

const MAINNET_QN_RPC = loadMainnetRpcUrl()
const EXPECTED_RELAYER_MAINNET = 'H2JcTKgrP5Hqj7v2hTuz5u6Tt1VB8yrznotT62hhp3vY'

async function assertRelayedOnChainPrivacy(
  label: string,
  solscanUrl: string | null | undefined,
  userWallet: string,
  requireAbsentFromAllKeys: boolean,
): Promise<void> {
  assert.ok(solscanUrl && solscanUrl.includes('/tx/'), `${label}: missing solscanUrl`)
  const sig = solscanUrl.split('/tx/')[1]!.split('?')[0]!
  for (let i = 0; i < 10; i++) {
    const res = await fetch(MAINNET_QN_RPC, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'getTransaction',
        params: [sig, { encoding: 'jsonParsed', commitment: 'confirmed', maxSupportedTransactionVersion: 1 }],
      }),
    })
    const body = (await res.json()) as {
      result?: {
        version?: number | 'legacy'
        transaction?: { message?: { accountKeys?: Array<string | { pubkey: string; signer?: boolean }> } }
        meta?: { loadedAddresses?: { writable?: string[]; readonly?: string[] } }
      } | null
    }
    const tx = body.result
    if (tx?.transaction?.message?.accountKeys) {
      const staticKeys = tx.transaction.message.accountKeys
      const signers = staticKeys
        .filter((k) => typeof k !== 'string' && k.signer)
        .map((k) => (typeof k === 'string' ? k : k.pubkey))
      const allKeys = [
        ...staticKeys.map((k) => (typeof k === 'string' ? k : k.pubkey)),
        ...(tx.meta?.loadedAddresses?.writable ?? []),
        ...(tx.meta?.loadedAddresses?.readonly ?? []),
      ]
      assert.equal(tx.version, 1, `${label}: expected Solana v1 tx, got ${tx.version}`)
      assert.deepEqual(
        signers,
        [EXPECTED_RELAYER_MAINNET],
        `${label}: expected ONLY relayer ${EXPECTED_RELAYER_MAINNET} as signer, got ${JSON.stringify(signers)}`,
      )
      assert.ok(!signers.includes(userWallet), `${label}: user wallet MUST NOT be a signer!`)
      if (requireAbsentFromAllKeys) {
        assert.ok(
          !allKeys.includes(userWallet),
          `${label}: PRIVACY LEAK! User wallet ${userWallet} appeared in tx accountKeys!`,
        )
      }
      console.log(
        `  ✓ ON-CHAIN PRIVACY VERIFIED (${label}): v${tx.version}, signer=${signers[0]}, userWalletPresent=${allKeys.includes(userWallet)}`,
      )
      return
    }
    await sleep(600)
  }
  throw new Error(`${label}: could not fetch tx ${sig} from Solana RPC`)
}

// ---------------------------------------------------------------------------
// Wallet Standard Injection Script (runs BEFORE page JS on every document)
// ---------------------------------------------------------------------------
function buildWalletStandardInitScript(address: string, pubkey: Uint8Array): string {
  const pubArr = JSON.stringify(Array.from(pubkey))
  return `(() => {
    const PENDING = new Map();
    let seq = 1;
    window.__audrenResolveSigner = (id, payloadJson) => {
      const p = PENDING.get(id);
      if (!p) return;
      PENDING.delete(id);
      const parsed = JSON.parse(payloadJson);
      if (parsed.error) p.reject(new Error(parsed.error));
      else p.resolve(parsed);
    };
    const callNode = (op, body) => new Promise((resolve, reject) => {
      const id = seq++;
      PENDING.set(id, { resolve, reject });
      window.__audrenSignBridge(JSON.stringify({ id, op, ...body }));
    });

    const pubkey = new Uint8Array(${pubArr});
    const account = Object.freeze({
      address: ${JSON.stringify(address)},
      publicKey: pubkey,
      chains: ['solana:mainnet', 'solana:devnet'],
      features: ['solana:signMessage', 'solana:signTransaction'],
    });

    let accounts = [];
    const listeners = new Set();

    const wallet = {
      version: '1.0.0',
      name: 'Phantom',
      icon: 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIzMiIgaGVpZ2h0PSIzMiI+PHJlY3Qgd2lkdGg9IjMyIiBoZWlnaHQ9IjMyIiByeD0iOCIgZmlsbD0iI2FiOWZmMiIvPjwvc3ZnPg==',
      chains: ['solana:mainnet', 'solana:devnet'],
      get accounts() { return accounts; },
      features: {
        'standard:connect': {
          version: '1.0.0',
          async connect() {
            accounts = [account];
            for (const fn of listeners) fn({ accounts });
            return { accounts };
          },
        },
        'standard:disconnect': {
          version: '1.0.0',
          async disconnect() {
            accounts = [];
            for (const fn of listeners) fn({ accounts });
          },
        },
        'standard:events': {
          version: '1.0.0',
          on(event, listener) {
            if (event === 'change') listeners.add(listener);
            return () => listeners.delete(listener);
          },
        },
        'solana:signMessage': {
          version: '1.0.0',
          async signMessage(...inputs) {
            const out = [];
            for (const inp of inputs) {
              const r = await callNode('signMessage', { message: Array.from(inp.message) });
              out.push({ signedMessage: inp.message, signature: new Uint8Array(r.signature) });
            }
            return out;
          },
        },
        'solana:signTransaction': {
          version: '1.0.0',
          supportedTransactionVersions: ['legacy', 0],
          async signTransaction(...inputs) {
            const r = await callNode('signTransactions', {
              transactions: inputs.map((i) => Array.from(i.transaction)),
            });
            return r.signedTransactions.map((arr) => ({ signedTransaction: new Uint8Array(arr) }));
          },
        },
      },
    };

    const register = () => {
      try {
        window.dispatchEvent(new CustomEvent('wallet-standard:register-wallet', {
          detail: Object.freeze((api) => api.register(wallet)),
        }));
      } catch {}
    };
    window.addEventListener('wallet-standard:app-ready', (ev) => {
      try { ev.detail?.register?.(wallet); } catch {}
    });
    register();
    window.addEventListener('DOMContentLoaded', register);
  })();`
}

// ---------------------------------------------------------------------------
// DOM Helpers
// ---------------------------------------------------------------------------
class FatalUiError extends Error {}

async function waitFor<T>(
  fn: () => Promise<T | false | null | undefined>,
  label: string,
  timeoutMs = 90_000,
  intervalMs = 500,
): Promise<T> {
  const start = Date.now()
  let lastErr: unknown = null
  while (Date.now() - start < timeoutMs) {
    try {
      const val = await fn()
      if (val) return val
    } catch (e) {
      if (e instanceof FatalUiError) throw e
      lastErr = e
    }
    await sleep(intervalMs)
  }
  throw new Error(
    `Timed out after ${timeoutMs}ms waiting for: ${label}${lastErr ? ` (lastErr=${String(lastErr)})` : ''}`,
  )
}

async function clickButtonByText(
  cdp: CdpClient,
  needle: string,
  opts?: { exact?: boolean; selector?: string; index?: number },
): Promise<string> {
  const selector = opts?.selector ?? 'button, [role="tab"]'
  const exact = opts?.exact ?? false
  const index = opts?.index ?? 0
  const result = await cdp.eval<{ ok: boolean; text?: string; candidates?: string[] }>(`(() => {
    const els = Array.from(document.querySelectorAll(${JSON.stringify(selector)}))
      .filter((el) => {
        const style = window.getComputedStyle(el);
        const r = el.getBoundingClientRect();
        return style.visibility !== 'hidden' && style.display !== 'none' && r.width > 0 && r.height > 0 && !el.disabled;
      });
    const norm = (s) => (s || '').replace(/\\s+/g, ' ').trim();
    const target = ${JSON.stringify(needle)}.toLowerCase();
    const matches = els.filter((el) => {
      const t = norm(el.textContent).toLowerCase();
      return ${exact} ? t === target : t.includes(target);
    });
    const chosen = matches[${index}];
    if (!chosen) {
      return { ok: false, candidates: els.map((e) => norm(e.textContent)).slice(0, 35) };
    }
    chosen.scrollIntoView({ block: 'center', behavior: 'instant' });
    chosen.click();
    return { ok: true, text: norm(chosen.textContent) };
  })()`)
  if (!result.ok) {
    throw new Error(
      `Could not find visible enabled "${needle}" (${selector}). Visible buttons: ${JSON.stringify(result.candidates)}`,
    )
  }
  return result.text ?? needle
}

async function setInputValue(cdp: CdpClient, selector: string, value: string): Promise<void> {
  const ok = await cdp.eval<boolean>(`(() => {
    const el = document.querySelector(${JSON.stringify(selector)});
    if (!el) return false;
    el.focus();
    const proto = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value');
    proto.set.call(el, ${JSON.stringify(value)});
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  })()`)
  assert.ok(ok, `Input not found: ${selector}`)
}

async function getUiState(cdp: CdpClient): Promise<{
  errorBanner: string | null
  busySubmitText: string | null
  privateTotal: string
  privateSub: string
  publicVal: string
  noteCount: number
  noteRows: string[]
  noteAmounts: string[]
  auditCount: number
  latestAudit: { kicker: string; summary: string; solscanUrl: string | null; proverMs: string | null } | null
  mergeButtons: string[]
  swapQuoteText: string | null
  swapQuoteError: string | null
  backupStatus: string | null
}> {
  return cdp.eval(`(() => {
    const norm = (s) => (s || '').replace(/\\s+/g, ' ').trim();
    const errEl = document.querySelector('.lv-error-bar, .alert-banner.is-error');
    const submitBtn = document.querySelector('.lv-submit-btn');
    const privTotal = document.querySelector('.lv-private-total strong');
    const privSub = document.querySelector('.lv-private-sub-amt');
    const pubVal = document.querySelector('.lv-pub-val');
    const noteEls = Array.from(document.querySelectorAll('.lv-private-row'));
    const auditEls = Array.from(document.querySelectorAll('.lv-audit-card'));
    let latestAudit = null;
    if (auditEls.length > 0) {
      const a = auditEls[0];
      const dds = Array.from(a.querySelectorAll('.lv-audit-facts dd')).map((d) => norm(d.textContent));
      latestAudit = {
        kicker: norm(a.querySelector('.kicker')?.textContent),
        summary: norm(a.querySelector('h4')?.textContent),
        solscanUrl: a.querySelector('a[href*="solscan.io"]')?.getAttribute('href') || null,
        proverMs: dds[3] || null,
      };
    }
    const mergeButtons = Array.from(document.querySelectorAll('.lv-merge-bar button')).map((b) => norm(b.textContent));
    const quoteCard = document.querySelector('.lv-quote-details');
    const quoteErr = document.querySelector('.lv-quote-err');
    const backupStatus = document.querySelector('.lv-backup-status');
    return {
      errorBanner: errEl ? norm(errEl.textContent) : null,
      busySubmitText: submitBtn && submitBtn.disabled ? norm(submitBtn.textContent) : null,
      privateTotal: norm(privTotal?.textContent),
      privateSub: norm(privSub?.textContent),
      publicVal: norm(pubVal?.textContent),
      noteCount: noteEls.length,
      noteRows: noteEls.map((n) => norm(n.textContent)),
      noteAmounts: noteEls.map((n) => norm(n.querySelector('.lv-balance-amt')?.textContent)),
      auditCount: auditEls.length,
      latestAudit,
      mergeButtons,
      swapQuoteText: quoteCard ? norm(quoteCard.textContent) : null,
      swapQuoteError: quoteErr ? norm(quoteErr.textContent) : null,
      backupStatus: backupStatus ? norm(backupStatus.textContent) : null,
    };
  })()`)
}

async function saveScreenshot(cdp: CdpClient, filename: string): Promise<string> {
  await sleep(250)
  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true })
  const out = path.join(SCREENSHOT_DIR, filename)
  const res = await cdp.send<{ data: string }>('Page.captureScreenshot', { format: 'png' })
  fs.writeFileSync(out, Buffer.from(res.data, 'base64'))
  console.log(`  📸 Saved screenshot: ${out}`)
  return out
}

// ---------------------------------------------------------------------------
// Main Live Web UI E2E Run
// ---------------------------------------------------------------------------
async function main() {
  const t0 = Date.now()
  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true })
  const signer = loadNodeSigner(KEYPAIR_PATH)
  console.log(`Audren LIVE Web UI E2E — ${BASE_URL}/demo/`)
  console.log(`Wallet: ${signer.address}`)

  const { proc, wsUrl, userDataDir } = await launchChromium()
  let cdp: CdpClient | null = null

  const consoleErrors: string[] = []
  const pageExceptions: string[] = []
  const failedHttp: Array<{ url: string; status: number }> = []
  let signedMessageCount = 0
  let signedTxCount = 0

  try {
    cdp = await CdpClient.connect(wsUrl)
    const { targetId } = await cdp.send<{ targetId: string }>(
      'Target.createTarget',
      { url: 'about:blank' },
      { browserLevel: true },
    )
    const { sessionId } = await cdp.send<{ sessionId: string }>(
      'Target.attachToTarget',
      { targetId, flatten: true },
      { browserLevel: true },
    )
    cdp.sessionId = sessionId

    await cdp.send('Page.enable')
    await cdp.send('Runtime.enable')
    await cdp.send('Network.enable')
    await cdp.send('Log.enable')
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: 1440,
      height: 1080,
      deviceScaleFactor: 1,
      mobile: false,
    })

    // Telemetry capture
    cdp.on('Runtime.consoleAPICalled', (p) => {
      if (p.type === 'error') {
        const args = (p.args as Array<{ value?: unknown; description?: string }> | undefined) ?? []
        const text = args.map((a) => String(a.value ?? a.description ?? '')).join(' ')
        consoleErrors.push(text)
        console.log(`  [CONSOLE ERROR] ${text}`)
      }
    })
    cdp.on('Runtime.exceptionThrown', (p) => {
      const d = p.exceptionDetails as { text?: string; exception?: { description?: string } }
      const text = d?.exception?.description ?? d?.text ?? JSON.stringify(p)
      pageExceptions.push(text)
      console.log(`  [PAGE EXCEPTION] ${text}`)
    })
    cdp.on('Log.entryAdded', (p) => {
      const entry = p.entry as { level?: string; text?: string; url?: string }
      if (entry?.level === 'error') {
        const text = `${entry.text ?? ''} (${entry.url ?? ''})`
        consoleErrors.push(text)
        console.log(`  [LOG ERROR] ${text}`)
      }
    })
    cdp.on('Network.responseReceived', (p) => {
      const resp = p.response as { url?: string; status?: number }
      if (resp?.status && resp.status >= 400) {
        failedHttp.push({ url: resp.url ?? '', status: resp.status })
        console.log(`  [HTTP ${resp.status}] ${resp.url}`)
      }
    })

    // Expose Node Ed25519 signing bridge to Chromium via CDP Runtime.addBinding
    await cdp.send('Runtime.addBinding', { name: '__audrenSignBridge' })
    cdp.on('Runtime.bindingCalled', (p) => {
      if (p.name !== '__audrenSignBridge') return
      const payload = JSON.parse(String(p.payload)) as {
        id: number
        op: 'signMessage' | 'signTransactions'
        message?: number[]
        transactions?: number[][]
      }
      let reply: Record<string, unknown>
      try {
        if (payload.op === 'signMessage') {
          signedMessageCount++
          const sig = signer.signMessage(Uint8Array.from(payload.message ?? []))
          console.log(`  🔐 Phantom.signMessage (#${signedMessageCount})`)
          reply = { signature: Array.from(sig) }
        } else if (payload.op === 'signTransactions') {
          const txs = (payload.transactions ?? []).map((arr) =>
            Array.from(signer.signTransaction(Uint8Array.from(arr))),
          )
          signedTxCount += txs.length
          console.log(
            `  ✍️  Phantom.signTransaction batch: ${txs.length} tx(s) (total signed=${signedTxCount})`,
          )
          reply = { signedTransactions: txs }
        } else {
          reply = { error: `Unknown op ${payload.op}` }
        }
      } catch (e) {
        reply = { error: e instanceof Error ? e.message : String(e) }
      }
      void cdp!.send('Runtime.evaluate', {
        expression: `window.__audrenResolveSigner(${payload.id}, ${JSON.stringify(JSON.stringify(reply))})`,
      })
    })

    await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
      source: buildWalletStandardInitScript(signer.address, signer.pubkey),
    })

    // =========================================================================
    // STEP 1: Navigate to /demo/, Connect Phantom, Unlock Vault, Inspect UI
    // =========================================================================
    banner('STEP 1: Open https://audren.xyz/demo/ → Connect Phantom → Unlock Vault')
    await cdp.send('Page.navigate', { url: `${BASE_URL}/demo/` })

    await waitFor(async () => {
      const hasConnect = await cdp!.eval<boolean>(
        `Array.from(document.querySelectorAll('button')).some((b) => /phantom/i.test(b.textContent || ''))`,
      )
      return hasConnect
    }, 'Connect Phantom button on /demo/')

    const connectLabel = await clickButtonByText(cdp, 'Phantom')
    console.log(`  ✓ Clicked "${connectLabel}"`)

    // Wait for balances to load & Unlock button to appear
    await waitFor(async () => {
      const st = await getUiState(cdp!)
      return st.publicVal.includes('SOL') ? st : false
    }, 'Public wallet SOL balance to load')

    const unlockLabel = await clickButtonByText(cdp, 'Unlock Private Balance')
    console.log(`  ✓ Clicked "${unlockLabel}"`)

    await waitFor(
      () => cdp!.eval<boolean>(`(document.querySelector('.lv-addr-row code')?.textContent?.trim() || '').startsWith('aud1')`),
      'Private Address render',
    )
    // Allow async vault scan + nullifier check effect to launch and complete
    await sleep(1500)
    const afterUnlock = await waitFor(async () => {
      const addrText = await cdp!.eval<string>(
        `document.querySelector('.lv-addr-row code')?.textContent?.trim() || ''`,
      )
      const st = await getUiState(cdp!)
      if (st.privateSub.includes('Scanning') || st.privateSub.includes('Checking') || st.privateSub.includes('Verifying')) return false
      return { addrText, st }
    }, 'Private Balance unlock + initial scan')

    console.log(`  ✓ Public Wallet: ${afterUnlock.st.publicVal}`)
    console.log(`  ✓ Private Address: ${afterUnlock.addrText}`)
    console.log(`  ✓ Private Balance: ${afterUnlock.st.privateTotal} (${afterUnlock.st.privateSub})`)

    // Guard against silently draining user-owned private notes on a shared wallet.
    // Pass AUDREN_E2E_DRAIN_EXISTING=1 explicitly only when cleaning up an interrupted E2E run.
    let auditBase = afterUnlock.st.auditCount
    let currentNotes = afterUnlock.st.noteCount
    if (currentNotes > 0 && process.env.AUDREN_E2E_DRAIN_EXISTING !== '1') {
      throw new FatalUiError(
        `Refusing to touch ${currentNotes} pre-existing private note(s) (${afterUnlock.st.privateTotal}). Use a dedicated test keypair or pass AUDREN_E2E_DRAIN_EXISTING=1 to drain interrupted test notes.`,
      )
    }
    while (currentNotes > 0) {
      console.log(`  🧹 Draining ${currentNotes} leftover private note(s) via Go Public before Step 2…`)
      await clickButtonByText(cdp, 'Go Public', { selector: '[role="tab"]' })
      await waitFor(() => cdp!.eval<boolean>(`!!document.querySelector('#lv-wd-amt')`), 'Pre-drain Go Public input')
      await clickButtonByText(cdp, 'Max', { exact: true })
      await sleep(200)
      await clickButtonByText(cdp, 'Go Public with', { selector: '.lv-submit-btn' })
      const drained = await waitFor(async () => {
        const st = await getUiState(cdp!)
        if (st.errorBanner) throw new FatalUiError(`Pre-drain Go Public error: ${st.errorBanner}`)
        if (st.auditCount > auditBase && st.noteCount < currentNotes && !st.busySubmitText) return st
        return false
      }, 'Pre-drain Go Public confirmation', 120_000)
      auditBase = drained.auditCount
      currentNotes = drained.noteCount
      console.log(`  ✓ Leftover note drained (${drained.latestAudit?.solscanUrl}); remaining=${currentNotes}`)
      console.log(`  ⏳ Waiting 13s for relay.audren.xyz anti-abuse cooldown…`)
      await sleep(13_000)
    }
    if (auditBase > afterUnlock.st.auditCount) {
      await clickButtonByText(cdp, 'Go Private', { selector: '[role="tab"]' })
    }

    // Test TOKENS drawer search & record baseline Public Wallet USDC AFTER any pre-drain
    await clickButtonByText(cdp, 'TOKENS', { exact: true })
    await waitFor(
      () => cdp!.eval<boolean>(`!!document.querySelector('.lv-public-drawer-list input')`),
      'Public tokens drawer search input',
    )
    await setInputValue(cdp, '.lv-public-drawer-list input', 'USDC')
    const usdcRow = await waitFor(async () => {
      const amt = await cdp!.eval<string>(
        `document.querySelector('.lv-public-drawer-list .lv-balance-amt')?.textContent?.replace(/\\s+/g, ' ').trim() || ''`,
      )
      return amt.includes('USDC') ? amt : false
    }, 'USDC filtered row in Public tokens drawer')
    console.log(`  ✓ Public tokens drawer search("USDC"): ${usdcRow}`)
    const initialPublicUsdcMatch = usdcRow.match(/([\d,]+\.?\d*)\s*USDC/)
    const initialPublicUsdc = initialPublicUsdcMatch
      ? Number(initialPublicUsdcMatch[1].replace(/,/g, ''))
      : null
    await clickButtonByText(cdp, 'HIDE TOKENS', { exact: true })

    // Open & close Go Private Token Picker (also verify cbBTC non-zero formatting!)
    await clickButtonByText(cdp, 'CHANGE (')
    await waitFor(
      () => cdp!.eval<boolean>(`document.querySelectorAll('.lv-search-item').length >= 5`),
      'Token picker items',
    )
    const pickerCount = await cdp.eval<number>(
      `document.querySelectorAll('.lv-search-item').length`,
    )
    const cbBtcRow = await cdp.eval<string>(
      `Array.from(document.querySelectorAll('.lv-search-item')).find((e) => (e.textContent || '').includes('cbBTC'))?.textContent?.replace(/\\s+/g, ' ').trim() || ''`,
    )
    console.log(`  ✓ Go Private Token Picker opened with ${pickerCount} selectable tokens${cbBtcRow ? ` (cbBTC: "${cbBtcRow}")` : ''}`)
    if (cbBtcRow) {
      assert.ok(!cbBtcRow.includes('0 cbBTC'), `Tiny cbBTC balance must not round to 0: "${cbBtcRow}"`)
    }
    await clickButtonByText(cdp, 'CLOSE', { selector: '.lv-token-trigger' })
    await saveScreenshot(cdp, 'step1-unlocked.png')

    // =========================================================================
    // STEP 2: Mainnet Go Private (0.01 SOL via Web UI)
    // =========================================================================
    banner('STEP 2: Mainnet Go Private (0.01 SOL via Web UI)')
    await clickButtonByText(cdp, '0.01 SOL', { exact: true })
    const shieldClick = await clickButtonByText(cdp, 'Go Private with 0.01 SOL')
    console.log(`  ✓ Clicked "${shieldClick}"`)

    const afterShield = await waitFor(async () => {
      const st = await getUiState(cdp!)
      if (st.errorBanner) throw new FatalUiError(`UI Error during Go Private: ${st.errorBanner}`)
      if (st.auditCount >= auditBase + 1 && st.noteCount >= 1 && !st.busySubmitText) return st
      return false
    }, 'Go Private Mainnet confirmation + Private Balance update', 90_000)

    console.log(`  ✓ Audit #1: ${afterShield.latestAudit?.kicker}`)
    console.log(`    Summary:  ${afterShield.latestAudit?.summary}`)
    console.log(`    Solscan:  ${afterShield.latestAudit?.solscanUrl}`)
    console.log(`  ✓ Private Balance now: ${afterShield.privateTotal} (${afterShield.privateSub})`)
    console.log(`  ✓ Notes (${afterShield.noteCount}): ${afterShield.noteRows[0]}`)
    await saveScreenshot(cdp, 'step2-go-private.png')

    // =========================================================================
    // STEP 3: Mainnet Private Send (0.004 SOL split to self via Web UI)
    // =========================================================================
    banner('STEP 3: Mainnet Private Send (0.004 SOL to self via Web UI)')
    await clickButtonByText(cdp, 'Private Send', { selector: '[role="tab"]' })
    await waitFor(
      () => cdp!.eval<boolean>(`!!document.querySelector('#lv-xfer-amt')`),
      'Private Send amount input',
    )
    await setInputValue(cdp, '#lv-xfer-amt', '0.004')
    await sleep(200)
    const sendClick = await clickButtonByText(cdp, 'Send 0.004 SOL Privately')
    console.log(`  ✓ Clicked "${sendClick}"`)

    const afterSend = await waitFor(async () => {
      const st = await getUiState(cdp!)
      if (st.errorBanner) throw new FatalUiError(`UI Error during Private Send: ${st.errorBanner}`)
      if (
        st.auditCount >= auditBase + 2 &&
        st.noteCount >= 2 &&
        st.mergeButtons.length >= 1 &&
        !st.busySubmitText
      ) {
        return st
      }
      return false
    }, 'Private Send 5-tx ProofBuffer Mainnet confirmation + 2 split notes', 120_000)

    console.log(`  ✓ Audit #2: ${afterSend.latestAudit?.kicker}`)
    console.log(`    Summary:  ${afterSend.latestAudit?.summary}`)
    console.log(`    Proof:    ${afterSend.latestAudit?.proverMs}`)
    console.log(`    Solscan:  ${afterSend.latestAudit?.solscanUrl}`)
    console.log(`  ✓ Notes split into ${afterSend.noteCount}:`)
    afterSend.noteRows.forEach((r, i) => console.log(`      [${i + 1}] ${r}`))
    console.log(`  ✓ Combine bar visible: ${JSON.stringify(afterSend.mergeButtons)}`)
    await assertRelayedOnChainPrivacy('Private Send', afterSend.latestAudit?.solscanUrl, signer.address, true)
    await saveScreenshot(cdp, 'step3-private-send.png')

    // Respect live 12s anti-abuse cooldown between sponsored relay calls
    console.log(`  ⏳ Waiting 13s for relay.audren.xyz anti-abuse cooldown…`)
    await sleep(13_000)

    // =========================================================================
    // STEP 4: Mainnet Combine Notes (2 split notes -> 1 note via Web UI)
    // =========================================================================
    banner('STEP 4: Mainnet Combine Notes (2 → 1 via Web UI)')
    const combineClick = await clickButtonByText(cdp, 'Combine 2 of', {
      selector: '.lv-merge-bar button',
    })
    console.log(`  ✓ Clicked "${combineClick}"`)

    const afterCombine = await waitFor(async () => {
      const st = await getUiState(cdp!)
      if (st.errorBanner) throw new FatalUiError(`UI Error during Combine Notes: ${st.errorBanner}`)
      if (st.auditCount >= auditBase + 3 && st.noteCount === afterSend.noteCount - 1 && !st.busySubmitText) return st
      return false
    }, 'Combine Notes 1-tx Relayer Mainnet confirmation + 1 merged note', 120_000)

    console.log(`  ✓ Audit #3: ${afterCombine.latestAudit?.kicker}`)
    console.log(`    Summary:  ${afterCombine.latestAudit?.summary}`)
    console.log(`    Proof:    ${afterCombine.latestAudit?.proverMs}`)
    console.log(`    Solscan:  ${afterCombine.latestAudit?.solscanUrl}`)
    console.log(`  ✓ Consolidated back to ${afterCombine.noteCount} note: ${afterCombine.noteRows[0]}`)
    await assertRelayedOnChainPrivacy('Combine Notes', afterCombine.latestAudit?.solscanUrl, signer.address, true)
    await saveScreenshot(cdp, 'step4-combine-notes.png')

    // Respect live 12s anti-abuse cooldown before small subsidized Jupiter Swap
    console.log(`  ⏳ Waiting 13s for relay.audren.xyz anti-abuse cooldown…`)
    await sleep(13_000)

    // =========================================================================
    // STEP 5: Mainnet Private Swap on Jupiter (0.01 SOL -> USDC via Web UI)
    // =========================================================================
    banner('STEP 5: Mainnet Private Swap on Jupiter (0.01 SOL → USDC via Web UI)')
    await clickButtonByText(cdp, 'Private Swap', { selector: '[role="tab"]' })

    // Open output token search picker, type USDC, pick USDC
    await clickButtonByText(cdp, 'SEARCH TOKENS')
    await waitFor(
      () => cdp!.eval<boolean>(`!!document.querySelector('#lv-swap-search')`),
      'Swap output token search input',
    )
    await setInputValue(cdp, '#lv-swap-search', 'USDC')
    await waitFor(async () => {
      return cdp!.eval<boolean>(
        `Array.from(document.querySelectorAll('.lv-search-item')).some((b) => /USDC/i.test(b.textContent || ''))`,
      )
    }, 'USDC in live Jupiter token search results')
    const pickedOut = await clickButtonByText(cdp, 'USDC', { selector: '.lv-search-item' })
    console.log(`  ✓ Selected swap output token: "${pickedOut}"`)

    // Wait for Live Jupiter Quote card to render
    const quoteState = await waitFor(async () => {
      const st = await getUiState(cdp!)
      if (st.swapQuoteError) throw new Error(`Jupiter quote error in UI: ${st.swapQuoteError}`)
      if (st.swapQuoteText && st.swapQuoteText.includes('USDC') && !st.busySubmitText) return st
      return false
    }, 'Live Mainnet Jupiter quote in UI', 30_000)

    console.log(`  ✓ Live Jupiter Quote displayed: ${quoteState.swapQuoteText}`)
    await saveScreenshot(cdp, 'step5a-jupiter-quote.png')

    // Click Swap button!
    const swapClick = await clickButtonByText(cdp, 'Swap 0.01 SOL', {
      selector: '.lv-submit-btn',
    })
    console.log(`  ✓ Clicked "${swapClick}"`)

    // Wait for swap confirmation AND resolved USDC note!
    const afterSwap = await waitFor(async () => {
      const st = await getUiState(cdp!)
      if (st.errorBanner) throw new FatalUiError(`UI Error during Private Jupiter Swap: ${st.errorBanner}`)
      if (
        st.auditCount >= auditBase + 4 &&
        st.noteCount >= 1 &&
        st.noteRows.some((r) => r.includes('USDC') && !r.includes('Verifying')) &&
        !st.busySubmitText
      ) {
        return st
      }
      return false
    }, 'Private Jupiter Swap Mainnet confirmation + settled USDC note in Private Balance', 120_000)

    console.log(`  ✓ Audit #4: ${afterSwap.latestAudit?.kicker}`)
    console.log(`    Summary:  ${afterSwap.latestAudit?.summary}`)
    console.log(`    Proof:    ${afterSwap.latestAudit?.proverMs}`)
    console.log(`    Solscan:  ${afterSwap.latestAudit?.solscanUrl}`)
    console.log(`  ✓ Private Balance now: ${afterSwap.privateTotal} (${afterSwap.privateSub})`)
    console.log(`  ✓ Settled USDC Note: ${afterSwap.noteRows.join(' | ')}`)
    const usdcAmtStr = afterSwap.noteAmounts.find((a) => a.includes('USDC')) ?? ''
    const settledUsdcMatch = usdcAmtStr.match(/([\d,]+\.?\d*)\s*USDC/)
    const settledUsdc = settledUsdcMatch ? Number(settledUsdcMatch[1].replace(/,/g, '')) : null
    assert.ok(
      settledUsdc !== null && Number.isFinite(settledUsdc) && settledUsdc > 0.1,
      `Expected settled USDC > 0.1, got ${settledUsdc} (from "${usdcAmtStr}")`,
    )
    await assertRelayedOnChainPrivacy('Private Jupiter Swap', afterSwap.latestAudit?.solscanUrl, signer.address, true)
    await saveScreenshot(cdp, 'step5b-jupiter-swapped.png')

    // Respect live 12s anti-abuse cooldown before Go Public Withdraw
    console.log(`  ⏳ Waiting 13s for relay.audren.xyz anti-abuse cooldown…`)
    await sleep(13_000)

    // =========================================================================
    // STEP 6: Mainnet Go Public (Max settled USDC -> back to Public Wallet)
    // =========================================================================
    banner('STEP 6: Mainnet Go Public (Withdraw settled USDC back to Phantom via Web UI)')
    await clickButtonByText(cdp, 'Go Public', { selector: '[role="tab"]' })
    await waitFor(
      () => cdp!.eval<boolean>(`!!document.querySelector('#lv-wd-amt')`),
      'Go Public amount input',
    )
    await clickButtonByText(cdp, 'Max', { exact: true })
    await sleep(200)
    const withdrawClick = await clickButtonByText(cdp, 'Go Public with', {
      selector: '.lv-submit-btn',
    })
    console.log(`  ✓ Clicked "${withdrawClick}"`)

    const afterWithdraw = await waitFor(async () => {
      const st = await getUiState(cdp!)
      if (st.errorBanner) throw new FatalUiError(`UI Error during Go Public: ${st.errorBanner}`)
      if (st.auditCount >= auditBase + 5 && st.noteCount === 0 && !st.busySubmitText) return st
      return false
    }, 'Go Public Mainnet confirmation + Private Balance back to $0.00', 120_000)

    console.log(`  ✓ Audit #5: ${afterWithdraw.latestAudit?.kicker}`)
    console.log(`    Summary:  ${afterWithdraw.latestAudit?.summary}`)
    console.log(`    Proof:    ${afterWithdraw.latestAudit?.proverMs}`)
    console.log(`    Solscan:  ${afterWithdraw.latestAudit?.solscanUrl}`)
    console.log(`  ✓ Private Balance now: ${afterWithdraw.privateTotal} (${afterWithdraw.privateSub})`)
    await assertRelayedOnChainPrivacy('Go Public Withdraw', afterWithdraw.latestAudit?.solscanUrl, signer.address, false)

    // Verify Public Wallet USDC actually increased by settledUsdc!
    if (initialPublicUsdc !== null && settledUsdc !== null) {
      await clickButtonByText(cdp, 'TOKENS', { exact: true })
      await setInputValue(cdp, '.lv-public-drawer-list input', 'USDC')
      await sleep(300)
      const afterUsdcRow = await cdp.eval<string>(
        `(document.querySelector('.lv-public-drawer-list .lv-balance-amt')?.textContent || '').replace(/\\s+/g, ' ').trim()`,
      )
      const finalMatch = afterUsdcRow.match(/([\d,]+\.?\d*)\s*USDC/)
      const finalPublicUsdc = finalMatch ? Number(finalMatch[1].replace(/,/g, '')) : null
      console.log(
        `  ✓ Public Wallet USDC: ${initialPublicUsdc.toFixed(6)} → ${finalPublicUsdc?.toFixed(6)} (expected +${settledUsdc.toFixed(6)})`,
      )
      if (finalPublicUsdc !== null) {
        const diff = finalPublicUsdc - initialPublicUsdc
        // Tolerate optional self-paying native relay fee deducted from the withdrawn USDC note.
        assert.ok(
          diff > 0 && diff <= settledUsdc + 0.002 && settledUsdc - diff < Math.max(0.25, settledUsdc * 0.15),
          `USDC delta mismatch: actual +${diff.toFixed(6)} vs settled +${settledUsdc.toFixed(6)}`,
        )
      }
      await clickButtonByText(cdp, 'HIDE TOKENS', { exact: true })
    }
    await saveScreenshot(cdp, 'step6-go-public.png')

    // =========================================================================
    // STEP 7: Stranger View + Encrypted Backup Export + Full Rescan
    // =========================================================================
    banner('STEP 7: Stranger View + Encrypted Backup Export + Full Rescan via Web UI')
    await clickButtonByText(cdp, 'STRANGER VIEW')
    const strangerOn = await cdp.eval<boolean>(
      `!!document.querySelector('.lv-private-card.is-stranger')`,
    )
    assert.ok(strangerOn, 'Stranger View class .is-stranger did not activate')
    console.log(`  ✓ Stranger View toggled ON cleanly`)
    await saveScreenshot(cdp, 'step7a-stranger-view.png')
    await clickButtonByText(cdp, 'MY VIEW')

    // Backup & Sync panel: export encrypted JSON + Full Rescan from Page 0
    await clickButtonByText(cdp, 'BACKUP & SYNC')
    await waitFor(
      () => cdp!.eval<boolean>(`!!document.querySelector('.lv-backup-box input[type="password"]')`),
      'Backup passphrase input',
    )
    await setInputValue(cdp, '.lv-backup-box input[type="password"]', 'AudrenE2E-TestPass-2026!')
    await clickButtonByText(cdp, 'EXPORT .JSON')
    const afterExport = await waitFor(async () => {
      const st = await getUiState(cdp!)
      return st.backupStatus && /encrypted|saved|exported|download/i.test(st.backupStatus)
        ? st.backupStatus
        : false
    }, 'Encrypted backup export status message')
    console.log(`  ✓ Backup Export: ${afterExport}`)

    await clickButtonByText(cdp, 'FULL RESCAN FROM PAGE 0')
    await sleep(1200)
    await waitFor(async () => {
      const st = await getUiState(cdp!)
      return !st.privateSub.includes('Scanning') ? st : false
    }, 'Full Rescan from Page 0 completion')
    console.log(`  ✓ Full Rescan from Page 0 completed cleanly`)
    await saveScreenshot(cdp, 'step7b-backup-rescan.png')

    // =========================================================================
    // STEP 8: Disconnect + Free Devnet Interactive Sandbox (1 Deposit -> 2 Spend -> 3 Receipt & Forgery)
    // =========================================================================
    banner('STEP 8: Disconnect → Free Devnet Sandbox (Deposit → Private Spend → Real & Forged Receipts)')
    await clickButtonByText(cdp, 'DISCONNECT', { exact: true })
    await waitFor(
      () =>
        cdp!.eval<boolean>(
          `Array.from(document.querySelectorAll('button')).some((b) => /NO WALLET/i.test(b.textContent || ''))`,
        ),
      'NO WALLET? TRY FREE DEVNET TEST button after Disconnect',
    )
    await clickButtonByText(cdp, 'NO WALLET? TRY FREE DEVNET TEST')
    await waitFor(async () => {
      return cdp!.eval<boolean>(
        `Array.from(document.querySelectorAll('button')).some((b) => /Free Test SOL Privately/i.test(b.textContent || ''))`,
      )
    }, 'Sandbox Step 1 button')

    // Sandbox Step 1: Deposit
    const sb1Click = await clickButtonByText(cdp, 'Free Test SOL Privately')
    console.log(`  ✓ Sandbox Step 1 clicked: "${sb1Click}"`)
    const sb1Proof = await waitFor(async () => {
      const err = await cdp!.eval<string | null>(
        `document.querySelector('.alert-banner.is-error')?.textContent?.trim() || null`,
      )
      if (err) throw new Error(`Sandbox Step 1 error: ${err}`)
      const txt = await cdp!.eval<string>(
        `document.querySelector('.sb-mini-proof')?.textContent?.replace(/\\s+/g, ' ').trim() || ''`,
      )
      return txt.includes('CONFIRMED ON DEVNET') ? txt : false
    }, 'Sandbox Step 1 Devnet deposit confirmation', 90_000)
    console.log(`  ✓ Sandbox Step 1 confirmed: ${sb1Proof.slice(0, 140)}`)

    // Sandbox Step 2: Private Spend (zero wallet — paid by Devnet Relayer)
    await clickButtonByText(cdp, 'Next: Send Privately')
    await waitFor(async () => {
      return cdp!.eval<boolean>(
        `Array.from(document.querySelectorAll('button')).some((b) => /Send Privately Live/i.test(b.textContent || ''))`,
      )
    }, 'Sandbox Step 2 button')
    const sb2Click = await clickButtonByText(cdp, 'Send Privately Live')
    console.log(`  ✓ Sandbox Step 2 clicked: "${sb2Click}"`)
    const sb2Proof = await waitFor(async () => {
      const err = await cdp!.eval<string | null>(
        `document.querySelector('.alert-banner.is-error')?.textContent?.trim() || null`,
      )
      if (err) throw new Error(`Sandbox Step 2 error: ${err}`)
      const txt = await cdp!.eval<string>(
        `document.querySelector('.sb-mini-proof.is-dark-proof')?.textContent?.replace(/\\s+/g, ' ').trim() || ''`,
      )
      return txt.includes('PRIVATE SPEND CONFIRMED') ? txt : false
    }, 'Sandbox Step 2 Devnet Private Spend confirmation', 120_000)
    console.log(`  ✓ Sandbox Step 2 confirmed: ${sb2Proof.slice(0, 160)}`)

    // Sandbox Step 3: Real Receipt + Forged Receipt Rejection
    await clickButtonByText(cdp, 'Next: Verify Commitment Receipt')
    await clickButtonByText(cdp, 'Create Real Receipt')
    const validStamp = await waitFor(async () => {
      const txt = await cdp!.eval<string>(
        `document.querySelector('.verify-strip.is-valid')?.textContent?.replace(/\\s+/g, ' ').trim() || ''`,
      )
      return txt.includes('VERIFIED BY SOLANA') ? txt : false
    }, 'Valid Selective Disclosure Receipt verification')
    console.log(`  ✓ Sandbox Step 3a (Real Receipt): ${validStamp}`)

    await clickButtonByText(cdp, 'Try Faking the Amount')
    const forgedStamp = await waitFor(async () => {
      const txt = await cdp!.eval<string>(
        `document.querySelector('.verify-strip.is-invalid')?.textContent?.replace(/\\s+/g, ' ').trim() || ''`,
      )
      return txt.includes('FORGERY CAUGHT') ? txt : false
    }, 'Forged Selective Disclosure Receipt rejection')
    console.log(`  ✓ Sandbox Step 3b (Forged Receipt): ${forgedStamp}`)
    await saveScreenshot(cdp, 'step8-devnet-sandbox.png')

    // =========================================================================
    // FINAL SUMMARY & STRICT ZERO-ERROR AUDIT
    // =========================================================================
    const elapsedSec = ((Date.now() - t0) / 1000).toFixed(1)
    banner(`ALL 8/8 LIVE WEB UI E2E FLOWS COMPLETED in ${elapsedSec}s`)
    console.log(`  Wallet signatures: ${signedMessageCount} signMessage, ${signedTxCount} signed tx(s)`)
    console.log(`  Console errors:    ${consoleErrors.length}`)
    console.log(`  Page exceptions:   ${pageExceptions.length}`)
    console.log(`  HTTP >= 400:       ${failedHttp.length}`)
    if (failedHttp.length > 0) {
      for (const h of failedHttp) console.log(`    - HTTP ${h.status}: ${h.url}`)
    }
    assert.equal(pageExceptions.length, 0, `Uncaught page exceptions: ${pageExceptions.join(' | ')}`)
    assert.equal(consoleErrors.length, 0, `Console errors: ${consoleErrors.join(' | ')}`)
  } catch (err) {
    if (cdp) {
      try {
        const snap = await getUiState(cdp)
        console.error('  [DIAG UI STATE]', JSON.stringify(snap, null, 2))
        console.error('  [DIAG CONSOLE ERRORS]', consoleErrors)
        console.error('  [DIAG PAGE EXCEPTIONS]', pageExceptions)
        console.error('  [DIAG FAILED HTTP]', failedHttp)
        await saveScreenshot(cdp, 'failure-diag.png')
      } catch {}
    }
    throw err
  } finally {
    cdp?.close()
    try {
      proc.kill('SIGTERM')
    } catch {
      // ignore
    }
    try {
      fs.rmSync(userDataDir, { recursive: true, force: true })
    } catch {
      // ignore
    }
  }
}

main().catch((err) => {
  console.error('\n❌ WEB UI E2E FAILED:', err)
  process.exit(1)
})
