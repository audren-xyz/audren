/**
 * SPL Token-2022 mint extension parsers and fee-on-transfer net amount helpers.
 *
 * Shared canonical implementation used by `@audren/sdk`, `apps/relay`, and `apps/web`
 * so wallets and relayers never drift on Token-2022 TLV offsets or epoch-aware fee selection.
 */

const TOKEN_2022_ACCOUNT_TYPE_OFFSET = 165;
const TOKEN_2022_ACCOUNT_TYPE_MINT = 1;
const TOKEN_2022_TLV_START = 166;

const EXT_TRANSFER_FEE_CONFIG = 1;
const EXT_NON_TRANSFERABLE = 9;
const EXT_PERMANENT_DELEGATE = 12;
const EXT_TRANSFER_HOOK = 14;

/** Maximum TransferFeeConfig basis points permitted for relayer self-pay fee settlement (5%). */
export const MAX_SELF_PAY_TRANSFER_FEE_BPS = 500;

export interface Token2022TransferFee {
  bps: bigint;
  maxFee: bigint;
  epoch: bigint;
}

/**
 * Parse a Token-2022 mint's `TransferFeeConfig` extension (TLV type `1`, 108 bytes)
 * and select the active fee schedule for `currentEpoch` (`newer_transfer_fee` if
 * `BigInt(currentEpoch) >= newerEpoch`, else `older_transfer_fee`).
 *
 * Returns `null` if the mint has no `TransferFeeConfig` extension or the active `bps === 0n`.
 */
export function parseToken2022TransferFeeConfig(
  mintData: Uint8Array | null | undefined,
  currentEpoch: bigint | number,
): Token2022TransferFee | null {
  if (
    !mintData ||
    mintData.byteLength <= TOKEN_2022_TLV_START ||
    mintData[TOKEN_2022_ACCOUNT_TYPE_OFFSET] !== TOKEN_2022_ACCOUNT_TYPE_MINT
  ) {
    return null;
  }
  const epoch = BigInt(currentEpoch);
  const dv = new DataView(mintData.buffer, mintData.byteOffset, mintData.byteLength);
  let pos = TOKEN_2022_TLV_START;
  while (pos + 4 <= mintData.byteLength) {
    const extType = dv.getUint16(pos, true);
    if (extType === 0) break;
    const extLen = dv.getUint16(pos + 2, true);
    const valStart = pos + 4;
    const valEnd = valStart + extLen;
    if (valEnd > mintData.byteLength) break;
    if (extType === EXT_TRANSFER_FEE_CONFIG && extLen >= 108) {
      // TransferFeeConfig layout:
      //   0..32   transfer_fee_config_authority
      //   32..64  withdraw_withheld_authority
      //   64..72  withheld_amount (u64 LE)
      //   72..90  older_transfer_fee { epoch: u64 LE, maximum_fee: u64 LE, bps: u16 LE }
      //   90..108 newer_transfer_fee { epoch: u64 LE, maximum_fee: u64 LE, bps: u16 LE }
      const olderEpoch = dv.getBigUint64(valStart + 72, true);
      const olderMaxFee = dv.getBigUint64(valStart + 80, true);
      const olderBps = BigInt(dv.getUint16(valStart + 88, true));

      const newerEpoch = dv.getBigUint64(valStart + 90, true);
      const newerMaxFee = dv.getBigUint64(valStart + 98, true);
      const newerBps = BigInt(dv.getUint16(valStart + 106, true));

      const active: Token2022TransferFee =
        epoch >= newerEpoch
          ? { epoch: newerEpoch, maxFee: newerMaxFee, bps: newerBps }
          : { epoch: olderEpoch, maxFee: olderMaxFee, bps: olderBps };
      return active.bps === 0n ? null : active;
    }
    pos = valEnd;
  }
  return null;
}

/**
 * Compute exact net received base units after SPL Token-2022 `TransferFee` ceiling deduction.
 */
export function computeToken2022NetAmount(
  grossAmount: bigint,
  fee: Token2022TransferFee | null,
): bigint {
  if (!fee || fee.bps <= 0n || grossAmount <= 0n) return grossAmount;
  const rawFee =
    fee.bps >= 10_000n ? grossAmount : (grossAmount * fee.bps + 9_999n) / 10_000n;
  const capped = rawFee > fee.maxFee ? fee.maxFee : rawFee;
  return grossAmount > capped ? grossAmount - capped : 0n;
}

/**
 * Return `true` if a Token-2022 mint carries extensions unsafe for relayer self-pay fee settlement:
 * - Malformed TLV or non-Mint account type past offset 165
 * - `NonTransferable` (9) or `PermanentDelegate` (12)
 * - Active `TransferHook` (14) with a non-zero hook program ID
 * - `TransferFeeConfig` (1) with either older or newer fee > 500 bps (5%)
 */
export function inspectToken2022UnsafeSelfPay(mintData: Uint8Array | null | undefined): boolean {
  if (!mintData || mintData.byteLength <= TOKEN_2022_TLV_START) return false;
  if (mintData[TOKEN_2022_ACCOUNT_TYPE_OFFSET] !== TOKEN_2022_ACCOUNT_TYPE_MINT) return true;
  const dv = new DataView(mintData.buffer, mintData.byteOffset, mintData.byteLength);
  let pos = TOKEN_2022_TLV_START;
  while (pos + 4 <= mintData.byteLength) {
    const extType = dv.getUint16(pos, true);
    if (extType === 0) break;
    const extLen = dv.getUint16(pos + 2, true);
    const valStart = pos + 4;
    const valEnd = valStart + extLen;
    if (valEnd > mintData.byteLength) return true;
    if (extType === EXT_NON_TRANSFERABLE || extType === EXT_PERMANENT_DELEGATE) return true;
    if (extType === EXT_TRANSFER_HOOK && extLen >= 64) {
      for (let i = 32; i < 64; i++) {
        if (mintData[valStart + i] !== 0) return true;
      }
    }
    if (extType === EXT_TRANSFER_FEE_CONFIG && extLen >= 108) {
      const olderBps = dv.getUint16(valStart + 88, true);
      const newerBps = dv.getUint16(valStart + 106, true);
      if (olderBps > MAX_SELF_PAY_TRANSFER_FEE_BPS || newerBps > MAX_SELF_PAY_TRANSFER_FEE_BPS) {
        return true;
      }
    }
    pos = valEnd;
  }
  return false;
}
