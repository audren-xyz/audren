#!/usr/bin/env python3
"""Generate deterministic Codama (v1.8.0) and Anchor-compatible (v0.30+) IDLs for all Audren programs.

Reads authoritative constants (program ID, error codes 1..=33, instruction tags 0..=12, PDA seeds,
account magics, and fixed byte lengths) directly from `crates/audren-core/src/` so the published
IDLs can never drift from the on-chain sBPFv3 Pinocchio programs.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORE_DIR = ROOT / "crates" / "audren-core" / "src"
IDL_DIR = ROOT / "idl"
SDK_IDL_DIR = ROOT / "packages" / "sdk" / "idl"

CODAMA_VERSION = "1.8.0"


def read_toml_value(manifest_path: Path, section: str, key: str) -> str:
    """Read a quoted string value strictly inside a single TOML `[section]`."""
    text = manifest_path.read_text()
    in_section = False
    target = f"[{section}]"
    key_re = re.compile(rf'^{re.escape(key)}\s*=\s*"([^"]+)"')
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            in_section = line == target
            continue
        if in_section:
            m = key_re.match(line)
            if m:
                return m.group(1)
    raise RuntimeError(f"Could not parse [{section}].{key} from {manifest_path}")


def read_cargo_version(manifest_path: Path) -> str:
    return read_toml_value(manifest_path, "package", "version")


PROGRAM_VERSION = read_cargo_version(ROOT / "program" / "Cargo.toml")
MOCK_ROUTER_VERSION = read_cargo_version(ROOT / "tests" / "mock-router" / "Cargo.toml")


def parse_core_constants() -> dict:
    lib_rs = (CORE_DIR / "lib.rs").read_text()
    ix_rs = (CORE_DIR / "instruction.rs").read_text()
    layout_rs = (CORE_DIR / "layout.rs").read_text()

    prog_id_m = re.search(r'AUDREN_PROGRAM_ID: Bytes32 =\s*decode_base58\("([^"]+)"\)', lib_rs)
    if not prog_id_m:
        raise RuntimeError("Could not parse AUDREN_PROGRAM_ID from crates/audren-core/src/lib.rs")
    program_id = prog_id_m.group(1)

    # Parse AudrenError enum variants (exact codes 1..=33)
    err_block_m = re.search(r"pub enum AudrenError \{([^}]+)\}", lib_rs, re.S)
    if not err_block_m:
        raise RuntimeError("Could not parse AudrenError enum")
    errors: list[tuple[str, int]] = []
    for name, code_s in re.findall(r"([A-Za-z0-9_]+)\s*=\s*(\d+),", err_block_m.group(1)):
        errors.append((name, int(code_s)))

    # Parse instruction tags 0..=12
    tags: dict[str, int] = {}
    for name, val_s in re.findall(r"pub const (TAG_[A-Z0-9_]+):\s*u8\s*=\s*(\d+);", ix_rs):
        tags[name] = int(val_s)

    # Parse PDA seeds
    seeds: dict[str, str] = {}
    for name, val in re.findall(r'pub const ([A-Z0-9_]+_SEED):\s*&\[u8\]\s*=\s*b"([^"]+)";', lib_rs):
        seeds[name] = val

    # Parse account magics
    magics: dict[str, str] = {}
    for name, val in re.findall(r'pub const ([A-Z0-9_]+_MAGIC):\s*\[u8;\s*8\]\s*=\s*\*b"([^"]+)";', layout_rs):
        magics[name] = val

    # Parse fixed lengths (including derived PAGE_LEN from layout.rs constants)
    lengths: dict[str, int] = {}
    for name, val_s in re.findall(r"pub const ([A-Z0-9_]+(?:_LEN|_CAPACITY)):\s*usize\s*=\s*([0-9_]+);", layout_rs):
        lengths[name] = int(val_s.replace("_", ""))
    if "PAGE_LEN" not in lengths:
        cap = lengths["PAGE_CAPACITY"]
        ct = lengths["NOTE_CT_LEN"]
        hdr = lengths["PAGE_HEADER_LEN"]
        lengths["PAGE_LEN"] = hdr + cap * (1 + 32 + 32 + 32 + 32 + ct)

    return {
        "program_id": program_id,
        "errors": errors,
        "tags": tags,
        "seeds": seeds,
        "magics": magics,
        "lengths": lengths,
    }


ERROR_DOCS: dict[str, str] = {
    "InvalidInstruction": "Malformed instruction tag, length, or argument encoding.",
    "InvalidAccount": "Missing, unwritable, wrong-owner, or aliased account.",
    "InvalidPda": "Account address does not match expected PDA derivation.",
    "InvalidMagic": "Account 8-byte ASCII magic discriminator mismatch.",
    "UnsupportedVersion": "Account protocol_version is not supported by this program build.",
    "PoolPaused": "Pool is paused by governance authority (full withdrawals remain open).",
    "Unauthorized": "Required signer is missing or does not match pool/buffer authority.",
    "UnsupportedTokenProgram": "Token program must be Classic SPL Token or Token-2022.",
    "UnsafeMintExtension": "Mint carries an unsupported or unsafe extension.",
    "ZeroAmount": "Deposit, swap, or withdrawal amount must be strictly greater than zero.",
    "PageFull": "Target EpochPage is already closed or has reached PAGE_CAPACITY (32 notes).",
    "PageNotReady": "Current EpochPage still has more than PAGE_ROLLOVER_HEADROOM (4) free slots.",
    "PageEmpty": "Input EpochPage contains zero notes and cannot form a Triptych ring.",
    "DuplicateOrUnorderedPages": "Input EpochPage IDs must be strictly ascending without duplicates.",
    "WrongPool": "EpochPage or lane belongs to a different pool_id or wrong active page_id.",
    "NullifierAlreadySpent": "NullifierPDA already exists (note is already spent or duplicated in Merge).",
    "InvalidPoint": "Bytes are not a canonical compressed Ristretto255 curve point (or forbidden identity).",
    "InvalidScalar": "Bytes are not a canonical Curve25519 scalar (< L).",
    "InvalidTriptychProof": "Multi-Base Binary Triptych ring proof verification failed.",
    "InvalidCrossBaseProof": "Cross-base Pedersen bridge proof (1-output or 2-output) verification failed.",
    "InvalidRangeProof": "Native Agave Bulletproof range proof CPI verification failed.",
    "InvalidAuditorProof": "Verifiable Auditor ElGamal asset-tag proof verification failed.",
    "MissingAuditorKey": "InstitutionalAudited pool requires a valid non-identity auditor_pk.",
    "InvalidEscrowShard": "Swap escrow shard_id must be in 0..16.",
    "InvalidRouterProgram": "Router program must be executable and cannot be Audren, System, ZK, or Token.",
    "EscrowAuthorityAltered": "Swap escrow PDA owner, data length, or lamport balance was altered by router CPI.",
    "EscrowAccountAltered": "Swap escrow token account owner, delegate, close_authority, or balance was altered.",
    "SlippageExceeded": "Net output received in pool vault is below min_amount_out (or zero).",
    "UnexpectedPartialFill": "Router left unspent input tokens when allow_partial_refund flag was not set.",
    "ArithmeticOverflow": "Checked integer arithmetic overflow or underflow.",
    "InsufficientPageRent": "Insufficient lamports to fund page rent.",
    "InvalidProofBuffer": "Invalid ProofBuffer header, authority, chunk index, length, or completion mask.",
    "InvalidLane": "Invalid parallel append lane_id (must be 1..16 and sequentially initialized).",
}


# ---------------------------------------------------------------------------
# Codama v1.8.0 node builders
# ---------------------------------------------------------------------------

def num_t(fmt: str) -> dict:
    return {"kind": "numberTypeNode", "format": fmt, "endian": "le"}


def bytes_t() -> dict:
    return {"kind": "bytesTypeNode"}


def fixed_bytes_t(size: int) -> dict:
    return {"kind": "fixedSizeTypeNode", "size": size, "type": bytes_t()}


def fixed_array_t(item: dict, count: int) -> dict:
    return {
        "kind": "arrayTypeNode",
        "item": item,
        "count": {"kind": "fixedCountNode", "value": count},
    }


def pubkey_t() -> dict:
    return {"kind": "publicKeyTypeNode"}


def bool_t() -> dict:
    return {"kind": "booleanTypeNode", "size": num_t("u8")}


def field_n(name: str, typ: dict, docs: list[str] | None = None) -> dict:
    n = {"kind": "structFieldTypeNode", "name": name, "type": typ}
    if docs:
        n["docs"] = docs
    return n


def ix_arg(name: str, typ: dict, docs: list[str] | None = None, default_val: dict | None = None, omitted: bool = False) -> dict:
    n: dict = {"kind": "instructionArgumentNode", "name": name, "type": typ}
    if docs:
        n["docs"] = docs
    if default_val is not None:
        n["defaultValue"] = default_val
        if omitted:
            n["defaultValueStrategy"] = "omitted"
    return n


def ix_disc_arg(tag: int) -> dict:
    return ix_arg(
        "discriminator",
        num_t("u8"),
        default_val={"kind": "numberValueNode", "number": tag},
        omitted=True,
    )


def ix_acc(
    name: str,
    is_writable: bool,
    is_signer: bool,
    docs: list[str],
    is_optional: bool = False,
    pda_name: str | None = None,
) -> dict:
    node: dict = {
        "kind": "instructionAccountNode",
        "name": name,
        "isWritable": is_writable,
        "isSigner": is_signer,
        "isOptional": is_optional,
        "docs": docs,
    }
    if pda_name is not None:
        node["defaultValue"] = {
            "kind": "pdaValueNode",
            "pda": {"kind": "pdaLinkNode", "name": pda_name},
            "seeds": [],
        }
    return node


def const_seed(ascii_str: str) -> dict:
    return {
        "kind": "constantPdaSeedNode",
        "type": fixed_bytes_t(len(ascii_str)),
        "value": {"kind": "bytesValueNode", "encoding": "utf8", "data": ascii_str},
    }


def var_seed(name: str, typ: dict, docs: list[str] | None = None) -> dict:
    n: dict = {"kind": "variablePdaSeedNode", "name": name, "type": typ}
    if docs:
        n["docs"] = docs
    return n


def pda_node(name: str, seeds: list[dict], docs: list[str]) -> dict:
    return {"kind": "pdaNode", "name": name, "seeds": seeds, "docs": docs}


def magic_disc(magic_ascii: str) -> dict:
    return {
        "kind": "constantDiscriminatorNode",
        "offset": 0,
        "constant": {
            "kind": "constantValueNode",
            "type": fixed_bytes_t(len(magic_ascii)),
            "value": {"kind": "bytesValueNode", "encoding": "utf8", "data": magic_ascii},
        },
    }


def tag_disc(tag: int) -> dict:
    return {
        "kind": "constantDiscriminatorNode",
        "offset": 0,
        "constant": {
            "kind": "constantValueNode",
            "type": num_t("u8"),
            "value": {"kind": "numberValueNode", "number": tag},
        },
    }


def build_audren_codama(core: dict) -> dict:
    tags = core["tags"]
    seeds = core["seeds"]
    magics = core["magics"]

    pdas = [
        pda_node("pool", [const_seed(seeds["POOL_SEED"]), var_seed("poolId", num_t("u32"))],
                 ["PoolState configuration and Lane 0 rollover state (192 B)."]),
        pda_node("epochPage", [const_seed(seeds["PAGE_SEED"]), var_seed("poolId", num_t("u32")), var_seed("pageId", num_t("u64"))],
                 ["Fixed 6,240 B Structure-of-Arrays EpochPage storing up to 32 notes. pageId = (laneId << 56) | seq."]),
        pda_node("nullifier", [const_seed(seeds["NULLIFIER_SEED"]), var_seed("poolId", num_t("u32")), var_seed("nullifier", fixed_bytes_t(32))],
                 ["0-byte NullifierPDA owned by Audren; its existence permanently prevents double-spends."]),
        pda_node("vaultAuth", [const_seed(seeds["VAULT_AUTH_SEED"]), var_seed("poolId", num_t("u32"))],
                 ["System-owned signer PDA that owns every SPL / Token-2022 pool vault ATA."]),
        pda_node("solVault", [const_seed(seeds["SOL_VAULT_SEED"]), var_seed("poolId", num_t("u32"))],
                 ["Program-owned 16 B sentinel PDA holding shielded Native SOL lamports."]),
        pda_node("pageRentVault", [const_seed(seeds["PAGE_RENT_SEED"]), var_seed("poolId", num_t("u32"))],
                 ["Program-owned 16 B sentinel PDA funding permissionless Lane 0 EpochPage rollovers."]),
        pda_node("swapEscrow", [const_seed(seeds["ESCROW_SEED"]), var_seed("poolId", num_t("u32")), var_seed("shardId", num_t("u8"))],
                 ["Sharded (0..16) isolated signer PDA for atomic SwapViaRouter external DEX CPIs."]),
        pda_node("proofBuffer", [const_seed(seeds["PROOF_BUFFER_SEED"]), var_seed("authority", pubkey_t()), var_seed("nonce", num_t("u64"))],
                 ["Ephemeral PDA staging oversized (>4 KiB) proof/swap payloads across <=768 B chunks."]),
        pda_node("appendLane", [const_seed(seeds["LANE_SEED"]), var_seed("poolId", num_t("u32")), var_seed("laneId", num_t("u8"))],
                 ["AppendLaneState (64 B) for lock-free parallel append lanes 1..15."]),
        pda_node("laneRentVault", [const_seed(seeds["LANE_RENT_SEED"]), var_seed("poolId", num_t("u32")), var_seed("laneId", num_t("u8"))],
                 ["Program-owned 16 B sentinel PDA funding permissionless rollovers for parallel lane 1..15."]),
    ]

    defined_types = [
        {
            "kind": "definedTypeNode",
            "name": "poolMode",
            "docs": ["Pool privacy/compliance operating mode."],
            "type": {
                "kind": "enumTypeNode",
                "size": num_t("u8"),
                "variants": [
                    {"kind": "enumEmptyVariantTypeNode", "name": "permissionless"},
                    {"kind": "enumEmptyVariantTypeNode", "name": "institutionalAudited"},
                ],
            },
        },
        {
            "kind": "definedTypeNode",
            "name": "noteWire",
            "docs": ["193-byte note wire block (viewTag + ephemeralPk + stealthPk + assetTag + commitment + 64 B ciphertext)."],
            "type": {
                "kind": "structTypeNode",
                "fields": [
                    field_n("viewTag", num_t("u8")),
                    field_n("ephemeralPk", fixed_bytes_t(32)),
                    field_n("stealthPk", fixed_bytes_t(32)),
                    field_n("assetTag", fixed_bytes_t(32)),
                    field_n("commitment", fixed_bytes_t(32)),
                    field_n("ciphertext", fixed_bytes_t(64)),
                ],
            },
        },
        {
            "kind": "definedTypeNode",
            "name": "dynamicOutputWire",
            "docs": ["129-byte stealth output descriptor used when assetTag and commitment are computed on-chain (Deposit, SwapViaRouter)."],
            "type": {
                "kind": "structTypeNode",
                "fields": [
                    field_n("viewTag", num_t("u8")),
                    field_n("ephemeralPk", fixed_bytes_t(32)),
                    field_n("stealthPk", fixed_bytes_t(32)),
                    field_n("ciphertext", fixed_bytes_t(64)),
                ],
            },
        },
        {
            "kind": "definedTypeNode",
            "name": "pageHeader",
            "docs": ["64-byte EpochPage header stored at byte offsets 0..64."],
            "type": {
                "kind": "structTypeNode",
                "fields": [
                    field_n("magic", fixed_bytes_t(8), ["ASCII 'AUDRNPG1'"]),
                    field_n("version", num_t("u8")),
                    field_n("bump", num_t("u8")),
                    field_n("closed", bool_t()),
                    field_n("count", num_t("u8"), ["Number of populated note slots (0..=32)."]),
                    field_n("poolId", num_t("u32")),
                    field_n("pageId", num_t("u64")),
                    field_n("createdSlot", num_t("u64")),
                    field_n("closedSlot", num_t("u64")),
                    field_n("reserved", fixed_bytes_t(24)),
                ],
            },
        },
    ]

    accounts = [
        {
            "kind": "accountNode",
            "name": "poolState",
            "size": 192,
            "docs": ["Root pool state PDA (192 bytes, magic 'AUDRNPL1')."],
            "pda": {"kind": "pdaLinkNode", "name": "pool"},
            "discriminators": [magic_disc(magics["POOL_MAGIC"])],
            "data": {
                "kind": "structTypeNode",
                "fields": [
                    field_n("magic", fixed_bytes_t(8), ["ASCII 'AUDRNPL1'"]),
                    field_n("version", num_t("u8")),
                    field_n("bump", num_t("u8")),
                    field_n("mode", {"kind": "definedTypeLinkNode", "name": "poolMode"}),
                    field_n("paused", bool_t()),
                    field_n("poolId", num_t("u32")),
                    field_n("currentPageId", num_t("u64")),
                    field_n("totalNotes", num_t("u64")),
                    field_n("totalSpends", num_t("u64")),
                    field_n("pageRentFeeLamports", num_t("u64")),
                    field_n("authority", pubkey_t()),
                    field_n("auditorPk", fixed_bytes_t(32), ["Ristretto255 K_aud when InstitutionalAudited, else 0."]),
                    field_n("auditorLocked", bool_t()),
                    field_n("vaultAuthBump", num_t("u8")),
                    field_n("solVaultBump", num_t("u8")),
                    field_n("pageRentBump", num_t("u8")),
                    field_n("activeLanes", num_t("u8"), ["0 or 1 = Lane 0 only; 2..=16 = parallel lanes 0..N-1 active."]),
                    field_n("reserved", fixed_bytes_t(75)),
                ],
            },
        },
        {
            "kind": "accountNode",
            "name": "epochPage",
            "size": 6240,
            "docs": [
                "Structure-of-Arrays note page PDA (6,240 bytes, 32 notes/page, magic 'AUDRNPG1').",
                "Pure-RPC scan slice: dataSlice { offset: 64, length: 1056 } reads viewTags[32] + ephemeralPks[32].",
            ],
            "pda": {"kind": "pdaLinkNode", "name": "epochPage"},
            "discriminators": [magic_disc(magics["PAGE_MAGIC"])],
            "data": {
                "kind": "structTypeNode",
                "fields": [
                    field_n("magic", fixed_bytes_t(8), ["ASCII 'AUDRNPG1'"]),
                    field_n("version", num_t("u8")),
                    field_n("bump", num_t("u8")),
                    field_n("closed", bool_t()),
                    field_n("count", num_t("u8")),
                    field_n("poolId", num_t("u32")),
                    field_n("pageId", num_t("u64")),
                    field_n("createdSlot", num_t("u64")),
                    field_n("closedSlot", num_t("u64")),
                    field_n("reserved", fixed_bytes_t(24)),
                    field_n("viewTags", fixed_bytes_t(32), ["Offsets 64..96: 1-byte ECDH view tag per note."]),
                    field_n("ephemeralPks", fixed_array_t(fixed_bytes_t(32), 32), ["Offsets 96..1120: Ristretto255 ephemeral pubkeys R."]),
                    field_n("stealthPks", fixed_array_t(fixed_bytes_t(32), 32), ["Offsets 1120..2144: Ristretto255 stealth pubkeys P."]),
                    field_n("assetTags", fixed_array_t(fixed_bytes_t(32), 32), ["Offsets 2144..3168: blinded asset generators A."]),
                    field_n("commitments", fixed_array_t(fixed_bytes_t(32), 32), ["Offsets 3168..4192: Pedersen value commitments V."]),
                    field_n("ciphertexts", fixed_array_t(fixed_bytes_t(64), 32), ["Offsets 4192..6240: 64 B encrypted note metadata."]),
                ],
            },
        },
        {
            "kind": "accountNode",
            "name": "appendLaneState",
            "size": 64,
            "docs": ["Parallel append lane metadata PDA (64 bytes, magic 'AUDRNLN1') for lanes 1..15."],
            "pda": {"kind": "pdaLinkNode", "name": "appendLane"},
            "discriminators": [magic_disc(magics["LANE_MAGIC"])],
            "data": {
                "kind": "structTypeNode",
                "fields": [
                    field_n("magic", fixed_bytes_t(8), ["ASCII 'AUDRNLN1'"]),
                    field_n("version", num_t("u8")),
                    field_n("laneId", num_t("u8")),
                    field_n("bump", num_t("u8")),
                    field_n("rentVaultBump", num_t("u8")),
                    field_n("poolId", num_t("u32")),
                    field_n("currentPageId", num_t("u64")),
                    field_n("createdSlot", num_t("u64")),
                    field_n("reserved", fixed_bytes_t(32)),
                ],
            },
        },
        {
            "kind": "accountNode",
            "name": "solVaultSentinel",
            "size": 16,
            "docs": ["Native SOL vault sentinel PDA (16 bytes, magic 'AUDRNSL1')."],
            "pda": {"kind": "pdaLinkNode", "name": "solVault"},
            "discriminators": [magic_disc(magics["SOL_VAULT_MAGIC"])],
            "data": {
                "kind": "structTypeNode",
                "fields": [
                    field_n("magic", fixed_bytes_t(8), ["ASCII 'AUDRNSL1'"]),
                    field_n("bump", num_t("u8")),
                    field_n("reserved", fixed_bytes_t(7)),
                ],
            },
        },
        {
            "kind": "accountNode",
            "name": "pageRentSentinel",
            "size": 16,
            "docs": ["Self-balancing page-rent vault sentinel PDA (16 bytes, magic 'AUDRNRN1') used by Lane 0 and Lanes 1..15."],
            "pda": {"kind": "pdaLinkNode", "name": "pageRentVault"},
            "discriminators": [magic_disc(magics["PAGE_RENT_MAGIC"])],
            "data": {
                "kind": "structTypeNode",
                "fields": [
                    field_n("magic", fixed_bytes_t(8), ["ASCII 'AUDRNRN1'"]),
                    field_n("bump", num_t("u8")),
                    field_n("reserved", fixed_bytes_t(7)),
                ],
            },
        },
        {
            "kind": "accountNode",
            "name": "proofBufferHeader",
            "docs": ["48-byte ProofBuffer header followed by `expectedLen` payload bytes (max 9,984 B)."],
            "pda": {"kind": "pdaLinkNode", "name": "proofBuffer"},
            "discriminators": [magic_disc(magics["PROOF_BUFFER_MAGIC"])],
            "data": {
                "kind": "structTypeNode",
                "fields": [
                    field_n("magic", fixed_bytes_t(8), ["ASCII 'AUDRNBF1'"]),
                    field_n("authority", pubkey_t()),
                    field_n("expectedLen", num_t("u32")),
                    field_n("writtenMask", num_t("u16"), ["Bitmask of uploaded 768 B chunks (bits 0..numChunks)."]),
                    field_n("reserved", fixed_bytes_t(2)),
                    field_n("payload", bytes_t(), ["Buffered inner instruction payload bytes."]),
                ],
            },
        },
        {
            "kind": "accountNode",
            "name": "nullifierPda",
            "size": 0,
            "docs": ["0-byte program-owned marker account proving a note nullifier has been spent."],
            "pda": {"kind": "pdaLinkNode", "name": "nullifier"},
            "data": {"kind": "structTypeNode", "fields": []},
        },
    ]

    instructions = [
        {
            "kind": "instructionNode",
            "name": "initPool",
            "docs": ["Tag 0: Initialize a shielded pool, Lane 0 page 0, SOL vault, and self-balancing page-rent vault."],
            "discriminators": [tag_disc(tags["TAG_INIT_POOL"])],
            "accounts": [
                ix_acc("payer", True, True, ["Pool authority and rent payer."]),
                ix_acc("pool", True, False, ["PoolState PDA ['audren_pool', poolId]."], pda_name="pool"),
                ix_acc("page0", True, False, ["Initial EpochPage PDA ['audren_page', poolId, 0u64]."]),
                ix_acc("solVault", True, False, ["SOL vault sentinel PDA ['audren_sol', poolId]."], pda_name="solVault"),
                ix_acc("pageRentVault", True, False, ["Lane 0 rent vault sentinel PDA ['audren_rent', poolId]."], pda_name="pageRentVault"),
                ix_acc("systemProgram", False, False, ["Solana System Program."]),
            ],
            "arguments": [
                ix_disc_arg(tags["TAG_INIT_POOL"]),
                ix_arg("poolId", num_t("u32")),
                ix_arg("mode", {"kind": "definedTypeLinkNode", "name": "poolMode"}),
                ix_arg("auditorLocked", bool_t()),
                ix_arg("pageRentFeeLamports", num_t("u64")),
                ix_arg("auditorPk", fixed_bytes_t(32), ["Non-zero Ristretto255 K_aud for InstitutionalAudited; 32 zero bytes for Permissionless."]),
            ],
        },
        {
            "kind": "instructionNode",
            "name": "openPage",
            "docs": ["Tag 1: Permissionlessly seal Lane 0's current EpochPage (when <=4 slots remain) and self-fund the next page."],
            "discriminators": [tag_disc(tags["TAG_OPEN_PAGE"])],
            "accounts": [
                ix_acc("payer", True, True, ["Permissionless cranker / fallback rent payer."]),
                ix_acc("pool", True, False, ["PoolState PDA."], pda_name="pool"),
                ix_acc("currentPage", True, False, ["Current Lane 0 EpochPage PDA (permanently sealed)."]),
                ix_acc("nextPage", True, False, ["Next Lane 0 EpochPage PDA (currentPageId + 1)."]),
                ix_acc("pageRentVault", True, False, ["Lane 0 PageRentVault PDA."], pda_name="pageRentVault"),
                ix_acc("systemProgram", False, False, ["Solana System Program."]),
            ],
            "arguments": [ix_disc_arg(tags["TAG_OPEN_PAGE"])],
        },
        {
            "kind": "instructionNode",
            "name": "deposit",
            "docs": [
                "Tag 2: Shield Native SOL (6 accounts) or Classic SPL / Token-2022 tokens (9+ accounts) into a stealth note.",
                "For Native SOL: [depositor, pool, outPage, solVault, rentVault, systemProgram].",
                "For SPL / Token-2022: [depositor, pool, outPage, mint, depositorAta, vaultAta, tokenProgram, rentVault, systemProgram, ...optionalTransferHookAccounts].",
                "On parallel Lanes 1..15, `pool` is read-only.",
            ],
            "discriminators": [tag_disc(tags["TAG_DEPOSIT"])],
            "accounts": [
                ix_acc("depositor", True, True, ["Source funds authority and rent-fee payer."]),
                ix_acc("pool", True, False, ["PoolState PDA (writable on Lane 0, read-only on Lanes 1..15)."], pda_name="pool"),
                ix_acc("outPage", True, False, ["Active target EpochPage PDA."], pda_name="epochPage"),
                ix_acc("solVaultOrMint", True, False, ["Native SOL: solVault (wr); SPL/Token-2022: mint (ro)."]),
                ix_acc("rentVaultOrDepositorAta", True, False, ["Native SOL: rentVault (wr); SPL/Token-2022: depositorAta (wr)."]),
                ix_acc("systemProgramOrVaultAta", True, False, ["Native SOL: systemProgram (ro); SPL/Token-2022: vaultAta (wr)."]),
                ix_acc("tokenProgram", False, False, ["SPL/Token-2022 only: Classic SPL Token or Token-2022 program."], is_optional=True),
                ix_acc("splRentVault", True, False, ["SPL/Token-2022 only: PageRentVault or LaneRentVault PDA."], is_optional=True),
                ix_acc("splSystemProgram", False, False, ["SPL/Token-2022 only: Solana System Program."], is_optional=True),
            ],
            "arguments": [
                ix_disc_arg(tags["TAG_DEPOSIT"]),
                ix_arg("isNativeSol", bool_t()),
                ix_arg("amount", num_t("u64")),
                ix_arg("output", {"kind": "definedTypeLinkNode", "name": "dynamicOutputWire"}),
            ],
        },
        {
            "kind": "instructionNode",
            "name": "transfer",
            "docs": [
                "Tag 3: Full-private 1-in -> 2-out multi-asset transfer hiding sender, recipient, token mint, and amount.",
                "Trailing accounts `[7..7+pages]` are 1 (m=5), 2 (m=6), or 4 (m=7) read-only input EpochPages in ascending pageId order.",
                "On parallel Lanes 1..15, `pool` is read-only.",
            ],
            "discriminators": [tag_disc(tags["TAG_TRANSFER"])],
            "accounts": [
                ix_acc("payer", True, True, ["Relayer or user fee payer."]),
                ix_acc("pool", True, False, ["PoolState PDA (writable on Lane 0, read-only on Lanes 1..15)."], pda_name="pool"),
                ix_acc("outPage", True, False, ["Active output EpochPage PDA."], pda_name="epochPage"),
                ix_acc("nullifier", True, False, ["Uninitialized NullifierPDA ['audren_null', poolId, J]."], pda_name="nullifier"),
                ix_acc("rentVault", True, False, ["PageRentVault (Lane 0) or LaneRentVault (Lanes 1..15)."]),
                ix_acc("zkProgram", False, False, ["Agave native ZK ElGamal Proof program."]),
                ix_acc("systemProgram", False, False, ["Solana System Program."]),
                ix_acc("inputPage0", False, False, ["First input EpochPage (followed by 0, 1, or 3 more input pages for m=5/6/7)."]),
            ],
            "arguments": [
                ix_disc_arg(tags["TAG_TRANSFER"]),
                ix_arg("m", num_t("u8"), ["Triptych exponent: 5 (32 notes), 6 (64 notes), or 7 (128 notes)."]),
                ix_arg("notePay", {"kind": "definedTypeLinkNode", "name": "noteWire"}),
                ix_arg("noteChg", {"kind": "definedTypeLinkNode", "name": "noteWire"}),
                ix_arg("cPay", fixed_bytes_t(32), ["Agave Pedersen value commitment for payment output."]),
                ix_arg("cChg", fixed_bytes_t(32), ["Agave Pedersen value commitment for change output."]),
                ix_arg("proofBundleAndPqEnvelope", bytes_t(), [
                    "Concatenation: triptychProof (929..1732 B) || crossBase2 (256 B) || rangeU128 (736 B) || [auditorAssetProof (192 B)] || [optional PQ ML-KEM-768 envelope]."
                ]),
            ],
        },
        {
            "kind": "instructionNode",
            "name": "merge",
            "docs": [
                "Tag 4: Full-private 2-in -> 1-out consolidation of two same-asset notes.",
                "Trailing accounts `[8..]` carry `inputPages(m1)` + `inputPages(m2)` read-only EpochPages (combined ring <= 128 slots).",
            ],
            "discriminators": [tag_disc(tags["TAG_MERGE"])],
            "accounts": [
                ix_acc("payer", True, True, ["Relayer or user fee payer."]),
                ix_acc("pool", True, False, ["PoolState PDA (writable on Lane 0, read-only on Lanes 1..15)."], pda_name="pool"),
                ix_acc("outPage", True, False, ["Active output EpochPage PDA."], pda_name="epochPage"),
                ix_acc("nullifier1", True, False, ["First NullifierPDA."]),
                ix_acc("nullifier2", True, False, ["Second NullifierPDA (must differ from nullifier1)."]),
                ix_acc("rentVault", True, False, ["PageRentVault or LaneRentVault PDA."]),
                ix_acc("zkProgram", False, False, ["Agave native ZK ElGamal Proof program."]),
                ix_acc("systemProgram", False, False, ["Solana System Program."]),
                ix_acc("inputPageLeg1_0", False, False, ["Leg 1 input EpochPage(s), followed by Leg 2 input EpochPage(s)."]),
            ],
            "arguments": [
                ix_disc_arg(tags["TAG_MERGE"]),
                ix_arg("m1", num_t("u8")),
                ix_arg("m2", num_t("u8")),
                ix_arg("noteOut", {"kind": "definedTypeLinkNode", "name": "noteWire"}),
                ix_arg("vIn1", fixed_bytes_t(32)),
                ix_arg("vIn2", fixed_bytes_t(32)),
                ix_arg("cOut", fixed_bytes_t(32)),
                ix_arg("proofBundle", bytes_t(), [
                    "Concatenation: triptych1 || triptych2 || crossBase1 (128 B) || rangeU64 (672 B) || [auditorAssetProof (192 B)]."
                ]),
            ],
        },
        {
            "kind": "instructionNode",
            "name": "swapViaRouter",
            "docs": [
                "Tag 5: Single-transaction router-agnostic private DEX swap via sharded isolated swap_escrow PDA.",
                "Trailing accounts `[15..15+pages]` are read-only input EpochPages; `[15+pages..]` are external router accounts (up to 80) with `swap_escrow`, `escrow_in`, `escrow_out` at arbitrary indices `(escrowIdx, escrowInIdx, escrowOutIdx)`.",
            ],
            "discriminators": [tag_disc(tags["TAG_SWAP_VIA_ROUTER"])],
            "accounts": [
                ix_acc("payer", True, True, ["Relayer or user fee payer."]),
                ix_acc("pool", True, False, ["PoolState PDA (writable on Lane 0, read-only on Lanes 1..15)."], pda_name="pool"),
                ix_acc("outPage", True, False, ["Active output EpochPage PDA."], pda_name="epochPage"),
                ix_acc("nullifier", True, False, ["Uninitialized NullifierPDA."], pda_name="nullifier"),
                ix_acc("rentVault", True, False, ["PageRentVault or LaneRentVault PDA."]),
                ix_acc("zkProgram", False, False, ["Agave native ZK ElGamal Proof program."]),
                ix_acc("systemProgram", False, False, ["Solana System Program."]),
                ix_acc("vaultAuth", False, False, ["Pool vault authority PDA ['audren_vault', poolId]."], pda_name="vaultAuth"),
                ix_acc("mintIn", False, False, ["Input SPL / Token-2022 mint."]),
                ix_acc("vaultIn", True, False, ["Pool vault ATA for mintIn."]),
                ix_acc("tokenProgramIn", False, False, ["Token program for mintIn."]),
                ix_acc("mintOut", False, False, ["Output SPL / Token-2022 mint (must differ from mintIn)."]),
                ix_acc("vaultOut", True, False, ["Pool vault ATA for mintOut."]),
                ix_acc("tokenProgramOut", False, False, ["Token program for mintOut."]),
                ix_acc("routerProgram", False, False, ["Executable external DEX / aggregator program."]),
            ],
            "arguments": [
                ix_disc_arg(tags["TAG_SWAP_VIA_ROUTER"]),
                ix_arg("m", num_t("u8")),
                ix_arg("shardId", num_t("u8"), ["Swap escrow shard index 0..16."]),
                ix_arg("flags", num_t("u8"), ["bit0 = hasChange, bit1 = allowPartialRefund."]),
                ix_arg("amountIn", num_t("u64")),
                ix_arg("minAmountOut", num_t("u64")),
                ix_arg("escrowIdx", num_t("u8"), ["Index of swap_escrow PDA inside routerAccounts."]),
                ix_arg("escrowInIdx", num_t("u8"), ["Index of escrow_in ATA inside routerAccounts."]),
                ix_arg("escrowOutIdx", num_t("u8"), ["Index of escrow_out ATA inside routerAccounts."]),
                ix_arg("routerDataLen", num_t("u16")),
                ix_arg("swapOutDesc", {"kind": "definedTypeLinkNode", "name": "dynamicOutputWire"}),
                ix_arg("variableTail", bytes_t(), [
                    "Concatenation: [changeNote(193) + cChg(32) + crossBase1(128) + rangeU64(672) if bit0] || [refundDesc(129) if bit1] || triptychProof || routerInstructionData(routerDataLen)."
                ]),
            ],
        },
        {
            "kind": "instructionNode",
            "name": "withdraw",
            "docs": [
                "Tag 6: Full-private spend to a public SOL or SPL/Token-2022 recipient with optional hidden change note.",
                "Full withdrawals (hasChange=false) always succeed even when pool.paused=true (non-custodial escape hatch).",
                "Native SOL accounts `[7..9]`: [solVault (wr), recipient (wr)], followed by input EpochPages.",
                "SPL/Token-2022 accounts `[7..12]`: [vaultAuth (ro), mint (ro), vaultAta (wr), recipientAta (wr), tokenProgram (ro)], followed by input EpochPages and optional TransferHook accounts.",
            ],
            "discriminators": [tag_disc(tags["TAG_WITHDRAW"])],
            "accounts": [
                ix_acc("payer", True, True, ["Relayer or user fee payer."]),
                ix_acc("pool", True, False, ["PoolState PDA (writable on Lane 0 with change; read-only on Lanes 1..15 or full withdraw)."], pda_name="pool"),
                ix_acc("outPage", True, False, ["Output EpochPage PDA (writable only when hasChange=true)."], pda_name="epochPage"),
                ix_acc("nullifier", True, False, ["Uninitialized NullifierPDA."], pda_name="nullifier"),
                ix_acc("rentVault", True, False, ["PageRentVault or LaneRentVault PDA."]),
                ix_acc("zkProgram", False, False, ["Agave native ZK ElGamal Proof program."]),
                ix_acc("systemProgram", False, False, ["Solana System Program."]),
                ix_acc("solVaultOrVaultAuth", True, False, ["Native SOL: solVault (wr); SPL/Token-2022: vaultAuth (ro)."]),
                ix_acc("recipientOrMint", True, False, ["Native SOL: recipient (wr); SPL/Token-2022: mint (ro)."]),
                ix_acc("inputPage0OrVaultAta", True, False, ["Native SOL: inputPage0 (ro); SPL/Token-2022: vaultAta (wr)."]),
                ix_acc("recipientAta", True, False, ["SPL/Token-2022 only: recipient token account (wr)."], is_optional=True),
                ix_acc("tokenProgram", False, False, ["SPL/Token-2022 only: Classic SPL Token or Token-2022 program."], is_optional=True),
            ],
            "arguments": [
                ix_disc_arg(tags["TAG_WITHDRAW"]),
                ix_arg("m", num_t("u8")),
                ix_arg("isNativeSol", bool_t()),
                ix_arg("hasChange", bool_t()),
                ix_arg("amountOut", num_t("u64")),
                ix_arg("changeAndTriptychProof", bytes_t(), [
                    "Concatenation: [changeNote(193) + cChg(32) + crossBase1(128) + rangeU64(672) if hasChange] || triptychProof."
                ]),
            ],
        },
        {
            "kind": "instructionNode",
            "name": "setPaused",
            "docs": ["Tag 7: Governance emergency pause/unpause. Never grants custody or blocks full withdrawals."],
            "discriminators": [tag_disc(tags["TAG_SET_PAUSED"])],
            "accounts": [
                ix_acc("authority", False, True, ["PoolState::authority signer."]),
                ix_acc("pool", True, False, ["PoolState PDA."], pda_name="pool"),
            ],
            "arguments": [
                ix_disc_arg(tags["TAG_SET_PAUSED"]),
                ix_arg("paused", bool_t()),
            ],
        },
        {
            "kind": "instructionNode",
            "name": "writeProofBuffer",
            "docs": ["Tag 8: Upload one <=768 B chunk (in any order) into an ephemeral ProofBuffer PDA (max 9,984 B payload)."],
            "discriminators": [tag_disc(tags["TAG_WRITE_PROOF_BUFFER"])],
            "accounts": [
                ix_acc("payer", True, True, ["Buffer authority and rent payer."]),
                ix_acc("proofBuffer", True, False, ["ProofBuffer PDA ['audren_buf', payer, nonce]."], pda_name="proofBuffer"),
                ix_acc("systemProgram", False, False, ["Solana System Program."]),
            ],
            "arguments": [
                ix_disc_arg(tags["TAG_WRITE_PROOF_BUFFER"]),
                ix_arg("nonce", num_t("u64")),
                ix_arg("totalLen", num_t("u32")),
                ix_arg("chunkIndex", num_t("u8")),
                ix_arg("chunk", bytes_t(), ["1..=768 payload bytes for this chunk."]),
            ],
        },
        {
            "kind": "instructionNode",
            "name": "execBuffered",
            "docs": [
                "Tag 9: Execute Transfer (3), Merge (4), SwapViaRouter (5), or Withdraw (6) directly from a completed ProofBuffer PDA, atomically closing the buffer and refunding 100% of rent to payer.",
                "Accounts: [0] proofBuffer (wr), [1..] exact account list of the inner instruction (where [1] = payer/authority).",
            ],
            "discriminators": [tag_disc(tags["TAG_EXEC_BUFFERED"])],
            "accounts": [
                ix_acc("proofBuffer", True, False, ["Completed ProofBuffer PDA (closed atomically after execution)."], pda_name="proofBuffer"),
                ix_acc("payer", True, True, ["Buffer authority & inner instruction payer (followed by remaining inner instruction accounts)."]),
            ],
            "arguments": [
                ix_disc_arg(tags["TAG_EXEC_BUFFERED"]),
                ix_arg("innerTag", num_t("u8"), ["One of: 3 (Transfer), 4 (Merge), 5 (SwapViaRouter), 6 (Withdraw)."]),
            ],
        },
        {
            "kind": "instructionNode",
            "name": "closeProofBuffer",
            "docs": ["Tag 10: Close an abandoned/unexecuted ProofBuffer PDA and reclaim 100% of its rent to authority."],
            "discriminators": [tag_disc(tags["TAG_CLOSE_PROOF_BUFFER"])],
            "accounts": [
                ix_acc("payer", True, True, ["Buffer authority and rent refund recipient."]),
                ix_acc("proofBuffer", True, False, ["ProofBuffer PDA to close."], pda_name="proofBuffer"),
            ],
            "arguments": [ix_disc_arg(tags["TAG_CLOSE_PROOF_BUFFER"])],
        },
        {
            "kind": "instructionNode",
            "name": "initLane",
            "docs": ["Tag 11: Sequentially activate parallel append lane 1..15 inside an existing pool for lock-free concurrent writes."],
            "discriminators": [tag_disc(tags["TAG_INIT_LANE"])],
            "accounts": [
                ix_acc("authority", True, True, ["PoolState::authority and rent payer."]),
                ix_acc("pool", True, False, ["PoolState PDA."], pda_name="pool"),
                ix_acc("laneState", True, False, ["AppendLaneState PDA ['audren_lane', poolId, laneId]."], pda_name="appendLane"),
                ix_acc("lanePage0", True, False, ["Initial EpochPage PDA for this lane (pageId = (laneId << 56) | 0)."]),
                ix_acc("laneRentVault", True, False, ["LaneRentVault sentinel PDA ['audren_lrent', poolId, laneId]."], pda_name="laneRentVault"),
                ix_acc("systemProgram", False, False, ["Solana System Program."]),
            ],
            "arguments": [
                ix_disc_arg(tags["TAG_INIT_LANE"]),
                ix_arg("laneId", num_t("u8"), ["Next sequential lane index (1..16)."]),
            ],
        },
        {
            "kind": "instructionNode",
            "name": "openLanePage",
            "docs": ["Tag 12: Permissionlessly seal a parallel lane's current EpochPage (when <=4 slots remain) and self-fund the next page with read-only PoolState."],
            "discriminators": [tag_disc(tags["TAG_OPEN_LANE_PAGE"])],
            "accounts": [
                ix_acc("payer", True, True, ["Permissionless cranker / fallback rent payer."]),
                ix_acc("pool", False, False, ["PoolState PDA (read-only!)."], pda_name="pool"),
                ix_acc("laneState", True, False, ["AppendLaneState PDA."], pda_name="appendLane"),
                ix_acc("currentPage", True, False, ["Current lane EpochPage PDA (permanently sealed)."]),
                ix_acc("nextPage", True, False, ["Next lane EpochPage PDA ((laneId << 56) | (seq + 1))."]),
                ix_acc("laneRentVault", True, False, ["LaneRentVault PDA."], pda_name="laneRentVault"),
                ix_acc("systemProgram", False, False, ["Solana System Program."]),
            ],
            "arguments": [
                ix_disc_arg(tags["TAG_OPEN_LANE_PAGE"]),
                ix_arg("laneId", num_t("u8"), ["Parallel lane index 1..16."]),
            ],
        },
    ]

    error_nodes = [
        {
            "kind": "errorNode",
            "name": name[0].lower() + name[1:],
            "code": code,
            "message": ERROR_DOCS.get(name, name),
            "docs": [f"AudrenError::{name} (Custom error {code})."],
        }
        for name, code in core["errors"]
    ]

    return {
        "kind": "rootNode",
        "standard": "codama",
        "version": CODAMA_VERSION,
        "program": {
            "kind": "programNode",
            "name": "audren",
            "publicKey": core["program_id"],
            "version": PROGRAM_VERSION,
            "origin": "shank",
            "docs": [
                "Audren — Multi-Asset Confidential & Full-Private Settlement & Swap Protocol on Solana (Pinocchio + sBPFv3).",
                "Zero trusted setup: pure Ristretto255 Multi-Base Binary Triptych (32/64/128-note rings) + Agave native Bulletproofs.",
            ],
            "accounts": accounts,
            "instructions": instructions,
            "definedTypes": defined_types,
            "pdas": pdas,
            "errors": error_nodes,
        },
        "additionalPrograms": [],
    }


def build_audren_anchor(core: dict, codama: dict) -> dict:
    """Build an Anchor v0.30+ compatible IDL JSON mirroring the Codama IDL for explorers and Anchor tooling."""
    prog = codama["program"]

    def map_type(t: dict):
        k = t["kind"]
        if k == "numberTypeNode":
            return t["format"]
        if k == "booleanTypeNode":
            return "bool"
        if k == "publicKeyTypeNode":
            return "pubkey"
        if k == "bytesTypeNode":
            return "bytes"
        if k == "fixedSizeTypeNode":
            return {"array": ["u8", t["size"]]}
        if k == "arrayTypeNode":
            return {"array": [map_type(t["item"]), t["count"]["value"]]}
        if k == "definedTypeLinkNode":
            n = t["name"]
            return {"defined": {"name": n[0].upper() + n[1:]}}
        raise ValueError(f"Unsupported Codama type: {t}")

    def pascal(s: str) -> str:
        return s[0].upper() + s[1:]

    def snake(s: str) -> str:
        return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s).lower()

    anchor_instructions = []
    for ix in prog["instructions"]:
        tag = ix["discriminators"][0]["constant"]["value"]["number"]
        args = []
        for a in ix["arguments"]:
            if a.get("defaultValueStrategy") == "omitted":
                continue
            args.append({"name": snake(a["name"]), "type": map_type(a["type"])})
        accs = []
        for acc in ix["accounts"]:
            entry = {
                "name": snake(acc["name"]),
                "writable": acc["isWritable"],
                "signer": acc["isSigner"],
            }
            if acc.get("isOptional"):
                entry["optional"] = True
            if acc.get("docs"):
                entry["docs"] = acc["docs"]
            accs.append(entry)
        anchor_instructions.append({
            "name": snake(ix["name"]),
            "docs": ix.get("docs", []),
            "discriminator": [tag],
            "accounts": accs,
            "args": args,
        })

    anchor_accounts = []
    anchor_types = []

    for dt in prog["definedTypes"]:
        t = dt["type"]
        if t["kind"] == "enumTypeNode":
            anchor_types.append({
                "name": pascal(dt["name"]),
                "docs": dt.get("docs", []),
                "type": {
                    "kind": "enum",
                    "variants": [{"name": pascal(v["name"])} for v in t["variants"]],
                },
            })
        elif t["kind"] == "structTypeNode":
            anchor_types.append({
                "name": pascal(dt["name"]),
                "docs": dt.get("docs", []),
                "type": {
                    "kind": "struct",
                    "fields": [{"name": snake(f["name"]), "type": map_type(f["type"])} for f in t["fields"]],
                },
            })

    for acc in prog["accounts"]:
        acc_name = pascal(acc["name"])
        disc_bytes: list[int] = []
        if acc.get("discriminators"):
            magic_str = acc["discriminators"][0]["constant"]["value"]["data"]
            disc_bytes = list(magic_str.encode("ascii"))
        anchor_accounts.append({
            "name": acc_name,
            "discriminator": disc_bytes,
        })
        anchor_types.append({
            "name": acc_name,
            "docs": acc.get("docs", []),
            "type": {
                "kind": "struct",
                "fields": [{"name": snake(f["name"]), "type": map_type(f["type"])} for f in acc["data"]["fields"]],
            },
        })

    anchor_errors = [
        {"code": code, "name": name, "msg": ERROR_DOCS.get(name, name)}
        for name, code in core["errors"]
    ]

    return {
        "address": core["program_id"],
        "metadata": {
            "name": "audren",
            "version": PROGRAM_VERSION,
            "spec": "0.1.0",
            "description": "Audren — Institutional Confidential & Full-Private Settlement & Swap Program on Solana (Pinocchio + sBPFv3).",
            "repository": "https://github.com/audren-xyz/audren",
        },
        "instructions": anchor_instructions,
        "accounts": anchor_accounts,
        "types": anchor_types,
        "errors": anchor_errors,
    }


def build_mock_router_codama() -> dict:
    """Build Codama v1.8.0 IDL for the Pinocchio sBPFv3 mock DEX router test program."""
    return {
        "kind": "rootNode",
        "standard": "codama",
        "version": CODAMA_VERSION,
        "program": {
            "kind": "programNode",
            "name": "audrenMockRouter",
            "publicKey": "11111111111111111111111111111111",
            "version": MOCK_ROUTER_VERSION,
            "origin": "shank",
            "docs": [
                "Minimal zero-alloc Pinocchio sBPFv3 mock DEX router used by Audren SwapViaRouter integration tests.",
                "Not deployed to Mainnet; tests assign an ephemeral LiteSVM program ID.",
            ],
            "accounts": [],
            "definedTypes": [],
            "pdas": [
                pda_node("mockPoolAuthority", [const_seed("mock_pool")], ["PDA signing pool_out -> escrow_out token transfers."]),
            ],
            "errors": [],
            "instructions": [
                {
                    "kind": "instructionNode",
                    "name": "executeMockSwap",
                    "docs": [
                        "Execute honest swap (mode=0) or adversarial custody attack simulation (mode=1 delegate, mode=2 set_authority, mode=3 lamport drain).",
                    ],
                    "accounts": [
                        ix_acc("poolAuthority", False, False, ["PDA ['mock_pool']."], pda_name="mockPoolAuthority"),
                        ix_acc("escrowIn", True, False, ["Audren swap_escrow input ATA."]),
                        ix_acc("poolIn", True, False, ["Mock pool input liquidity ATA."]),
                        ix_acc("swapEscrow", True, True, ["Audren swap_escrow PDA signer."]),
                        ix_acc("escrowOut", True, False, ["Audren swap_escrow output ATA."]),
                        ix_acc("poolOut", True, False, ["Mock pool output liquidity ATA."]),
                        ix_acc("tokenProgramIn", False, False, ["SPL / Token-2022 program for input mint."]),
                        ix_acc("tokenProgramOut", False, False, ["SPL / Token-2022 program for output mint."]),
                        ix_acc("mintIn", False, False, ["Input mint."]),
                        ix_acc("mintOut", False, False, ["Output mint."]),
                        ix_acc("attacker", True, False, ["Adversarial target account (modes 1, 2, 3 only)."], is_optional=True),
                        ix_acc("systemProgram", False, False, ["System Program (mode 3 only)."], is_optional=True),
                    ],
                    "arguments": [
                        ix_arg("mode", num_t("u8"), ["0=honest, 1=approve_delegate, 2=hijack_owner, 3=drain_lamports."]),
                        ix_arg("spendIn", num_t("u64")),
                        ix_arg("payOut", num_t("u64")),
                        ix_arg("decIn", num_t("u8")),
                        ix_arg("decOut", num_t("u8")),
                    ],
                }
            ],
        },
        "additionalPrograms": [],
    }


def main() -> None:
    core = parse_core_constants()
    codama = build_audren_codama(core)
    anchor = build_audren_anchor(core, codama)
    mock_router = build_mock_router_codama()

    IDL_DIR.mkdir(parents=True, exist_ok=True)
    SDK_IDL_DIR.mkdir(parents=True, exist_ok=True)

    codama_json = json.dumps(codama, indent=2) + "\n"
    anchor_json = json.dumps(anchor, indent=2) + "\n"
    mock_json = json.dumps(mock_router, indent=2) + "\n"

    (IDL_DIR / "audren.codama.json").write_text(codama_json)
    (IDL_DIR / "audren.anchor.json").write_text(anchor_json)
    (IDL_DIR / "audren-mock-router.codama.json").write_text(mock_json)

    # Mirror canonical IDLs into @audren/sdk (both raw JSON exports and zero-import-attribute TS module)
    (SDK_IDL_DIR / "audren.codama.json").write_text(codama_json)
    (SDK_IDL_DIR / "audren.anchor.json").write_text(anchor_json)

    sdk_ts = (
        "// AUTO-GENERATED by idl/generate-idl.py from crates/audren-core — DO NOT EDIT BY HAND.\n"
        "// Re-run `python3 idl/generate-idl.py && python3 idl/verify-idl.py` after any protocol change.\n\n"
        f"export const AUDREN_CODAMA_IDL = {codama_json.rstrip()} as const;\n\n"
        f"export const AUDREN_ANCHOR_IDL = {anchor_json.rstrip()} as const;\n"
    )
    (ROOT / "packages" / "sdk" / "src" / "idl.ts").write_text(sdk_ts)

    # Keep canonical security.json release version synchronized with program/Cargo.toml
    sec_path = IDL_DIR / "security.json"
    if sec_path.exists():
        sec = json.loads(sec_path.read_text())
        if sec.get("version") != PROGRAM_VERSION or sec.get("source_release") != f"v{PROGRAM_VERSION}":
            sec["version"] = PROGRAM_VERSION
            sec["source_release"] = f"v{PROGRAM_VERSION}"
            sec_path.write_text(json.dumps(sec, indent=2) + "\n")

    print(
        f"Generated IDLs for {core['program_id']}: "
        f"{len(codama['program']['instructions'])} instructions, "
        f"{len(codama['program']['accounts'])} accounts, "
        f"{len(codama['program']['pdas'])} PDAs, "
        f"{len(codama['program']['errors'])} errors (+ mock-router IDL)."
    )


if __name__ == "__main__":
    main()
