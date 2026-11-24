#!/usr/bin/env python3
"""Generate deterministic Codama (v1.8.0) and Anchor-compatible (v0.30+) IDLs for Audren.

Reads authoritative constants (program ID, error codes 6000..=6032, instruction tags 0..=8,
PDA seeds, account magics, and fixed byte lengths) directly from `crates/audren-core/src/`
so published IDLs can never drift from the on-chain sBPFv3 Pinocchio program.
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

    err_block_m = re.search(r"pub enum AudrenError \{([^}]+)\}", lib_rs, re.S)
    if not err_block_m:
        raise RuntimeError("Could not parse AudrenError enum")
    errors: list[tuple[str, int]] = []
    for name, code_s in re.findall(r"([A-Za-z0-9_]+)\s*=\s*(\d+),", err_block_m.group(1)):
        errors.append((name, int(code_s)))

    tags: dict[str, int] = {}
    for name, val_s in re.findall(r"pub const (TAG_[A-Z0-9_]+):\s*u8\s*=\s*(0x[0-9a-fA-F]+|\d+);", ix_rs):
        tags[name] = int(val_s, 0)

    seeds: dict[str, str] = {}
    for name, val in re.findall(r'pub const ([A-Z0-9_]+_SEED):\s*&\[u8\]\s*=\s*b"([^"]+)";', lib_rs):
        seeds[name] = val

    magics: dict[str, str] = {}
    for name, val in re.findall(r'pub const ([A-Z0-9_]+_MAGIC):\s*\[u8;\s*8\]\s*=\s*\*b"([^"]+)";', layout_rs):
        magics[name] = val

    lengths: dict[str, int] = {}
    for name, val_s in re.findall(r"pub const ([A-Z0-9_]+_LEN):\s*usize\s*=\s*([0-9_]+);", layout_rs):
        lengths[name] = int(val_s.replace("_", ""))
    for name, val_s in re.findall(r"assert!\(([A-Z0-9_]+_LEN)\s*==\s*([0-9_]+)", layout_rs):
        lengths[name] = int(val_s.replace("_", ""))
    required_lengths = (
        "POOL_STATE_LEN",
        "SENTINEL_LEN",
        "LANE_STATE_LEN",
        "SUBTREE_PAGE_LEN",
        "SUBROOT_PAGE_LEN",
        "MEMO_PAGE_LEN",
        "NF_PAGE_LEN",
        "ROOT_HISTORY_LEN",
    )
    missing_lengths = [k for k in required_lengths if k not in lengths]
    if missing_lengths:
        raise RuntimeError(f"Could not parse account lengths from layout.rs: {missing_lengths}")

    return {
        "program_id": program_id,
        "errors": errors,
        "tags": tags,
        "seeds": seeds,
        "magics": magics,
        "lengths": lengths,
    }


ERROR_DOCS: dict[str, str] = {
    "InvalidInstruction": "Malformed instruction tag, length, flags, or argument encoding.",
    "InvalidPda": "Account address does not match expected PDA derivation.",
    "InvalidAccount": "Missing, unwritable, wrong-owner, or aliased account.",
    "InvalidLane": "Invalid or inactive append lane_id (must be sequentially initialized in 0..16).",
    "SubtreePageFull": "Active SubtreePage has reached 256 note commitments.",
    "SubtreePageMismatch": "Provided SubtreePage sequence does not match active lane leaf index.",
    "SubrootPageMismatch": "Provided SubtreeRootPage sequence does not match finalized subtree index.",
    "InvalidRootRing": "Root ring selector must be 0 (slot ring) or 1 (epoch ring).",
    "RootIndexOutOfBounds": "Referenced GlobalRootHistory ring index is out of bounds or unpopulated.",
    "RootHistoryMismatch": "Referenced GlobalRootHistory account is uninitialized, corrupted, or belongs to another pool.",
    "ProofVerificationFailed": "BN254 Groth16 proof verification or ctx_hash binding failed.",
    "InvalidVkId": "Verifying key identifier is unsupported.",
    "NullifierAlreadyUsed": "NullifierPDA already exists (note already spent).",
    "PoseidonFailed": "Solana sol_poseidon BN254 syscall returned an error.",
    "SlippageExceeded": "Measured net vault output is zero or below min_amount_out after fees.",
    "CustodyInvariantViolated": "Pool custody accounting invariant failed.",
    "Overflow": "Checked integer arithmetic overflow or tree capacity exceeded.",
    "InsufficientVaultBalance": "Custody vault or LaneRentVault holds insufficient balance (or OpenPage payer_deficit exceeds max_payer_deficit).",
    "MemoPageFull": "Active MemoPage has reached 96 note entries.",
    "MemoPageMismatch": "Provided MemoPage sequence does not match active lane leaf index.",
    "InvalidTokenAccount": "Invalid SPL / Token-2022 mint, canonical custody/escrow ATA, delegate, close_authority, or TLV extension.",
    "ForbiddenRouterAccount": "Forbidden Audren custody, program, or relayer fee account smuggled into router_accounts.",
    "EscrowNotDrained": "External DeFi CPI left unspent input tokens in escrow.",
    "NullifierPageFull": "Active NullifierPage has reached 600 nullifier prefixes.",
    "NullifierPageMismatch": "Provided NullifierPage sequence does not match active lane nf_count.",
    "InvalidEscrowShard": "Escrow shard index must be in 0..16.",
    "InvalidFieldElement": "32-byte input is not a canonical BN254 scalar (< Fr modulus).",
    "PoolPaused": "Pool is paused by authority (full exits and OpenPage remain open).",
    "Unauthorized": "Required authority signer is missing, renounced, or mismatched.",
    "PageSeqOutOfRange": "OpenPage sequence exceeds allowed lookahead bound (cur_seq, or cur_seq + 1 only at >= 90% occupancy: Subtree >= 230/256, Subroot >= 280/300, Memo >= 86/96, Nullifier >= 540/600; cur_seq + 2 rejected).",
    "InvalidTargetProgram": "Target program must be executable and cannot be Audren, System, Token, Token-2022, ATA, or ElGamal Registry.",
    "EscrowAuthorityAltered": "Target CPI altered swap_escrow owner, data length, or drained lamports.",
    "EscrowAccountAltered": "Target CPI altered an escrow token account owner, delegate, close_authority, TLV, or size.",
}


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


def field(name: str, typ: dict, docs: list[str] | None = None) -> dict:
    node = {"kind": "structFieldTypeNode", "name": name, "type": typ}
    if docs:
        node["docs"] = docs
    return node


def const_seed(ascii_str: str) -> dict:
    return {
        "kind": "constantPdaSeedNode",
        "type": fixed_bytes_t(len(ascii_str)),
        "value": {"kind": "bytesValueNode", "encoding": "utf8", "data": ascii_str},
    }


def var_seed(name: str, typ: dict) -> dict:
    return {"kind": "variablePdaSeedNode", "name": name, "type": typ}


def pda_node(name: str, seeds: list[dict], docs: list[str]) -> dict:
    return {"kind": "pdaNode", "name": name, "docs": docs, "seeds": seeds}


def account_node(name: str, magic: str, size: int, fields: list[dict], docs: list[str]) -> dict:
    return {
        "kind": "accountNode",
        "name": name,
        "docs": docs,
        "size": size,
        "discriminators": [
            {
                "kind": "constantDiscriminatorNode",
                "offset": 0,
                "constant": {
                    "kind": "constantValueNode",
                    "type": fixed_bytes_t(len(magic)),
                    "value": {"kind": "bytesValueNode", "encoding": "utf8", "data": magic},
                },
            }
        ],
        "data": {"kind": "structTypeNode", "fields": fields},
    }


def ix_acc(
    name: str,
    is_writable: bool,
    is_signer: bool,
    docs: list[str],
    is_optional: bool = False,
) -> dict:
    return {
        "kind": "instructionAccountNode",
        "name": name,
        "isWritable": is_writable,
        "isSigner": is_signer,
        "isOptional": is_optional,
        "docs": docs,
    }


def ix_arg(name: str, typ: dict, docs: list[str] | None = None) -> dict:
    node = {"kind": "instructionArgumentNode", "name": name, "type": typ}
    if docs:
        node["docs"] = docs
    return node


def ix_node(name: str, tag: int, docs: list[str], accounts: list[dict], arguments: list[dict]) -> dict:
    tag_arg = {
        "kind": "instructionArgumentNode",
        "name": "tag",
        "type": num_t("u8"),
        "defaultValue": {"kind": "numberValueNode", "number": tag},
        "defaultValueStrategy": "omitted",
    }
    return {
        "kind": "instructionNode",
        "name": name,
        "docs": docs,
        "discriminators": [
            {
                "kind": "constantDiscriminatorNode",
                "offset": 0,
                "constant": {
                    "kind": "constantValueNode",
                    "type": num_t("u8"),
                    "value": {"kind": "numberValueNode", "number": tag},
                },
            }
        ],
        "accounts": accounts,
        "arguments": [tag_arg, *arguments],
    }


def camel(name: str) -> str:
    return name[0].lower() + name[1:]


def pascal(name: str) -> str:
    return name[0].upper() + name[1:]


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def build_audren_codama(core: dict) -> dict:
    seeds = core["seeds"]
    magics = core["magics"]
    tags = core["tags"]

    pdas = [
        pda_node("poolState", [const_seed(seeds["POOL_SEED"]), var_seed("poolId", num_t("u32"))], ["Global pool configuration PDA (128 B)."]),
        pda_node("vaultAuthority", [const_seed(seeds["VAULT_AUTH_SEED"]), var_seed("poolId", num_t("u32"))], ["Unified WSOL / Classic SPL / Token-2022 custody vault ATA owner PDA."]),
        pda_node("laneTreeState", [const_seed(seeds["LANE_SEED"]), var_seed("poolId", num_t("u32")), var_seed("laneId", num_t("u8"))], ["Per-lane 4-ary Depth-18 incremental frontier PDA (1,824 B)."]),
        pda_node("laneRentVault", [const_seed(seeds["LANE_RENT_SEED"]), var_seed("poolId", num_t("u32")), var_seed("laneId", num_t("u8"))], ["Per-lane self-funding rent sentinel PDA (16 B)."]),
        pda_node("subtreePage", [const_seed(seeds["SUBTREE_SEED"]), var_seed("poolId", num_t("u32")), var_seed("laneId", num_t("u8")), var_seed("pageSeq", num_t("u64"))], ["256-leaf note commitment page PDA (8,256 B)."]),
        pda_node("subtreeRootPage", [const_seed(seeds["SUBROOT_SEED"]), var_seed("poolId", num_t("u32")), var_seed("laneId", num_t("u8")), var_seed("rootPageSeq", num_t("u64"))], ["300 finalized 256-leaf subtree roots PDA (9,664 B)."]),
        pda_node("memoPage", [const_seed(seeds["MEMO_SEED"]), var_seed("poolId", num_t("u32")), var_seed("laneId", num_t("u8")), var_seed("pageSeq", num_t("u64"))], ["96 x 106 B versioned SoA encrypted note memos PDA (10,240 B)."]),
        pda_node("nullifierPage", [const_seed(seeds["NF_PAGE_SEED"]), var_seed("poolId", num_t("u32")), var_seed("laneId", num_t("u8")), var_seed("pageSeq", num_t("u64"))], ["600 x 16 B nullifier prefixes PDA for ordinary-RPC spent sync (9,664 B)."]),
        pda_node("globalRootHistory", [const_seed(seeds["ROOTS_SEED"]), var_seed("poolId", num_t("u32"))], ["Protocol-automated dual-ring global super_root history PDA (10,216 B)."]),
        pda_node("nullifier", [const_seed(seeds["NULLIFIER_SEED"]), var_seed("poolId", num_t("u32")), var_seed("nullifier", fixed_bytes_t(32))], ["Canonical 0-byte global spent-nullifier replay guard PDA."]),
        pda_node("swapEscrow", [const_seed(seeds["ESCROW_SEED"]), var_seed("poolId", num_t("u32")), var_seed("shardId", num_t("u8"))], ["Isolated DeFi CPI signer shard PDA (0..16)."]),
        pda_node("unwrapAccount", [const_seed(seeds["UNWRAP_SEED"]), var_seed("poolId", num_t("u32")), var_seed("nf0", fixed_bytes_t(32))], ["Ephemeral 1-shot WSOL unwrap token account PDA."]),
    ]

    accounts = [
        account_node(
            "poolState",
            magics["POOL_MAGIC"],
            128,
            [
                field("magic", fixed_bytes_t(8)),
                field("version", num_t("u8")),
                field("bump", num_t("u8")),
                field("paused", num_t("u8")),
                field("activeLanes", num_t("u8")),
                field("poolId", num_t("u32")),
                field("rootEpochInterval", num_t("u64")),
                field("reserved24", fixed_bytes_t(8)),
                field("authority", pubkey_t()),
                field("vaultAuthBump", num_t("u8")),
                field("reserved1", fixed_bytes_t(7)),
                field("noteRentFee", num_t("u64")),
                field("nfRentFee", num_t("u64")),
                field("pendingAuthority", pubkey_t()),
                field("reserved2", fixed_bytes_t(8)),
            ],
            ["Global pool configuration (128 B; read-only on all deposits, spends, and DeFi swaps)."],
        ),
        account_node(
            "laneRentVault",
            magics["LANE_RENT_MAGIC"],
            16,
            [
                field("magic", fixed_bytes_t(8)),
                field("poolId", num_t("u32")),
                field("laneId", num_t("u8")),
                field("bump", num_t("u8")),
                field("reserved", fixed_bytes_t(2)),
            ],
            ["Per-lane self-funding rent sentinel (16 B)."],
        ),
        account_node(
            "laneTreeState",
            magics["LANE_MAGIC"],
            1824,
            [
                field("magic", fixed_bytes_t(8)),
                field("version", num_t("u8")),
                field("laneId", num_t("u8")),
                field("bump", num_t("u8")),
                field("rentBump", num_t("u8")),
                field("poolId", num_t("u32")),
                field("nextLeaf", num_t("u64")),
                field("nfCount", num_t("u64")),
                field("reserved", fixed_bytes_t(32)),
                field("currentRoot", fixed_bytes_t(32)),
                field("frontier", fixed_array_t(fixed_bytes_t(32), 54)),
            ],
            ["Per-lane 4-ary Depth-18 incremental Poseidon4 frontier (1,824 B)."],
        ),
        account_node(
            "subtreePage",
            magics["SUBTREE_MAGIC"],
            8256,
            [
                field("magic", fixed_bytes_t(8)),
                field("laneId", num_t("u8")),
                field("bump", num_t("u8")),
                field("count", num_t("u16")),
                field("poolId", num_t("u32")),
                field("pageSeq", num_t("u64")),
                field("reserved", fixed_bytes_t(40)),
                field("leaves", fixed_array_t(fixed_bytes_t(32), 256)),
            ],
            ["Append-only 256-leaf note commitment page (8,256 B <= 10 KiB)."],
        ),
        account_node(
            "subtreeRootPage",
            magics["SUBROOT_MAGIC"],
            9664,
            [
                field("magic", fixed_bytes_t(8)),
                field("laneId", num_t("u8")),
                field("bump", num_t("u8")),
                field("count", num_t("u16")),
                field("poolId", num_t("u32")),
                field("rootPageSeq", num_t("u64")),
                field("reserved", fixed_bytes_t(40)),
                field("roots", fixed_array_t(fixed_bytes_t(32), 300)),
            ],
            ["Append-only 300 finalized 256-leaf subtree roots page (9,664 B <= 10 KiB)."],
        ),
        account_node(
            "memoPage",
            magics["MEMO_MAGIC"],
            10240,
            [
                field("magic", fixed_bytes_t(8)),
                field("laneId", num_t("u8")),
                field("bump", num_t("u8")),
                field("count", num_t("u16")),
                field("poolId", num_t("u32")),
                field("pageSeq", num_t("u64")),
                field("createdSlot", num_t("u64")),
                field("closedSlot", num_t("u64")),
                field("reserved", fixed_bytes_t(24)),
                field("viewTags", fixed_array_t(fixed_bytes_t(2), 96)),
                field("ephemeralPks", fixed_array_t(fixed_bytes_t(32), 96)),
                field("ciphertexts", fixed_array_t(fixed_bytes_t(72), 96)),
            ],
            ["Versioned Structure-of-Arrays 96 x 106 B note memo page (10,240 B == 10 KiB CPI cap)."],
        ),
        account_node(
            "nullifierPage",
            magics["NF_PAGE_MAGIC"],
            9664,
            [
                field("magic", fixed_bytes_t(8)),
                field("laneId", num_t("u8")),
                field("bump", num_t("u8")),
                field("count", num_t("u16")),
                field("poolId", num_t("u32")),
                field("pageSeq", num_t("u64")),
                field("createdSlot", num_t("u64")),
                field("closedSlot", num_t("u64")),
                field("reserved", fixed_bytes_t(24)),
                field("prefixes", fixed_array_t(fixed_bytes_t(16), 600)),
            ],
            ["Append-only 600 x 16 B nullifier prefix page for zero-leakage wallet sync (9,664 B <= 10 KiB)."],
        ),
        account_node(
            "globalRootHistory",
            magics["ROOTS_MAGIC"],
            10216,
            [
                field("magic", fixed_bytes_t(8)),
                field("version", num_t("u8")),
                field("bump", num_t("u8")),
                field("slotCursor", num_t("u16")),
                field("poolId", num_t("u32")),
                field("epochCursor", num_t("u16")),
                field("slotCount", num_t("u16")),
                field("epochCount", num_t("u16")),
                field("sameSlotBumped", num_t("u8")),
                field("pad", num_t("u8")),
                field("latestSlot", num_t("u64")),
                field("stableEpochId", num_t("u64")),
                field("stableSlot", num_t("u64")),
                field("epochInterval", num_t("u64")),
                field("reserved", fixed_bytes_t(8)),
                field("groupRoots", fixed_array_t(fixed_bytes_t(32), 4)),
                field("latestSuperRoot", fixed_bytes_t(32)),
                field("latestLaneRoots", fixed_array_t(fixed_bytes_t(32), 16)),
                field("latestLaneCounts", fixed_array_t(num_t("u64"), 16)),
                field("stableSuperRoot", fixed_bytes_t(32)),
                field("stableLaneRoots", fixed_array_t(fixed_bytes_t(32), 16)),
                field("stableLaneCounts", fixed_array_t(num_t("u64"), 16)),
                field("slotRing", fixed_array_t({"kind": "definedTypeLinkNode", "name": "rootEntry"}, 128)),
                field("epochRing", fixed_array_t({"kind": "definedTypeLinkNode", "name": "rootEntry"}, 89)),
            ],
            ["Protocol-automated dual-ring global super_root history (10,216 B <= 10 KiB CPI cap; 128-entry slot ring + 89-entry epoch ring, updated atomically inline on every note commitment)."],
        ),
    ]

    defined_types: list[dict] = [
        {
            "kind": "definedTypeNode",
            "name": "rootEntry",
            "docs": ["Single ring entry inside GlobalRootHistory (40 B: super_root[32] || slot[8])."],
            "type": {
                "kind": "structTypeNode",
                "fields": [
                    field("superRoot", fixed_bytes_t(32)),
                    field("slot", num_t("u64")),
                ],
            },
        }
    ]

    instructions = [
        ix_node(
            "initPool",
            tags["TAG_INIT_POOL"],
            ["Initialize PoolState (128 B, PROTOCOL_VERSION = 1, active_lanes = 0) and empty GlobalRootHistory (10,216 B) atomically."],
            [
                ix_acc("payer", True, True, ["Initial pool authority and rent payer."]),
                ix_acc("poolState", True, False, ["PoolState PDA."]),
                ix_acc("roots", True, False, ["GlobalRootHistory PDA."]),
                ix_acc("systemProgram", False, False, ["System Program."]),
            ],
            [
                ix_arg("poolId", num_t("u32")),
                ix_arg("rootEpochInterval", num_t("u64")),
                ix_arg("noteRentFee", num_t("u64")),
                ix_arg("nfRentFee", num_t("u64")),
            ],
        ),
        ix_node(
            "initLane",
            tags["TAG_INIT_LANE"],
            ["Authority-gated sequential append-lane activation (0 -> 4 -> 8 -> 16) with zero circuit changes."],
            [
                ix_acc("authority", True, True, ["Pool authority and initial page-0 rent payer."]),
                ix_acc("poolState", True, False, ["PoolState PDA (increments active_lanes)."]),
                ix_acc("laneState", True, False, ["LaneTreeState PDA."]),
                ix_acc("laneRentVault", True, False, ["Per-lane LaneRentVault PDA."]),
                ix_acc("subtreePage0", True, False, ["Initial SubtreePage(seq=0) PDA."]),
                ix_acc("subrootPage0", True, False, ["Initial SubtreeRootPage(seq=0) PDA."]),
                ix_acc("memoPage0", True, False, ["Initial MemoPage(seq=0) PDA."]),
                ix_acc("nfPage0", True, False, ["Initial NullifierPage(seq=0) PDA."]),
                ix_acc("systemProgram", False, False, ["System Program."]),
            ],
            [
                ix_arg("poolId", num_t("u32")),
                ix_arg("laneId", num_t("u8")),
            ],
        ),
        ix_node(
            "openPage",
            tags["TAG_OPEN_PAGE"],
            ["Idempotent, >=90%-lookahead-gated, pause-exempt, LaneRentVault-subsidized page opener with explicit max_payer_deficit protection against TOCTOU drains."],
            [
                ix_acc("payer", True, True, ["Permissionless cranker / bounded fallback rent payer."]),
                ix_acc("poolState", False, False, ["PoolState PDA (read-only)."]),
                ix_acc("laneState", False, False, ["LaneTreeState PDA (read-only)."]),
                ix_acc("laneRentVault", True, False, ["Per-lane LaneRentVault PDA."]),
                ix_acc("targetPage", True, False, ["SubtreePage / SubtreeRootPage / MemoPage / NullifierPage PDA."]),
                ix_acc("systemProgram", False, False, ["System Program."]),
            ],
            [
                ix_arg("pageKind", num_t("u8"), ["0=SubtreePage, 1=SubtreeRootPage, 2=MemoPage, 3=NullifierPage."]),
                ix_arg("poolId", num_t("u32")),
                ix_arg("laneId", num_t("u8")),
                ix_arg("pageSeq", num_t("u64")),
                ix_arg("maxPayerDeficit", num_t("u64"), ["Maximum lamports payer consents to cover if LaneRentVault cannot subsidize full page rent (pass 0 for proactive >=90% lookaheads)."]),
            ],
        ),
        ix_node(
            "deposit",
            tags["TAG_DEPOSIT"],
            ["Unified deposit for Native SOL (via DEPOSIT_FLAG_NATIVE_SOL + SyncNative into WSOL vault ATA) and Classic SPL / Token-2022 (net TransferFee + active TransferHook) into canonical vault_auth ATA, updating GlobalRootHistory atomically inline."],
            [
                ix_acc("depositor", True, True, ["Depositor signer."]),
                ix_acc("poolState", False, False, ["PoolState PDA (read-only)."]),
                ix_acc("roots", True, False, ["GlobalRootHistory PDA (updated atomically on deposit)."]),
                ix_acc("vaultAuthority", False, False, ["Unified vault_auth PDA."]),
                ix_acc("mint", False, False, ["WSOL, Classic SPL, or Token-2022 Mint."]),
                ix_acc("sourceAccount", True, False, ["Depositor signer pubkey (when DEPOSIT_FLAG_NATIVE_SOL) or depositor token account."]),
                ix_acc("vaultAta", True, False, ["Canonical vault_auth Associated Token Account for mint."]),
                ix_acc("tokenProgram", False, False, ["Classic SPL Token or Token-2022 program."]),
                ix_acc("laneState", True, False, ["Target active LaneTreeState PDA."]),
                ix_acc("laneRentVault", True, False, ["Per-lane LaneRentVault PDA."]),
                ix_acc("subtreePage", True, False, ["Active SubtreePage PDA."]),
                ix_acc("subrootPage", True, False, ["Active SubtreeRootPage PDA."]),
                ix_acc("memoPage", True, False, ["Active MemoPage PDA."]),
                ix_acc("systemProgram", False, False, ["System Program."]),
                ix_acc("nextSubtreePage", True, False, ["Optional rollover SubtreePage."], is_optional=True),
                ix_acc("nextMemoPage", True, False, ["Optional rollover MemoPage."], is_optional=True),
            ],
            [
                ix_arg("poolId", num_t("u32")),
                ix_arg("laneId", num_t("u8")),
                ix_arg("flags", num_t("u8"), ["bit0=nextSub, bit1=nextMemo, bit2=DEPOSIT_FLAG_FEE_FROM_AMOUNT, bit3=DEPOSIT_FLAG_NATIVE_SOL."]),
                ix_arg("amount", num_t("u64")),
                ix_arg("stealthOwner", fixed_bytes_t(32)),
                ix_arg("blinding", fixed_bytes_t(32)),
                ix_arg("memo106", fixed_bytes_t(106)),
            ],
        ),
        ix_node(
            "initRootHistory",
            tags["TAG_INIT_ROOT_HISTORY"],
            ["Authority-gated one-shot initializer creating GlobalRootHistory (10,216 B) from existing active lanes (passed as trailing read-only accounts) and updating PoolState.root_epoch_interval."],
            [
                ix_acc("authority", True, True, ["Pool authority signer and rent payer."]),
                ix_acc("poolState", True, False, ["PoolState PDA."]),
                ix_acc("roots", True, False, ["GlobalRootHistory PDA."]),
                ix_acc("systemProgram", False, False, ["System Program."]),
            ],
            [
                ix_arg("poolId", num_t("u32")),
                ix_arg("rootEpochInterval", num_t("u64")),
            ],
        ),
        ix_node(
            "transact",
            tags["TAG_TRANSACT"],
            ["Unified 2-in -> 3-out BN254 Groth16 private transfer (shielded cm2 fee) or public withdraw from canonical vault_auth ATA (incl. atomic WSOL unwrap & pause-exempt full exit) with GlobalRootHistory verification and inline root update."],
            [
                ix_acc("payer", True, True, ["Transaction fee & nullifier rent payer (relayer or user)."]),
                ix_acc("poolState", False, False, ["PoolState PDA (read-only)."]),
                ix_acc("roots", True, False, ["GlobalRootHistory PDA (writable when output_mask != 0; may be read-only on full exits with output_mask == 0)."]),
                ix_acc("nullifier0", True, False, ["Primary NullifierPDA (always created before outflow)."]),
                ix_acc("nullifier1", True, False, ["Secondary NullifierPDA (or System Program when economy nf1 == 0)."]),
                ix_acc("laneState", True, False, ["Target active output LaneTreeState PDA."]),
                ix_acc("laneRentVault", True, False, ["Per-lane LaneRentVault PDA."]),
                ix_acc("subtreePage", True, False, ["Active SubtreePage PDA."]),
                ix_acc("subrootPage", True, False, ["Active SubtreeRootPage PDA."]),
                ix_acc("memoPage", True, False, ["Active MemoPage PDA."]),
                ix_acc("nfPage", True, False, ["Active NullifierPage PDA."]),
                ix_acc("systemProgram", False, False, ["System Program."]),
            ],
            [
                ix_arg("poolId", num_t("u32")),
                ix_arg("vkId", num_t("u8")),
                ix_arg("outLaneId", num_t("u8")),
                ix_arg("outputMask", num_t("u8")),
                ix_arg("assetMode", num_t("u8"), ["0=Private, 1=Public (canonical SPL/Token-2022/WSOL vault ATA)."]),
                ix_arg("flags", num_t("u8"), ["bit0..2=rollover, bit3=WITHDRAW_FLAG_UNWRAP_WSOL."]),
                ix_arg("rootRingKind", num_t("u8"), ["0=slot ring (0..128), 1=epoch ring (0..89)."]),
                ix_arg("rootRingIdx", num_t("u8"), ["Entry index inside the selected GlobalRootHistory ring."]),
                ix_arg("proof192", fixed_bytes_t(192)),
                ix_arg("nf0", fixed_bytes_t(32)),
                ix_arg("nf1", fixed_bytes_t(32)),
                ix_arg("cm0", fixed_bytes_t(32)),
                ix_arg("cm1", fixed_bytes_t(32)),
                ix_arg("cm2", fixed_bytes_t(32)),
                ix_arg("publicAmountOut", num_t("u64")),
                ix_arg("relayerFeeAmount", num_t("u64")),
                ix_arg("memos", bytes_t()),
            ],
        ),
        ix_node(
            "execViaEscrow",
            tags["TAG_EXEC_VIA_ESCROW"],
            ["Atomic SPL / Token-2022 DeFi CPI behind WatchedEscrowBuf firewall with canonical vault/escrow ATAs, optional EXEC_FLAG_FEE_ON_OUTPUT, XOR-masked 72 B dynamic output memo, and inline GlobalRootHistory update."],
            [
                ix_acc("payer", True, True, ["Transaction fee & nullifier rent payer (never signs router CPI)."]),
                ix_acc("poolState", False, False, ["PoolState PDA (read-only)."]),
                ix_acc("roots", True, False, ["GlobalRootHistory PDA (verified and updated atomically after output append)."]),
                ix_acc("nullifier0", True, False, ["Primary NullifierPDA (created before router CPI)."]),
                ix_acc("nullifier1", True, False, ["Secondary NullifierPDA (or System Program when economy nf1 == 0)."]),
                ix_acc("laneState", True, False, ["Target active output LaneTreeState PDA."]),
                ix_acc("laneRentVault", True, False, ["Per-lane LaneRentVault PDA."]),
                ix_acc("subtreePage", True, False, ["Active SubtreePage PDA."]),
                ix_acc("subrootPage", True, False, ["Active SubtreeRootPage PDA."]),
                ix_acc("memoPage", True, False, ["Active MemoPage PDA."]),
                ix_acc("nfPage", True, False, ["Active NullifierPage PDA."]),
                ix_acc("swapEscrow", True, False, ["Isolated swap_escrow shard PDA (sole router CPI signer)."]),
                ix_acc("routerProgram", False, False, ["Executable external DeFi target program."]),
                ix_acc("systemProgram", False, False, ["System Program."]),
            ],
            [
                ix_arg("poolId", num_t("u32")),
                ix_arg("vkId", num_t("u8")),
                ix_arg("outLaneId", num_t("u8")),
                ix_arg("escrowShard", num_t("u8")),
                ix_arg("changeMask", num_t("u8")),
                ix_arg("flags", num_t("u8"), ["bit0..2=rollover, bit3=EXEC_FLAG_FEE_ON_OUTPUT."]),
                ix_arg("rootRingKind", num_t("u8"), ["0=slot ring (0..128), 1=epoch ring (0..89)."]),
                ix_arg("rootRingIdx", num_t("u8"), ["Entry index inside the selected GlobalRootHistory ring."]),
                ix_arg("proof192", fixed_bytes_t(192)),
                ix_arg("nf0", fixed_bytes_t(32)),
                ix_arg("nf1", fixed_bytes_t(32)),
                ix_arg("cm0", fixed_bytes_t(32)),
                ix_arg("cm1", fixed_bytes_t(32)),
                ix_arg("cm2", fixed_bytes_t(32)),
                ix_arg("amountIn", num_t("u64")),
                ix_arg("minAmountOut", num_t("u64")),
                ix_arg("relayerFeeAmount", num_t("u64")),
                ix_arg("outStealthOwner", fixed_bytes_t(32)),
                ix_arg("outBlinding", fixed_bytes_t(32)),
                ix_arg("dynMemoHead34", fixed_bytes_t(34)),
                ix_arg("dynMask72", fixed_bytes_t(72)),
                ix_arg("routerIxAndChangeMemos", bytes_t()),
            ],
        ),
        ix_node(
            "setPaused",
            tags["TAG_SET_PAUSED"],
            ["Authority-only emergency pause toggle (full withdrawals and OpenPage remain permanently open)."],
            [
                ix_acc("authority", False, True, ["Pool authority signer."]),
                ix_acc("poolState", True, False, ["PoolState PDA."]),
            ],
            [
                ix_arg("poolId", num_t("u32")),
                ix_arg("paused", num_t("u8")),
            ],
        ),
        ix_node(
            "updatePool",
            tags["TAG_UPDATE_POOL"],
            ["Update pool governance parameters (note_rent_fee, nf_rent_fee; root_epoch_interval is immutable after InitPool / InitRootHistory) or execute two-step authority transfer / renounce (renounce requires !paused)."],
            [
                ix_acc("signer", False, True, ["Pool authority (or pending_authority for AcceptAuthority)."]),
                ix_acc("poolState", True, False, ["PoolState PDA."]),
            ],
            [
                ix_arg("poolId", num_t("u32")),
                ix_arg("action", num_t("u8"), ["0=UpdateParams, 1=ProposeAuthority, 2=AcceptAuthority, 3=RenounceAuthority."]),
                ix_arg("payload", bytes_t(), ["UpdateParams: note_rent_fee(8)|nf_rent_fee(8); ProposeAuthority: pending_authority(32); AcceptAuthority/RenounceAuthority: empty."]),
            ],
        ),
    ]

    errors = [
        {
            "kind": "errorNode",
            "name": camel(name),
            "code": code,
            "message": ERROR_DOCS.get(name, name),
            "docs": [ERROR_DOCS.get(name, name)],
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
                "Audren — Global Multi-Asset Shielded Pool (BN254 Groth16, 4-ary Depth-20 MASP) and Protocol-Agnostic DeFi Execution Program on Solana.",
            ],
            "accounts": accounts,
            "instructions": instructions,
            "definedTypes": defined_types,
            "pdas": pdas,
            "errors": errors,
        },
        "additionalPrograms": [],
    }


def build_audren_anchor(core: dict, codama: dict) -> dict:
    prog = codama["program"]

    def map_type(t: dict):
        k = t["kind"]
        if k == "numberTypeNode":
            return t["format"]
        if k == "publicKeyTypeNode":
            return "pubkey"
        if k == "bytesTypeNode":
            return "bytes"
        if k == "fixedSizeTypeNode":
            return {"array": ["u8", t["size"]]}
        if k == "arrayTypeNode":
            return {"array": [map_type(t["item"]), t["count"]["value"]]}
        if k == "definedTypeLinkNode":
            return {"defined": {"name": pascal(t["name"])}}
        raise ValueError(f"Unsupported Codama type: {k}")

    anchor_instructions = []
    for ix in prog["instructions"]:
        disc = [ix["discriminators"][0]["constant"]["value"]["number"]]
        has_raw_tail = any(
            arg["type"]["kind"] == "bytesTypeNode"
            for arg in ix["arguments"]
            if arg["name"] != "tag"
        )
        ix_docs = list(ix.get("docs", []))
        if has_raw_tail:
            ix_docs.append(
                "Wire note (Pinocchio raw framing): trailing `bytes` argument is raw unprefixed bytes on-chain (NOT Borsh u32-length-prefixed); use @audren/sdk or audren-client builders to serialize instruction data."
            )
        anchor_instructions.append({
            "name": snake(ix["name"]),
            "docs": ix_docs,
            "discriminator": disc,
            "accounts": [
                {
                    "name": snake(a["name"]),
                    "writable": a["isWritable"],
                    "signer": a["isSigner"],
                    **({"optional": True} if a.get("isOptional") else {}),
                }
                for a in ix["accounts"]
            ],
            "args": [
                {"name": snake(arg["name"]), "type": map_type(arg["type"])}
                for arg in ix["arguments"]
                if arg["name"] != "tag"
            ],
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
        magic_str = acc["discriminators"][0]["constant"]["value"]["data"]
        anchor_accounts.append({
            "name": acc_name,
            "discriminator": list(magic_str.encode("ascii")),
        })
        # Anchor v0.30+ BorshAccountsCoder strips the 8-byte `discriminator` BEFORE decoding
        # `types[*].fields`, so omit the leading `magic` field from Anchor account structs.
        anchor_types.append({
            "name": acc_name,
            "docs": acc.get("docs", []),
            "type": {
                "kind": "struct",
                "fields": [
                    {"name": snake(f["name"]), "type": map_type(f["type"])}
                    for f in acc["data"]["fields"]
                    if f["name"] != "magic"
                ],
            },
        })

    return {
        "address": core["program_id"],
        "metadata": {
            "name": "audren",
            "version": PROGRAM_VERSION,
            "spec": "0.1.0",
            "description": "Audren — Global Multi-Asset Shielded Pool (BN254 Groth16) and Protocol-Agnostic DeFi Execution Program on Solana (Pinocchio + sBPFv3).",
            "repository": "https://github.com/audren-xyz/audren",
        },
        "instructions": anchor_instructions,
        "accounts": anchor_accounts,
        "types": anchor_types,
        "errors": [
            {"code": code, "name": name, "msg": ERROR_DOCS.get(name, name)}
            for name, code in core["errors"]
        ],
    }


def build_mock_router_codama() -> dict:
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
                "Minimal Pinocchio sBPFv3 mock AMM, yield vault, and adversarial CPI harness for Audren ExecViaEscrow integration tests.",
            ],
            "accounts": [],
            "definedTypes": [],
            "pdas": [
                pda_node("dexPool", [const_seed("dex_pool")], ["Mock router liquidity & authority PDA."]),
            ],
            "errors": [],
            "instructions": [
                ix_node(
                    "initDex",
                    0,
                    ["Initialize mock DEX pool PDA with rate_bps and initial SOL liquidity."],
                    [
                        ix_acc("payer", True, True, ["Funder."]),
                        ix_acc("dexPool", True, False, ["Mock DEX pool PDA."]),
                        ix_acc("systemProgram", False, False, ["System Program."]),
                    ],
                    [ix_arg("rateBps", num_t("u64")), ix_arg("liquidityLamports", num_t("u64"))],
                ),
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
    (SDK_IDL_DIR / "audren.codama.json").write_text(codama_json)
    (SDK_IDL_DIR / "audren.anchor.json").write_text(anchor_json)

    sdk_ts = (
        "// AUTO-GENERATED by idl/generate-idl.py from crates/audren-core — DO NOT EDIT BY HAND.\n"
        "// Re-run `python3 idl/generate-idl.py && python3 idl/verify-idl.py` after any protocol change.\n\n"
        f"export const AUDREN_CODAMA_IDL = {codama_json.rstrip()} as const;\n\n"
        f"export const AUDREN_ANCHOR_IDL = {anchor_json.rstrip()} as const;\n"
    )
    (ROOT / "packages" / "sdk" / "src" / "idl.ts").write_text(sdk_ts)

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
        f"{len(codama['program']['errors'])} errors."
    )


if __name__ == "__main__":
    main()
