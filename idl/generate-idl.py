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
        "CKPT_LEN",
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
    "CheckpointTooSoon": "Checkpoint epoch is not strictly greater than the existing slot epoch.",
    "CheckpointExpired": "Referenced RootCheckpoint exceeded PoolState.max_ckpt_age slots.",
    "CheckpointMismatch": "Referenced RootCheckpoint account is uninitialized or belongs to another pool.",
    "ProofVerificationFailed": "BN254 Groth16 proof verification or ctx_hash binding failed.",
    "InvalidVkId": "Verifying key identifier is unsupported for this PoolMode.",
    "NullifierAlreadyUsed": "NullifierPDA already exists (note already spent).",
    "PoseidonFailed": "Solana sol_poseidon BN254 syscall returned an error.",
    "SlippageExceeded": "Measured net vault output is zero or below min_amount_out after fees.",
    "CustodyInvariantViolated": "Pool custody accounting invariant failed.",
    "Overflow": "Checked integer arithmetic overflow or tree capacity exceeded.",
    "InsufficientVaultBalance": "Custody vault holds insufficient balance for outflow.",
    "MemoPageFull": "Active MemoPage has reached 112 note entries.",
    "MemoPageMismatch": "Provided MemoPage sequence does not match active lane leaf index.",
    "InvalidTokenAccount": "Invalid SPL / Token-2022 mint, custody ATA, delegate, close_authority, or TLV extension.",
    "ForbiddenRouterAccount": "Forbidden Audren custody, program, or relayer fee account smuggled into router_accounts.",
    "EscrowNotDrained": "External DeFi CPI left unspent input tokens or SOL dust in escrow.",
    "NullifierPageFull": "Active NullifierPage has reached 600 nullifier prefixes.",
    "NullifierPageMismatch": "Provided NullifierPage sequence does not match active lane nf_count.",
    "InvalidEscrowShard": "Escrow shard index must be in 0..16.",
    "InvalidFieldElement": "32-byte input is not a canonical BN254 scalar (< Fr modulus).",
    "PoolPaused": "Pool is paused by authority (full exits, PublishCheckpoint, and OpenPage remain open).",
    "Unauthorized": "Required authority signer is missing or mismatched.",
    "PageSeqOutOfRange": "OpenPage sequence exceeds cur_seq + 2 lookahead bound.",
    "InvalidTargetProgram": "Target program must be executable and cannot be Audren, System, Token, or ATA.",
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
        pda_node("solVault", [const_seed(seeds["SOL_VAULT_SEED"]), var_seed("poolId", num_t("u32"))], ["Unified System-owned Native SOL custody vault PDA."]),
        pda_node("vaultAuthority", [const_seed(seeds["VAULT_AUTH_SEED"]), var_seed("poolId", num_t("u32"))], ["Unified SPL / Token-2022 custody vault ATA owner PDA."]),
        pda_node("laneTreeState", [const_seed(seeds["LANE_SEED"]), var_seed("poolId", num_t("u32")), var_seed("laneId", num_t("u8"))], ["Per-lane 4-ary Depth-18 incremental frontier PDA (1,824 B)."]),
        pda_node("laneRentVault", [const_seed(seeds["LANE_RENT_SEED"]), var_seed("poolId", num_t("u32")), var_seed("laneId", num_t("u8"))], ["Per-lane self-funding rent sentinel PDA (16 B)."]),
        pda_node("subtreePage", [const_seed(seeds["SUBTREE_SEED"]), var_seed("poolId", num_t("u32")), var_seed("laneId", num_t("u8")), var_seed("pageSeq", num_t("u64"))], ["256-leaf note commitment page PDA (8,256 B)."]),
        pda_node("subtreeRootPage", [const_seed(seeds["SUBROOT_SEED"]), var_seed("poolId", num_t("u32")), var_seed("laneId", num_t("u8")), var_seed("rootPageSeq", num_t("u64"))], ["300 finalized 256-leaf subtree roots PDA (9,664 B)."]),
        pda_node("memoPage", [const_seed(seeds["MEMO_SEED"]), var_seed("poolId", num_t("u32")), var_seed("laneId", num_t("u8")), var_seed("pageSeq", num_t("u64"))], ["112 x 90 B compact SoA encrypted note memos PDA (10,144 B)."]),
        pda_node("nullifierPage", [const_seed(seeds["NF_PAGE_SEED"]), var_seed("poolId", num_t("u32")), var_seed("laneId", num_t("u8")), var_seed("pageSeq", num_t("u64"))], ["600 x 16 B nullifier prefixes PDA for ordinary-RPC spent sync (9,664 B)."]),
        pda_node("rootCheckpoint", [const_seed(seeds["CKPT_SEED"]), var_seed("poolId", num_t("u32")), var_seed("slotIdx", num_t("u16"))], ["Cyclic 256-slot global super_root checkpoint ring PDA (704 B)."]),
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
                field("ckptInterval", num_t("u64")),
                field("maxCkptAge", num_t("u64")),
                field("authority", pubkey_t()),
                field("solVaultBump", num_t("u8")),
                field("vaultAuthBump", num_t("u8")),
                field("mode", num_t("u8")),
                field("reserved1", fixed_bytes_t(5)),
                field("noteRentFee", num_t("u64")),
                field("nfRentFee", num_t("u64")),
                field("auditorPk", fixed_bytes_t(32)),
                field("reserved2", fixed_bytes_t(8)),
            ],
            ["Global pool configuration (128 B; read-only on all deposits, spends, checkpoints, and DeFi swaps)."],
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
            ["Append-only 256-leaf note commitment page (8,256 B < 10 KiB)."],
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
            ["Append-only 300 finalized 256-leaf subtree roots page (9,664 B < 10 KiB)."],
        ),
        account_node(
            "memoPage",
            magics["MEMO_MAGIC"],
            10144,
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
                field("viewTags", fixed_array_t(fixed_bytes_t(2), 112)),
                field("ephemeralPks", fixed_array_t(fixed_bytes_t(32), 112)),
                field("ciphertexts", fixed_array_t(fixed_bytes_t(56), 112)),
            ],
            ["Compact Structure-of-Arrays 112 x 90 B note memo page (10,144 B < 10 KiB)."],
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
            ["Append-only 600 x 16 B nullifier prefix page for zero-leakage wallet sync (9,664 B < 10 KiB)."],
        ),
        account_node(
            "rootCheckpoint",
            magics["CKPT_MAGIC"],
            704,
            [
                field("magic", fixed_bytes_t(8)),
                field("version", num_t("u8")),
                field("bump", num_t("u8")),
                field("slotIdx", num_t("u16")),
                field("poolId", num_t("u32")),
                field("epochId", num_t("u64")),
                field("publishedSlot", num_t("u64")),
                field("superRoot", fixed_bytes_t(32)),
                field("laneRoots", fixed_array_t(fixed_bytes_t(32), 16)),
                field("laneCounts", fixed_array_t(num_t("u64"), 16)),
            ],
            ["Fixed-size cyclic global checkpoint ring slot (704 B, 256 slots max)."],
        ),
    ]

    defined_types = [
        {
            "kind": "definedTypeNode",
            "name": "poolMode",
            "docs": ["Pool governance / verifying-key policy."],
            "type": {
                "kind": "enumTypeNode",
                "size": num_t("u8"),
                "variants": [
                    {"kind": "enumEmptyVariantTypeNode", "name": "permissionless"},
                    {"kind": "enumEmptyVariantTypeNode", "name": "institutionalAudited"},
                ],
            },
        }
    ]

    instructions = [
        ix_node(
            "initPool",
            tags["TAG_INIT_POOL"],
            ["Initialize PoolState (active_lanes = 0) and prefund unified sol_vault PDA."],
            [
                ix_acc("payer", True, True, ["Pool authority and rent payer."]),
                ix_acc("poolState", True, False, ["PoolState PDA."]),
                ix_acc("solVault", True, False, ["Unified Native SOL custody vault PDA."]),
                ix_acc("systemProgram", False, False, ["System Program."]),
            ],
            [
                ix_arg("poolId", num_t("u32")),
                ix_arg("ckptInterval", num_t("u64")),
                ix_arg("maxCkptAge", num_t("u64")),
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
            ["Idempotent, sequence-bounded, pause-exempt, LaneRentVault-subsidized page opener."],
            [
                ix_acc("payer", True, True, ["Permissionless cranker / fallback rent payer."]),
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
            ],
        ),
        ix_node(
            "depositSol",
            tags["TAG_DEPOSIT_SOL"],
            ["Deposit Native SOL into unified sol_vault (supports zero-dust DEPOSIT_FLAG_FEE_FROM_AMOUNT)."],
            [
                ix_acc("depositor", True, True, ["Native SOL depositor signer."]),
                ix_acc("poolState", False, False, ["PoolState PDA (read-only)."]),
                ix_acc("solVault", True, False, ["Unified sol_vault PDA."]),
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
                ix_arg("flags", num_t("u8"), ["bit0=nextSub, bit1=nextMemo, bit2=DEPOSIT_FLAG_FEE_FROM_AMOUNT."]),
                ix_arg("amount", num_t("u64")),
                ix_arg("stealthOwner", fixed_bytes_t(32)),
                ix_arg("blinding", fixed_bytes_t(32)),
                ix_arg("memo90", fixed_bytes_t(90)),
            ],
        ),
        ix_node(
            "depositSpl",
            tags["TAG_DEPOSIT_SPL"],
            ["Deposit Classic SPL or Token-2022 (net TransferFee + active TransferHook) into unified vault_auth ATA."],
            [
                ix_acc("depositor", True, True, ["Token depositor signer."]),
                ix_acc("poolState", False, False, ["PoolState PDA (read-only)."]),
                ix_acc("vaultAuthority", False, False, ["Unified vault_auth PDA."]),
                ix_acc("mint", False, False, ["SPL or Token-2022 Mint."]),
                ix_acc("depositorAta", True, False, ["Depositor source token account."]),
                ix_acc("vaultAta", True, False, ["Pool vault_auth token account."]),
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
                ix_arg("flags", num_t("u8"), ["bit0=nextSub, bit1=nextMemo."]),
                ix_arg("amount", num_t("u64")),
                ix_arg("stealthOwner", fixed_bytes_t(32)),
                ix_arg("blinding", fixed_bytes_t(32)),
                ix_arg("memo90", fixed_bytes_t(90)),
            ],
        ),
        ix_node(
            "publishCheckpoint",
            tags["TAG_PUBLISH_CHECKPOINT"],
            ["Permissionless, pause-exempt global super_root checkpoint publisher over active_lanes read-only lanes."],
            [
                ix_acc("payer", True, True, ["Permissionless cranker."]),
                ix_acc("poolState", False, False, ["PoolState PDA (read-only)."]),
                ix_acc("checkpoint", True, False, ["Cyclic RootCheckpoint(slot_idx) PDA."]),
                ix_acc("systemProgram", False, False, ["System Program."]),
            ],
            [ix_arg("poolId", num_t("u32"))],
        ),
        ix_node(
            "joinSplit",
            tags["TAG_JOINSPLIT"],
            ["Unified 2-in -> 3-out BN254 Groth16 private transfer (shielded cm2 fee) or public withdraw (incl. atomic WSOL unwrap & pause-exempt full exit)."],
            [
                ix_acc("payer", True, True, ["Transaction fee & nullifier rent payer (relayer or user)."]),
                ix_acc("poolState", False, False, ["PoolState PDA (read-only)."]),
                ix_acc("checkpoint", False, False, ["Referenced RootCheckpoint PDA."]),
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
                ix_arg("assetMode", num_t("u8"), ["0=Private, 1=NativeSOL, 2=SPL/T22."]),
                ix_arg("flags", num_t("u8"), ["bit0..2=rollover, bit3=WITHDRAW_FLAG_UNWRAP_WSOL."]),
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
            ["Atomic multi-asset DeFi CPI behind WatchedEscrowBuf firewall with optional EXEC_FLAG_FEE_ON_OUTPUT and XOR-masked dynamic output memo."],
            [
                ix_acc("payer", True, True, ["Transaction fee & nullifier rent payer (never signs router CPI)."]),
                ix_acc("poolState", False, False, ["PoolState PDA (read-only)."]),
                ix_acc("checkpoint", False, False, ["Referenced RootCheckpoint PDA."]),
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
                ix_arg("inKind", num_t("u8"), ["0=SOL, 1=SPL/T22."]),
                ix_arg("outKind", num_t("u8"), ["0=SOL, 1=SPL/T22."]),
                ix_arg("flags", num_t("u8"), ["bit0..2=rollover, bit3=EXEC_FLAG_FEE_ON_OUTPUT."]),
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
                ix_arg("dynMask56", fixed_bytes_t(56)),
                ix_arg("routerIxAndChangeMemos", bytes_t()),
            ],
        ),
        ix_node(
            "setPaused",
            tags["TAG_SET_PAUSED"],
            ["Authority-only emergency pause toggle (full withdrawals, PublishCheckpoint, and OpenPage remain permanently open)."],
            [
                ix_acc("authority", False, True, ["Pool authority signer."]),
                ix_acc("poolState", True, False, ["PoolState PDA."]),
            ],
            [
                ix_arg("poolId", num_t("u32")),
                ix_arg("paused", num_t("u8")),
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
        anchor_instructions.append({
            "name": snake(ix["name"]),
            "docs": ix.get("docs", []),
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
    for acc in prog["accounts"]:
        acc_name = pascal(acc["name"])
        magic_str = acc["discriminators"][0]["constant"]["value"]["data"]
        anchor_accounts.append({
            "name": acc_name,
            "discriminator": list(magic_str.encode("ascii")),
        })
        anchor_types.append({
            "name": acc_name,
            "docs": acc.get("docs", []),
            "type": {
                "kind": "struct",
                "fields": [{"name": snake(f["name"]), "type": map_type(f["type"])} for f in acc["data"]["fields"]],
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
