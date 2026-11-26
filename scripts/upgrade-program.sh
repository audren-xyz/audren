#!/usr/bin/env bash
set -euo pipefail

# Audren release, upgrade, Program Metadata, and Verified Build operator script.
#
# Every program upgrade automatically enforces release compliance:
#   1. Local drift verification (`idl/verify-idl.py`: IDLs, @audren/sdk, security.json,
#      embedded .security.txt, Cargo.toml versions, and pinned Agave/sBPFv3 toolchain).
#   2. sBPFv3 ELF64 header verification (`scripts/build-sbf.py --check-elf`) and, on Mainnet,
#      ELF-to-HEAD freshness verification against `program/target/deploy/audren.verifiable.json`
#      (`elf_sha256`, `head_commit`, `program_tree`, `core_tree`, `version`, `worktree_clean`).
#   3. Program deployment (two-step `write-buffer --use-rpc` + `deploy --buffer --use-rpc`
#      on Mainnet to eliminate UDP/QUIC chunk drops and orphaned buffer leaks), followed
#      IMMEDIATELY by idempotent Pool #0 `GlobalRootHistory` migration (`InitRootHistory`, Tag 4,
#      unless `SKIP_INIT_ROOT_HISTORY=1`) so live Pool #0 never waits on metadata/verify/release.
#   4. Automatic Solana Program Metadata sync (`security` + `idl`) with round-trip verification.
#   5. On Mainnet: automatic Solana Verified Build attestation (Otter Verify PDA update +
#      remote job submission to `verify.osec.io`) AND automatic GitHub tag + Release cutting
#      (`v<version>` with verified ELF, SHA-256, `audren_joinsplit.pk`, `transcript.json`, IDLs,
#      and `security.json`), requiring a clean pushed commit and deterministic Docker build
#      (`build-verifiable`) unless `ALLOW_UNVERIFIED_DEPLOY=1`.
#
# Configuration is read strictly from environment variables or gitignored `.credentials/operator.env`:
#   MAINNET_RPC_URL      - Solana Mainnet RPC URL
#   DEVNET_RPC_URL       - Solana Devnet RPC URL
#   AUDREN_KEYPAIR_PATH  - Upgrade authority / fee payer keypair JSON (default: .credentials/funder.json)
#   AUDREN_PROGRAM_ID    - Target program ID (default: AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3)
#   AUDREN_SO_PATH       - Optional explicit path to sBPFv3 `.so` artifact
#
# Usage:
#   ./scripts/upgrade-program.sh build-verifiable
#   ./scripts/upgrade-program.sh devnet
#   ./scripts/upgrade-program.sh mainnet [--commit <sha>]
#   ./scripts/upgrade-program.sh metadata <devnet|mainnet>
#   ./scripts/upgrade-program.sh idl <devnet|mainnet>
#   ./scripts/upgrade-program.sh security <devnet|mainnet>
#   ./scripts/upgrade-program.sh verify <mainnet|devnet> [--commit <sha>]
#   ./scripts/upgrade-program.sh release [--commit <sha>]
#   ./scripts/upgrade-program.sh check <devnet|mainnet>

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -f "$ROOT/.credentials/operator.env" ]]; then
  # shellcheck disable=SC1091
  source "$ROOT/.credentials/operator.env"
fi

if [[ -d "$HOME/.cargo/bin" && ":$PATH:" != *":$HOME/.cargo/bin:"* ]]; then
  export PATH="$HOME/.cargo/bin:$PATH"
fi

# Pinned build & verification parameters (cross-checked by `idl/verify-idl.py`).
AGAVE_VERSION="4.3.0"
TOOLS_VERSION="v1.57"
SBF_ARCH="v3"
VERIFY_BASE_IMAGE="solanafoundation/solana-verifiable-build@sha256:12fd4c0a0790f0fc41ef74b0cdb6bccc167ba6137eb1adb749bac649481c86bd"
PROGRAM_METADATA_PKG="@solana-program/program-metadata@0.11.0"
REPO_OWNER_NAME="audren-xyz/audren"
REPO_URL="https://github.com/${REPO_OWNER_NAME}"
PROGRAM_LIB_NAME="audren"
PROGRAM_WORKSPACE_PATH="program"

PROGRAM_ID="${AUDREN_PROGRAM_ID:-AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3}"
KEYPAIR="${AUDREN_KEYPAIR_PATH:-$ROOT/.credentials/funder.json}"
VERIFIABLE_SO_PATH="$ROOT/program/target/deploy/audren.so"
VERIFIABLE_META_PATH="$ROOT/program/target/deploy/audren.verifiable.json"
LOCAL_SO_PATH="$ROOT/target/deploy/audren.so"
IDL_PATH="$ROOT/idl/audren.codama.json"
SECURITY_PATH="$ROOT/idl/security.json"

usage() {
  cat >&2 <<'EOF'
Usage:
  ./scripts/upgrade-program.sh build-verifiable
  ./scripts/upgrade-program.sh devnet
  ./scripts/upgrade-program.sh mainnet [--commit <sha>]
  ./scripts/upgrade-program.sh metadata <devnet|mainnet>
  ./scripts/upgrade-program.sh idl <devnet|mainnet>
  ./scripts/upgrade-program.sh security <devnet|mainnet>
  ./scripts/upgrade-program.sh verify <mainnet|devnet> [--commit <sha>]
  ./scripts/upgrade-program.sh release [--commit <sha>]
  ./scripts/upgrade-program.sh check <devnet|mainnet>
EOF
  exit 1
}

resolve_rpc() {
  local cluster="$1"
  case "$cluster" in
    devnet)
      [[ -n "${DEVNET_RPC_URL:-}" ]] || { echo "Error: DEVNET_RPC_URL is not set" >&2; exit 1; }
      echo "$DEVNET_RPC_URL"
      ;;
    mainnet)
      [[ -n "${MAINNET_RPC_URL:-}" ]] || { echo "Error: MAINNET_RPC_URL is not set" >&2; exit 1; }
      echo "$MAINNET_RPC_URL"
      ;;
    *)
      usage
      ;;
  esac
}

require_keypair() {
  [[ -f "$KEYPAIR" ]] || { echo "Error: keypair not found at $KEYPAIR" >&2; exit 1; }
}

resolve_solana_cli() {
  local candidate=""
  if [[ -n "${AUDREN_SOLANA_BIN:-}" && -x "$AUDREN_SOLANA_BIN" ]]; then
    echo "$AUDREN_SOLANA_BIN"
    return 0
  fi
  if command -v solana >/dev/null 2>&1; then
    local ver major
    ver="$(solana --version 2>/dev/null | awk '{print $2}' || true)"
    major="${ver%%.*}"
    if [[ "$major" =~ ^[0-9]+$ && "$major" -ge 3 ]]; then
      command -v solana
      return 0
    fi
  fi
  # Fall back to the highest Agave >= 3.x release installed under ~/.local/share/solana/install/releases
  candidate="$(python3 - <<'PY'
import pathlib, re
root = pathlib.Path.home() / ".local/share/solana/install/releases"
best = None
if root.is_dir():
    for entry in root.iterdir():
        m = re.match(r"^(\d+)\.(\d+)\.(\d+)$", entry.name)
        if not m:
            continue
        ver = tuple(int(x) for x in m.groups())
        if ver[0] < 3:
            continue
        bin_path = entry / "solana-release/bin/solana"
        if bin_path.is_file() and (best is None or ver > best[0]):
            best = (ver, str(bin_path))
if best:
    print(best[1])
PY
)"
  if [[ -n "$candidate" && -x "$candidate" ]]; then
    echo "$candidate"
    return 0
  fi
  echo "Error: Agave CLI >= 3.x is required to deploy sBPFv3 programs (active solana is too old). Set AUDREN_SOLANA_BIN or install Agave 4.x." >&2
  exit 1
}

resolve_solana_keygen() {
  local solana_bin sibling
  solana_bin="$(resolve_solana_cli)"
  sibling="$(dirname "$solana_bin")/solana-keygen"
  if [[ -x "$sibling" ]]; then
    echo "$sibling"
    return 0
  fi
  if command -v solana-keygen >/dev/null 2>&1; then
    command -v solana-keygen
    return 0
  fi
  echo "Error: solana-keygen not found alongside $solana_bin or on PATH." >&2
  exit 1
}

_AUDREN_CLEANUP_PATHS=()
cleanup_temp_paths() {
  local p
  for p in "${_AUDREN_CLEANUP_PATHS[@]:-}"; do
    if [[ -n "$p" ]]; then
      rm -rf "$p"
    fi
  done
  return 0
}
trap cleanup_temp_paths EXIT

require_solana_verify() {
  if ! command -v solana-verify >/dev/null 2>&1; then
    cat >&2 <<'EOF'
Error: `solana-verify` CLI is not installed.
Install v0.5.2+ before building or verifying Mainnet releases:
  cargo install solana-verify --git https://github.com/solana-foundation/solana-verifiable-build --tag v0.5.2 --locked
EOF
    exit 1
  fi
}

verify_onchain_metadata() {
  local seed="$1"
  local rpc_url="$2"
  local expected_path="$3"
  local tmp_dir fetched attempt
  tmp_dir="$(mktemp -d "/tmp/audren-meta-XXXXXX")"
  _AUDREN_CLEANUP_PATHS+=("$tmp_dir")
  fetched="${tmp_dir}/${seed}.txt"
  for attempt in 1 2 3 4; do
    if npx --yes "$PROGRAM_METADATA_PKG" fetch "$seed" \
      "$PROGRAM_ID" \
      --rpc "$rpc_url" >"$fetched" 2>/dev/null &&
      python3 - "$expected_path" "$fetched" "$seed" <<'PY'
import json, pathlib, sys

expected_path, fetched_path, seed = sys.argv[1], sys.argv[2], sys.argv[3]
expected = json.loads(pathlib.Path(expected_path).read_text())
raw = pathlib.Path(fetched_path).read_text().strip()
start = raw.find("{")
if start == -1:
    sys.exit(f"Error: on-chain '{seed}' fetch did not return JSON:\n{raw}")
actual = json.loads(raw[start:])
if actual != expected:
    sys.exit(f"Error: on-chain Program Metadata '{seed}' does not match {expected_path}")
print(f"Verified on-chain Program Metadata '{seed}' matches {expected_path} byte-for-byte.")
PY
    then
      rm -rf "$tmp_dir"
      return 0
    fi
    if [[ "$attempt" -lt 4 ]]; then
      echo "Waiting 3s for on-chain Program Metadata '${seed}' RPC propagation (attempt ${attempt}/4)..." >&2
      sleep 3
    fi
  done
  rm -rf "$tmp_dir"
  echo "Error: failed to verify on-chain Program Metadata '${seed}' for $PROGRAM_ID after 4 attempts" >&2
  exit 1
}

publish_security() {
  local cluster="$1"
  local rpc_url="$2"
  echo "Publishing canonical security metadata ($SECURITY_PATH) for $PROGRAM_ID on $cluster..."
  npx --yes "$PROGRAM_METADATA_PKG" write security \
    "$PROGRAM_ID" \
    "$SECURITY_PATH" \
    --format json \
    --keypair "$KEYPAIR" \
    --rpc "$rpc_url"
  verify_onchain_metadata security "$rpc_url" "$SECURITY_PATH"
}

list_metadata_buffers() {
  local rpc_url="$1"
  npx --yes "$PROGRAM_METADATA_PKG" list-buffers \
    --keypair "$KEYPAIR" \
    --rpc "$rpc_url" 2>/dev/null | python3 -c '
import re, sys
for m in re.findall(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b", sys.stdin.read()):
    print(m)
' || true
}

publish_idl() {
  local cluster="$1"
  local rpc_url="$2"
  local tmp_dir min_idl solana_keygen
  tmp_dir="$(mktemp -d "/tmp/audren-meta-XXXXXX")"
  _AUDREN_CLEANUP_PATHS+=("$tmp_dir")
  min_idl="${tmp_dir}/idl.json"
  python3 -c "import json, pathlib, sys; pathlib.Path(sys.argv[2]).write_text(json.dumps(json.loads(pathlib.Path(sys.argv[1]).read_text()), separators=(',',':')))" "$IDL_PATH" "$min_idl"

  local authority
  solana_keygen="$(resolve_solana_keygen)"
  authority="$("$solana_keygen" pubkey "$KEYPAIR")"
  local before_buffers
  before_buffers="$(list_metadata_buffers "$rpc_url")"

  echo "Publishing canonical Codama IDL ($IDL_PATH) for $PROGRAM_ID on $cluster..."
  if ! npx --yes "$PROGRAM_METADATA_PKG" write idl \
    "$PROGRAM_ID" \
    "$min_idl" \
    --format json \
    --keypair "$KEYPAIR" \
    --rpc "$rpc_url"; then
    echo "Direct multi-tx upload hit RPC propagation lag; recovering via pre-created buffer..." >&2
    sleep 2
    local after_buffers new_buffer
    after_buffers="$(list_metadata_buffers "$rpc_url")"
    new_buffer="$(python3 - "$authority" "$before_buffers" "$after_buffers" <<'PY'
import sys
authority = sys.argv[1].strip()
before = set(sys.argv[2].split()) | {authority}
after = [x for x in sys.argv[3].split() if x not in before]
if after:
    print(after[-1])
PY
)"
    if [[ -z "$new_buffer" ]]; then
      rm -rf "$tmp_dir"
      echo "Error: direct IDL upload failed and no new buffer account was found." >&2
      exit 1
    fi
    echo "Populating buffer $new_buffer and finalizing canonical IDL..." >&2
    if ! npx --yes "$PROGRAM_METADATA_PKG" update-buffer \
      "$new_buffer" \
      "$min_idl" \
      --format json \
      --keypair "$KEYPAIR" \
      --rpc "$rpc_url"; then
      npx --yes "$PROGRAM_METADATA_PKG" close "$new_buffer" --keypair "$KEYPAIR" --rpc "$rpc_url" >/dev/null 2>&1 || true
      rm -rf "$tmp_dir"
      exit 1
    fi
    if ! npx --yes "$PROGRAM_METADATA_PKG" write idl \
      "$PROGRAM_ID" \
      --buffer "$new_buffer" \
      --close-buffer \
      --keypair "$KEYPAIR" \
      --rpc "$rpc_url"; then
      npx --yes "$PROGRAM_METADATA_PKG" close "$new_buffer" --keypair "$KEYPAIR" --rpc "$rpc_url" >/dev/null 2>&1 || true
      rm -rf "$tmp_dir"
      exit 1
    fi
  fi
  rm -rf "$tmp_dir"
  verify_onchain_metadata idl "$rpc_url" "$IDL_PATH"
}

resolve_verified_commit() {
  local explicit_commit="${1:-}"
  local require_clean_head="${2:-0}"
  local commit="$explicit_commit"
  if [[ "$require_clean_head" == "1" || -z "$commit" ]]; then
    if [[ -n "$(git status --porcelain)" ]]; then
      echo "Error: working tree has uncommitted changes. Commit and push to $REPO_URL before Mainnet deploy/verification." >&2
      exit 1
    fi
    local head_sha
    if ! head_sha="$(git rev-parse HEAD 2>/dev/null)"; then
      echo "Error: repository has no commits yet. Commit and push to $REPO_URL (or pass --commit <sha> to 'verify')." >&2
      exit 1
    fi
    if [[ -z "$commit" ]]; then
      commit="$head_sha"
    elif [[ "$require_clean_head" == "1" && "$commit" != "$head_sha" ]]; then
      echo "Error: --commit ${commit} does not match checked-out HEAD ${head_sha}. Checkout the exact commit being deployed." >&2
      exit 1
    fi
  fi
  if ! curl -fsS -o /dev/null "https://api.github.com/repos/${REPO_OWNER_NAME}/commits/${commit}"; then
    echo "Error: commit ${commit} is not publicly reachable on ${REPO_URL}. Push it before Mainnet deploy/verification." >&2
    exit 1
  fi
  echo "$commit"
}

build_verifiable() {
  require_solana_verify
  command -v docker >/dev/null 2>&1 || { echo "Error: docker is required for verifiable builds" >&2; exit 1; }
  python3 "$ROOT/idl/verify-idl.py"

  local head_commit program_tree core_tree version worktree_clean
  head_commit="$(git rev-parse HEAD)"
  program_tree="$(git rev-parse HEAD:program)"
  core_tree="$(git rev-parse HEAD:crates/audren-core)"
  version="$(read_program_version)"
  if [[ -z "$(git status --porcelain -- program crates/audren-core)" ]]; then
    worktree_clean="true"
  else
    worktree_clean="false"
  fi

  echo "Building deterministic sBPFv3 binary (Agave ${AGAVE_VERSION}, tools ${TOOLS_VERSION}, arch ${SBF_ARCH})..."
  solana-verify build \
    --workspace-path "$PROGRAM_WORKSPACE_PATH" \
    --library-name "$PROGRAM_LIB_NAME" \
    --base-image "$VERIFY_BASE_IMAGE" \
    --arch "$SBF_ARCH" \
    --cargo-build-sbf-args="--tools-version ${TOOLS_VERSION}"

  echo "Validating sBPFv3 ELF header..."
  python3 "$ROOT/scripts/build-sbf.py" --check-elf "$VERIFIABLE_SO_PATH"
  local exec_hash
  exec_hash="$(solana-verify get-executable-hash "$VERIFIABLE_SO_PATH" | tail -n 1 | tr -d '[:space:]')"
  echo "solana-verify executable hash: ${exec_hash}"

  python3 - "$VERIFIABLE_SO_PATH" "$VERIFIABLE_META_PATH" "$head_commit" "$program_tree" "$core_tree" "$version" "$exec_hash" "$worktree_clean" "$AGAVE_VERSION" "$TOOLS_VERSION" "$SBF_ARCH" "$VERIFY_BASE_IMAGE" <<'PY'
import datetime, hashlib, json, pathlib, sys

(
    so_path,
    meta_path,
    head_commit,
    program_tree,
    core_tree,
    version,
    exec_hash,
    worktree_clean,
    agave_version,
    tools_version,
    sbf_arch,
    base_image,
) = sys.argv[1:]

elf = pathlib.Path(so_path).read_bytes()
elf_sha256 = hashlib.sha256(elf).hexdigest()
meta = {
    "version": version,
    "head_commit": head_commit,
    "program_tree": program_tree,
    "core_tree": core_tree,
    "elf_sha256": elf_sha256,
    "executable_hash": exec_hash,
    "elf_bytes": len(elf),
    "worktree_clean": worktree_clean == "true",
    "agave_version": agave_version,
    "tools_version": tools_version,
    "sbf_arch": sbf_arch,
    "base_image": base_image,
    "built_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
pathlib.Path(meta_path).write_text(json.dumps(meta, indent=2) + "\n")
print(
    f"Stamped verifiable build manifest: {meta_path} "
    f"(v{version}, {len(elf)} B, sha256={elf_sha256[:16]}..., head={head_commit[:12]}, clean={meta['worktree_clean']})"
)
PY
  if [[ "$worktree_clean" != "true" ]]; then
    echo "WARNING: working tree had uncommitted changes in program/ or crates/audren-core/ during build-verifiable. Commit and re-run build-verifiable before Mainnet deploy." >&2
  fi
}

verify_verifiable_elf_freshness() {
  local so_path="$1"
  local expected_commit="$2"
  local expected_version="$3"
  if [[ ! -f "$VERIFIABLE_META_PATH" ]]; then
    echo "Error: verifiable build freshness manifest missing at $VERIFIABLE_META_PATH." >&2
    echo "Refusing to deploy an unattested or potentially stale ELF ($so_path)." >&2
    echo "Rebuild on clean HEAD first: ./scripts/upgrade-program.sh build-verifiable" >&2
    exit 1
  fi
  local expected_program_tree expected_core_tree
  expected_program_tree="$(git rev-parse HEAD:program)"
  expected_core_tree="$(git rev-parse HEAD:crates/audren-core)"
  python3 - "$VERIFIABLE_META_PATH" "$so_path" "$expected_commit" "$expected_program_tree" "$expected_core_tree" "$expected_version" <<'PY'
import hashlib, json, pathlib, sys

meta_path, so_path, exp_commit, exp_prog_tree, exp_core_tree, exp_version = sys.argv[1:]
try:
    meta = json.loads(pathlib.Path(meta_path).read_text())
except Exception as exc:
    sys.exit(f"Error: failed to parse {meta_path}: {exc}. Re-run ./scripts/upgrade-program.sh build-verifiable.")

elf = pathlib.Path(so_path).read_bytes()
actual_sha = hashlib.sha256(elf).hexdigest()
actual_bytes = len(elf)

if meta.get("worktree_clean") is not True:
    sys.exit(
        f"Error: {meta_path} indicates the ELF was built from a dirty working tree. "
        "Re-run ./scripts/upgrade-program.sh build-verifiable on clean committed HEAD."
    )
if meta.get("elf_sha256") != actual_sha:
    sys.exit(
        f"Error: stale or tampered ELF at {so_path} ({actual_bytes} B): "
        f"actual sha256={actual_sha} != {meta_path} elf_sha256={meta.get('elf_sha256')}. "
        "Re-run ./scripts/upgrade-program.sh build-verifiable."
    )
if "elf_bytes" in meta and meta.get("elf_bytes") != actual_bytes:
    sys.exit(
        f"Error: ELF size mismatch at {so_path}: actual={actual_bytes} B != {meta_path} elf_bytes={meta.get('elf_bytes')}."
    )
if meta.get("version") != exp_version:
    sys.exit(
        f"Error: stale verifiable ELF version in {meta_path}: {meta.get('version')} != program/Cargo.toml {exp_version}. "
        "Re-run ./scripts/upgrade-program.sh build-verifiable."
    )
if meta.get("head_commit") != exp_commit:
    sys.exit(
        f"Error: stale verifiable ELF in {meta_path}: head_commit={meta.get('head_commit')} != HEAD {exp_commit}. "
        "Re-run ./scripts/upgrade-program.sh build-verifiable."
    )
if meta.get("program_tree") != exp_prog_tree:
    sys.exit(
        f"Error: stale verifiable ELF in {meta_path}: program_tree={meta.get('program_tree')} != HEAD:program {exp_prog_tree}. "
        "Re-run ./scripts/upgrade-program.sh build-verifiable."
    )
if meta.get("core_tree") != exp_core_tree:
    sys.exit(
        f"Error: stale verifiable ELF in {meta_path}: core_tree={meta.get('core_tree')} != HEAD:crates/audren-core {exp_core_tree}. "
        "Re-run ./scripts/upgrade-program.sh build-verifiable."
    )
print(
    f"Verified verifiable ELF freshness ({so_path}: v{exp_version}, {actual_bytes} B, "
    f"sha256={actual_sha[:16]}..., HEAD={exp_commit[:12]}, program_tree & core_tree matched)."
)
PY
}

verify_onchain_build() {
  local cluster="$1"
  local rpc_url="$2"
  local commit="$3"
  require_solana_verify
  require_keypair

  local uploader solana_keygen
  solana_keygen="$(resolve_solana_keygen)"
  uploader="$("$solana_keygen" pubkey "$KEYPAIR")"

  echo "Verifying $PROGRAM_ID on $cluster against ${REPO_URL}@${commit} and uploading Otter Verify PDA..."
  solana-verify verify-from-repo \
    --url "$rpc_url" \
    --keypair "$KEYPAIR" \
    --program-id "$PROGRAM_ID" \
    --commit-hash "$commit" \
    --workspace-path "$PROGRAM_WORKSPACE_PATH" \
    --library-name "$PROGRAM_LIB_NAME" \
    --base-image "$VERIFY_BASE_IMAGE" \
    --arch "$SBF_ARCH" \
    --cargo-build-sbf-args="--tools-version ${TOOLS_VERSION}" \
    --skip-prompt \
    "$REPO_URL"

  if [[ "$cluster" == "mainnet" || "${AUDREN_SUBMIT_REMOTE:-0}" == "1" ]]; then
    echo "Submitting remote verification job to OtterSec API (uploader: $uploader)..."
    local attempt
    for attempt in 1 2 3; do
      if solana-verify --url "$rpc_url" remote submit-job \
        --program-id "$PROGRAM_ID" \
        --uploader "$uploader"; then
        return 0
      fi
      if [[ "$attempt" -lt 3 ]]; then
        echo "Waiting 5s for Otter Verify PDA RPC propagation before retry (${attempt}/3)..." >&2
        sleep 5
      fi
    done
    echo "Error: failed to submit remote verification job after 3 attempts" >&2
    exit 1
  fi
}

read_program_version() {
  python3 - "$ROOT/program/Cargo.toml" <<'PY'
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
assert m, "Could not read version from program/Cargo.toml"
print(m.group(1))
PY
}

publish_github_release() {
  local commit="$1"
  command -v gh >/dev/null 2>&1 || { echo "Error: GitHub CLI (gh) is required to cut a GitHub Release." >&2; exit 1; }
  require_solana_verify
  [[ -f "$VERIFIABLE_SO_PATH" ]] || { echo "Error: verifiable ELF not found at $VERIFIABLE_SO_PATH; run build-verifiable first." >&2; exit 1; }

  local version tag
  version="$(read_program_version)"
  tag="v${version}"

  # Poll OtterSec until remote attestation matches commit & local verifiable ELF hash
  local exec_hash raw_sha elf_bytes status_json poll_attempt max_polls
  exec_hash="$(solana-verify get-executable-hash "$VERIFIABLE_SO_PATH" | tail -n 1 | tr -d '[:space:]')"
  raw_sha="$(shasum -a 256 "$VERIFIABLE_SO_PATH" | awk '{print $1}')"
  elf_bytes="$(wc -c < "$VERIFIABLE_SO_PATH" | tr -d '[:space:]')"
  max_polls="${AUDREN_VERIFY_POLL_ATTEMPTS:-60}"
  for ((poll_attempt = 1; poll_attempt <= max_polls; poll_attempt++)); do
    status_json="$(curl -fsS "https://verify.osec.io/status/${PROGRAM_ID}" || echo '{}')"
    if python3 - "$status_json" "$commit" "$exec_hash" <<'PY'
import json, sys
try:
    data = json.loads(sys.argv[1])
except Exception:
    sys.exit(1)
commit, exec_hash = sys.argv[2], sys.argv[3]
ok = (
    bool(data.get("is_verified"))
    and data.get("commit") == commit
    and data.get("on_chain_hash") == exec_hash
    and data.get("executable_hash") == exec_hash
)
sys.exit(0 if ok else 1)
PY
    then
      echo "OtterSec remote attestation confirmed for commit ${commit} (${exec_hash})."
      break
    fi
    if [[ "$poll_attempt" -eq "$max_polls" ]]; then
      echo "Error: verify.osec.io did not finish attesting commit ${commit} (${exec_hash}) within $((max_polls * 15))s." >&2
      echo "Latest response: ${status_json}" >&2
      echo "Once verified, cut the release with: ./scripts/upgrade-program.sh release --commit ${commit}" >&2
      exit 1
    fi
    echo "Waiting 15s for OtterSec remote build attestation (${poll_attempt}/${max_polls})..." >&2
    sleep 15
  done

  # Ensure annotated git tag points to the exact verified commit and is pushed to origin
  local existing_tag_sha=""
  if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null 2>&1; then
    existing_tag_sha="$(git rev-list -n 1 "$tag")"
    if [[ "$existing_tag_sha" != "$commit" ]]; then
      echo "Error: local tag ${tag} points to ${existing_tag_sha}, not verified commit ${commit}." >&2
      exit 1
    fi
  else
    git tag -a "$tag" "$commit" -m "Audren ${tag}"
  fi
  git push origin "refs/tags/${tag}"

  local tmp_dir sha_file notes_file
  tmp_dir="$(mktemp -d /tmp/audren-release-XXXXXX)"
  _AUDREN_CLEANUP_PATHS+=("$tmp_dir")
  sha_file="${tmp_dir}/audren.so.sha256"
  notes_file="${tmp_dir}/release-notes.md"

  cat >"$sha_file" <<EOF
${raw_sha}  audren.so
# solana-verify executable hash: ${exec_hash}
# elf_bytes: ${elf_bytes}
# commit: ${commit}
# program_id: ${PROGRAM_ID}
EOF

  local pk_path="$ROOT/crates/audren-circuits/params/audren_joinsplit.pk"
  local transcript_path="$ROOT/ceremony/transcript.json"
  local pk_sha
  pk_sha="$(shasum -a 256 "$pk_path" | awk '{print $1}')"
  local pk_bytes
  pk_bytes="$(wc -c < "$pk_path" | tr -d '[:space:]')"

  cat >"$notes_file" <<EOF
# Audren ${tag}

Deterministic, verifiable Solana \`sBPFv3\` release for **Audren** (\`${PROGRAM_ID}\`).

## On-Chain Trust & Verification

| Surface | Identifier / Link |
| :--- | :--- |
| **Program ID (Mainnet & Devnet)** | \`${PROGRAM_ID}\` |
| **Verified Source Commit** | \`${commit}\` |
| **On-Chain & Executable Hash** | \`${exec_hash}\` |
| **Deployed ELF Size / Raw SHA-256** | \`${elf_bytes} B\` · \`${raw_sha}\` |
| **Groth16 Ceremony Proving Key** | \`audren_joinsplit.pk\` (\`${pk_bytes} B\`) · SHA-256 \`${pk_sha}\` |
| **Mainnet Verified Build** | [Solana Explorer Verified Build](https://explorer.solana.com/address/${PROGRAM_ID}/verified-build) · [OtterSec Status](https://verify.osec.io/status/${PROGRAM_ID}) |
| **Canonical Program IDL (Codama 1.8.0)** | \`5QoLwK1C3NpUXjsHEV14RsQE65MaaiT9WxGvoTyxBPsn\` · [Solana Explorer IDL](https://explorer.solana.com/address/${PROGRAM_ID}/idl) |
| **Canonical Security Metadata** | \`GU7K3e7p8zUHoKQuQ1fidi9atxQc3UN1e3Q1Xomzs2Lj\` · [Solana Explorer Security](https://explorer.solana.com/address/${PROGRAM_ID}/security) |
| **Otter Verify PDA (Mainnet)** | \`FUQpuou8R4iDA5iMVTZiCB6X8uMdWdhSXxgo85Viv4Qt\` |

## Reproduce Independently

\`\`\`bash
solana-verify verify-from-repo -um \\
  --program-id ${PROGRAM_ID} \\
  --commit-hash ${commit} \\
  --workspace-path ${PROGRAM_WORKSPACE_PATH} \\
  --library-name ${PROGRAM_LIB_NAME} \\
  --base-image ${VERIFY_BASE_IMAGE} \\
  --arch ${SBF_ARCH} \\
  --cargo-build-sbf-args="--tools-version ${TOOLS_VERSION}" \\
  ${REPO_URL}
\`\`\`

## Attached Artifacts

- \`audren.so\` — deterministic \`sBPFv3\` binary (\`${elf_bytes} B\`, embedded \`.security.txt\`)
- \`audren.so.sha256\` — raw SHA-256 and \`solana-verify\` executable hash manifest
- \`audren_joinsplit.pk\` — compressed BN254 Groth16 ceremony proving key (\`${pk_bytes} B\`, Hermez Perpetual Powers of Tau (54 contributions + beacon) + Audren BGM17 Phase-2 ceremony)
- \`transcript.json\` — pairing-verifiable Groth16 ceremony transcript (Schnorr PoKs, G1/G2 deltas, live drand Quicknet & Solana Mainnet finalized beacon)
- \`audren.codama.json\` — canonical Codama v1.8.0 IDL
- \`audren.anchor.json\` — Anchor v0.30+ compatible IDL
- \`security.json\` — canonical Solana Program Metadata security manifest (\`security@audren.xyz\`)
EOF

  if gh release view "$tag" --repo "$REPO_OWNER_NAME" >/dev/null 2>&1; then
    local existing_rel_target=""
    existing_rel_target="$(gh api "repos/${REPO_OWNER_NAME}/releases/tags/${tag}" --jq '.target_commitish // ""' 2>/dev/null || true)"
    if [[ -n "$existing_rel_target" && "$existing_rel_target" != "$commit" && "${ALLOW_RELEASE_RETARGET:-0}" != "1" ]]; then
      echo "Error: GitHub Release ${tag} already targets ${existing_rel_target}, refusing to retarget to ${commit}. Cut a new patch version (or set ALLOW_RELEASE_RETARGET=1 explicitly)." >&2
      exit 1
    fi
    echo "Updating existing GitHub Release ${tag} on ${REPO_OWNER_NAME} (same commit ${commit})..."
    if gh release edit --help >/dev/null 2>&1; then
      gh release edit "$tag" \
        --repo "$REPO_OWNER_NAME" \
        --target "$commit" \
        --title "Audren ${tag}" \
        --notes-file "$notes_file"
    else
      local rel_id patch_json
      rel_id="$(gh api "repos/${REPO_OWNER_NAME}/releases/tags/${tag}" --jq '.id')"
      [[ "$rel_id" =~ ^[0-9]+$ ]] || {
        echo "Error: failed to resolve numeric GitHub release ID for ${tag} (got '${rel_id}')." >&2
        exit 1
      }
      patch_json="${tmp_dir}/release-patch.json"
      python3 - "$notes_file" "$tag" "$commit" "$patch_json" <<'PY'
import json, pathlib, sys
notes = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
payload = {"name": f"Audren {sys.argv[2]}", "body": notes, "target_commitish": sys.argv[3]}
pathlib.Path(sys.argv[4]).write_text(json.dumps(payload), encoding="utf-8")
PY
      gh api -X PATCH "repos/${REPO_OWNER_NAME}/releases/${rel_id}" --input "$patch_json" >/dev/null
    fi
    gh release upload "$tag" \
      --repo "$REPO_OWNER_NAME" \
      --clobber \
      "$VERIFIABLE_SO_PATH" \
      "$sha_file" \
      "$pk_path" \
      "$transcript_path" \
      "$IDL_PATH" \
      "$ROOT/idl/audren.anchor.json" \
      "$SECURITY_PATH"
  else
    echo "Creating GitHub Release ${tag} on ${REPO_OWNER_NAME}..."
    gh release create "$tag" \
      --repo "$REPO_OWNER_NAME" \
      --target "$commit" \
      --title "Audren ${tag}" \
      --notes-file "$notes_file" \
      "$VERIFIABLE_SO_PATH" \
      "$sha_file" \
      "$pk_path" \
      "$transcript_path" \
      "$IDL_PATH" \
      "$ROOT/idl/audren.anchor.json" \
      "$SECURITY_PATH"
  fi
}

check_compliance() {
  local cluster="$1"
  local rpc_url="$2"
  echo "1. Checking local IDL, SDK, Relayer, Web protocol.ts, docs, security.json, .security.txt, and toolchain parity..."
  python3 "$ROOT/idl/verify-idl.py"

  echo "2. Checking on-chain Program Metadata (${cluster})..."
  verify_onchain_metadata security "$rpc_url" "$SECURITY_PATH"
  verify_onchain_metadata idl "$rpc_url" "$IDL_PATH"

  if [[ "$cluster" == "mainnet" ]]; then
    local version tag
    version="$(read_program_version)"
    tag="v${version}"

    echo "3. Checking OtterSec Verified Build status & apps/web/lib/protocol.ts parity (https://verify.osec.io/status/${PROGRAM_ID})..."
    local status_json local_exec_hash
    status_json="$(curl -fsS "https://verify.osec.io/status/${PROGRAM_ID}")"
    local_exec_hash=""
    if [[ -f "$VERIFIABLE_SO_PATH" ]] && command -v solana-verify >/dev/null 2>&1; then
      local_exec_hash="$(solana-verify get-executable-hash "$VERIFIABLE_SO_PATH" | tail -n 1 | tr -d '[:space:]')"
    fi
    python3 - "$status_json" "$ROOT/apps/web/lib/protocol.ts" "$tag" "$VERIFIABLE_SO_PATH" "$local_exec_hash" <<'PY'
import hashlib, json, pathlib, re, sys
data = json.loads(sys.argv[1])
proto = pathlib.Path(sys.argv[2]).read_text()
expected_tag = sys.argv[3]
so_path = pathlib.Path(sys.argv[4])
local_exec_hash = sys.argv[5].strip()
print(json.dumps(data, indent=2))
if not data.get("is_verified"):
    sys.exit("Compliance check incomplete: Mainnet Verified Build is not yet verified (run build-verifiable + mainnet upgrade).")
exec_hash = re.search(r"\bexecutableHash:\s*'([0-9a-f]{64})'", proto).group(1)
verified_commit = re.search(r"\bverifiedCommit:\s*'([0-9a-f]{40})'", proto).group(1)
deployed_tag_m = re.search(r"\bdeployedReleaseTag:\s*'([^']+)'", proto)
if not deployed_tag_m or deployed_tag_m.group(1) != expected_tag:
    sys.exit(
        f"Drift detected: apps/web/lib/protocol.ts deployedReleaseTag "
        f"({deployed_tag_m.group(1) if deployed_tag_m else None}) != {expected_tag}"
    )
deployed_url_m = re.search(r"\bdeployedReleaseUrl:\s*'([^']+)'", proto)
if not deployed_url_m or not deployed_url_m.group(1).endswith(f"/releases/tag/{expected_tag}"):
    sys.exit(
        f"Drift detected: apps/web/lib/protocol.ts deployedReleaseUrl "
        f"({deployed_url_m.group(1) if deployed_url_m else None}) does not end with /releases/tag/{expected_tag}"
    )
elf_sha_m = re.search(r"\belfSha256:\s*'([0-9a-f]{64})'", proto)
if not elf_sha_m:
    sys.exit("Drift detected: apps/web/lib/protocol.ts missing elfSha256")
elf_sha = elf_sha_m.group(1)
elf_bytes_m = re.search(r"\belfBytes:\s*([0-9_]+)", proto)
if not elf_bytes_m:
    sys.exit("Drift detected: apps/web/lib/protocol.ts missing elfBytes")
proto_elf_bytes = int(elf_bytes_m.group(1).replace("_", ""))

if data.get("on_chain_hash") != exec_hash or data.get("executable_hash") != exec_hash:
    sys.exit(f"Drift detected: apps/web/lib/protocol.ts executableHash ({exec_hash}) != Mainnet verified hash ({data.get('on_chain_hash')})")
if data.get("commit") != verified_commit:
    sys.exit(f"Drift detected: apps/web/lib/protocol.ts verifiedCommit ({verified_commit}) != Mainnet verified commit ({data.get('commit')})")

if so_path.is_file():
    if local_exec_hash and local_exec_hash != data.get("on_chain_hash"):
        sys.exit(
            f"Drift detected: local verifiable ELF {so_path} executable hash ({local_exec_hash}) "
            f"!= live Mainnet on_chain_hash ({data.get('on_chain_hash')}); rebuild with ./scripts/upgrade-program.sh build-verifiable."
        )
    elf_raw = so_path.read_bytes()
    actual_elf_sha = hashlib.sha256(elf_raw).hexdigest()
    if elf_sha != actual_elf_sha:
        sys.exit(
            f"Drift detected: apps/web/lib/protocol.ts elfSha256 ({elf_sha}) != deployed binary SHA-256 ({actual_elf_sha})"
        )
    if proto_elf_bytes != len(elf_raw):
        sys.exit(
            f"Drift detected: apps/web/lib/protocol.ts elfBytes ({proto_elf_bytes}) != deployed binary size ({len(elf_raw)} B)"
        )
    print(f"Verified apps/web/lib/protocol.ts matches live Mainnet verified build ({expected_tag}, commit, executableHash, elfSha256 & {len(elf_raw)} B ELF).")
else:
    print(f"Verified apps/web/lib/protocol.ts matches live Mainnet verified build ({expected_tag}, commit & executableHash; verifying elfSha256 via release manifest in step 4).")
PY

    echo "4. Checking GitHub Release ${tag} (${REPO_URL}/releases/tag/${tag})..."
    local release_json
    release_json="$(curl -fsS "https://api.github.com/repos/${REPO_OWNER_NAME}/releases/tags/${tag}")"
    local sha_asset_url sha_manifest
    sha_asset_url="$(python3 - "$release_json" "$tag" <<'PY'
import json, sys
rel = json.loads(sys.argv[1])
tag = sys.argv[2]
assert rel.get("tag_name") == tag, f"Release tag mismatch: {rel.get('tag_name')} != {tag}"
assets = {a["name"]: a.get("browser_download_url", "") for a in rel.get("assets", [])}
required = {
    "audren.so",
    "audren.so.sha256",
    "audren_joinsplit.pk",
    "transcript.json",
    "audren.codama.json",
    "audren.anchor.json",
    "security.json",
}
missing = required - set(assets.keys())
if missing:
    sys.exit(f"GitHub Release {tag} missing required assets: {sorted(missing)}")
print(assets["audren.so.sha256"])
PY
)"
    sha_manifest="$(curl -fsSL "$sha_asset_url")"
    python3 - "$sha_manifest" "$status_json" "$ROOT/apps/web/lib/protocol.ts" "$tag" <<'PY'
import json, pathlib, re, sys
manifest, status_raw, proto_path, tag = sys.argv[1:]
data = json.loads(status_raw)
proto = pathlib.Path(proto_path).read_text()
proto_elf_sha = re.search(r"\belfSha256:\s*'([0-9a-f]{64})'", proto).group(1)
proto_elf_bytes = int(re.search(r"\belfBytes:\s*([0-9_]+)", proto).group(1).replace("_", ""))

raw_m = re.search(r"(?m)^([0-9a-f]{64})\s+audren\.so\s*$", manifest)
exec_m = re.search(r"(?m)^#\s*solana-verify executable hash:\s*([0-9a-f]{64})\s*$", manifest)
bytes_m = re.search(r"(?m)^#\s*elf_bytes:\s*(\d+)\s*$", manifest)
if not raw_m or not exec_m:
    sys.exit(f"Drift detected: GitHub Release {tag} audren.so.sha256 manifest is malformed:\n{manifest}")
if exec_m.group(1) != data.get("on_chain_hash"):
    sys.exit(
        f"Drift detected: GitHub Release {tag} executable hash ({exec_m.group(1)}) != live Mainnet on_chain_hash ({data.get('on_chain_hash')})"
    )
if raw_m.group(1) != proto_elf_sha:
    sys.exit(
        f"Drift detected: apps/web/lib/protocol.ts elfSha256 ({proto_elf_sha}) != GitHub Release {tag} audren.so SHA-256 ({raw_m.group(1)})"
    )
if bytes_m and int(bytes_m.group(1)) != proto_elf_bytes:
    sys.exit(
        f"Drift detected: apps/web/lib/protocol.ts elfBytes ({proto_elf_bytes}) != GitHub Release {tag} elf_bytes ({bytes_m.group(1)})"
    )
print(f"Verified GitHub Release {tag} with all 7 release assets and exact elfSha256/on_chain_hash parity ({raw_m.group(1)[:16]}...).")
PY

    echo "5. Checking GitHub org & repository metadata (${REPO_URL})..."
    local repo_json org_json
    repo_json="$(curl -fsS "https://api.github.com/repos/${REPO_OWNER_NAME}")"
    org_json="$(curl -fsS "https://api.github.com/orgs/${REPO_OWNER_NAME%%/*}")"
    python3 - "$repo_json" "$org_json" <<'PY'
import json, sys
repo = json.loads(sys.argv[1])
org = json.loads(sys.argv[2])
assert repo.get("homepage") == "https://audren.xyz", f"Repo homepage mismatch: {repo.get('homepage')}"
assert repo.get("description"), "Repo description is empty"
assert (repo.get("license") or {}).get("spdx_id") == "Apache-2.0", f"Repo SPDX license mismatch: {repo.get('license')}"
assert len(repo.get("topics") or []) >= 6, f"Repo topics too sparse: {repo.get('topics')}"
assert org.get("name") == "Audren", f"Org display name mismatch: {org.get('name')}"
assert org.get("blog") == "https://audren.xyz", f"Org blog mismatch: {org.get('blog')}"
assert org.get("description"), "Org description is empty"
print(f"Verified GitHub org '{org['name']}' & repo '{repo['full_name']}' (Apache-2.0, {len(repo['topics'])} topics, homepage https://audren.xyz).")
PY
  fi
}

[[ $# -ge 1 ]] || usage

case "$1" in
  build-verifiable)
    [[ $# -eq 1 ]] || usage
    build_verifiable
    exit 0
    ;;
  idl|security|metadata)
    [[ $# -eq 2 ]] || usage
    CLUSTER="$2"
    RPC_URL="$(resolve_rpc "$CLUSTER")"
    require_keypair
    python3 "$ROOT/idl/verify-idl.py"
    if [[ "$1" == "security" || "$1" == "metadata" ]]; then
      publish_security "$CLUSTER" "$RPC_URL"
    fi
    if [[ "$1" == "idl" || "$1" == "metadata" ]]; then
      publish_idl "$CLUSTER" "$RPC_URL"
    fi
    exit 0
    ;;
  verify)
    [[ $# -ge 2 ]] || usage
    CLUSTER="$2"
    shift 2
    COMMIT_ARG=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --commit)
          [[ $# -ge 2 ]] || usage
          COMMIT_ARG="$2"
          shift 2
          ;;
        *)
          usage
          ;;
      esac
    done
    RPC_URL="$(resolve_rpc "$CLUSTER")"
    python3 "$ROOT/idl/verify-idl.py"
    COMMIT_SHA="$(resolve_verified_commit "$COMMIT_ARG")"
    verify_onchain_build "$CLUSTER" "$RPC_URL" "$COMMIT_SHA"
    exit 0
    ;;
  release)
    shift
    COMMIT_ARG=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --commit)
          [[ $# -ge 2 ]] || usage
          COMMIT_ARG="$2"
          shift 2
          ;;
        *)
          usage
          ;;
      esac
    done
    python3 "$ROOT/idl/verify-idl.py"
    if [[ -z "$COMMIT_ARG" ]]; then
      COMMIT_ARG="$(curl -fsS "https://verify.osec.io/status/${PROGRAM_ID}" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("commit",""))')"
    fi
    REQUIRE_CLEAN_HEAD=1
    if [[ "${ALLOW_CROSS_COMMIT_RELEASE:-0}" == "1" ]]; then
      REQUIRE_CLEAN_HEAD=0
    fi
    COMMIT_SHA="$(resolve_verified_commit "$COMMIT_ARG" "$REQUIRE_CLEAN_HEAD")"
    publish_github_release "$COMMIT_SHA"
    exit 0
    ;;
  check)
    [[ $# -eq 2 ]] || usage
    CLUSTER="$2"
    RPC_URL="$(resolve_rpc "$CLUSTER")"
    check_compliance "$CLUSTER" "$RPC_URL"
    exit 0
    ;;
  devnet|mainnet)
    CLUSTER="$1"
    shift
    COMMIT_ARG=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --commit)
          [[ $# -ge 2 ]] || usage
          COMMIT_ARG="$2"
          shift 2
          ;;
        *)
          usage
          ;;
      esac
    done
    RPC_URL="$(resolve_rpc "$CLUSTER")"
    require_keypair

    echo "Pre-flight: verifying local IDLs, security metadata, and toolchain pins..."
    python3 "$ROOT/idl/verify-idl.py"

    EXPECTED_VERSION="$(read_program_version)"

    if [[ -n "${AUDREN_SO_PATH:-}" ]]; then
      SO_PATH="$AUDREN_SO_PATH"
    elif [[ "$CLUSTER" == "mainnet" ]]; then
      SO_PATH="$VERIFIABLE_SO_PATH"
    else
      DEVNET_VERIFIABLE_FRESH=0
      if [[ -f "$VERIFIABLE_SO_PATH" ]] \
        && git -C "$ROOT" diff --quiet HEAD -- program crates/audren-core \
        && git -C "$ROOT" diff --cached --quiet HEAD -- program crates/audren-core \
        && [[ -z "$(git -C "$ROOT" ls-files --others --exclude-standard -- program crates/audren-core)" ]] \
        && ( verify_verifiable_elf_freshness "$VERIFIABLE_SO_PATH" "$(git -C "$ROOT" rev-parse HEAD)" "$EXPECTED_VERSION" ) >/dev/null 2>&1; then
        DEVNET_VERIFIABLE_FRESH=1
      fi
      if [[ "$DEVNET_VERIFIABLE_FRESH" == "1" ]] && [[ ! -f "$LOCAL_SO_PATH" || "$VERIFIABLE_SO_PATH" -nt "$LOCAL_SO_PATH" ]]; then
        SO_PATH="$VERIFIABLE_SO_PATH"
      elif [[ -f "$LOCAL_SO_PATH" ]]; then
        SO_PATH="$LOCAL_SO_PATH"
      elif [[ -f "$VERIFIABLE_SO_PATH" ]]; then
        echo "Error: verifiable ELF at $VERIFIABLE_SO_PATH is stale for current program/crates/audren-core and local ELF $LOCAL_SO_PATH is absent." >&2
        echo "Rebuild via: ./scripts/upgrade-program.sh build-verifiable  (or python3 scripts/build-sbf.py --manifest-path program/Cargo.toml --sbf-out-dir target/deploy)" >&2
        exit 1
      else
        SO_PATH="$LOCAL_SO_PATH"
      fi
    fi

    if [[ ! -f "$SO_PATH" ]]; then
      if [[ "$CLUSTER" == "mainnet" ]]; then
        echo "Error: deterministic verifiable ELF not found at $SO_PATH." >&2
        echo "Run: ./scripts/upgrade-program.sh build-verifiable" >&2
      else
        echo "Error: sBPFv3 ELF not found at $SO_PATH." >&2
        echo "Run: ./scripts/upgrade-program.sh build-verifiable  (or python3 scripts/build-sbf.py --manifest-path program/Cargo.toml --sbf-out-dir target/deploy)" >&2
      fi
      exit 1
    fi

    echo "Pre-flight: verifying sBPFv3 ELF header & embedded .security.txt version ($SO_PATH)..."
    if [[ "$SO_PATH" == "$LOCAL_SO_PATH" && -f "${LOCAL_SO_PATH%.so}.build.json" ]]; then
      python3 "$ROOT/scripts/build-sbf.py" --check "$SO_PATH"
    else
      python3 "$ROOT/scripts/build-sbf.py" --check-elf "$SO_PATH"
    fi
    python3 - "$SO_PATH" "$EXPECTED_VERSION" <<'PY'
import pathlib, sys
elf = pathlib.Path(sys.argv[1]).read_bytes()
needle = f"source_release\0v{sys.argv[2]}\0".encode("utf-8")
if needle not in elf:
    sys.exit(f"Error: ELF {sys.argv[1]} does not contain embedded .security.txt source_release v{sys.argv[2]} (rebuild with ./scripts/upgrade-program.sh build-verifiable).")
PY

    COMMIT_SHA=""
    if [[ "$CLUSTER" == "mainnet" && "${ALLOW_UNVERIFIED_DEPLOY:-0}" != "1" ]]; then
      if [[ "$SO_PATH" != "$VERIFIABLE_SO_PATH" ]]; then
        echo "Error: Mainnet upgrades require the Docker verifiable ELF at $VERIFIABLE_SO_PATH (set ALLOW_UNVERIFIED_DEPLOY=1 only for emergency overrides)." >&2
        exit 1
      fi
      require_solana_verify
      COMMIT_SHA="$(resolve_verified_commit "$COMMIT_ARG" 1)"
      verify_verifiable_elf_freshness "$SO_PATH" "$COMMIT_SHA" "$EXPECTED_VERSION"
    fi

    if [[ "${SKIP_INIT_ROOT_HISTORY:-0}" != "1" ]]; then
      command -v node >/dev/null 2>&1 || {
        echo "Error: node is required for immediate post-deploy Pool #0 InitRootHistory migration (or set SKIP_INIT_ROOT_HISTORY=1)." >&2
        exit 1
      }
      echo "Pre-flight: verifying @audren/sdk ESM dist & runtime imports for Step [1c] InitRootHistory..."
      if ! (
        cd "$ROOT" && node --input-type=module <<'JS'
import {
  buildInitRootHistoryInstruction,
  decodeGlobalRootHistory,
  deriveRootsPdaSync,
  CU_LIMIT_INIT_ROOT_HISTORY,
  DEFAULT_ROOT_EPOCH_INTERVAL,
  ROOT_RING_EPOCH,
  ROOT_RING_SLOT,
  fetchGlobalRootHistory,
  selectRootSnapshotForNotes,
  planAutoOpenPages,
  buildAutoOpenPageInstructions,
} from './packages/sdk/dist/index.js';
import {
  AudrenWasmProver,
  dummyInputWitness,
  dummyOutputWitness,
} from './packages/sdk/dist/prover-entry.js';
import { ed25519 } from './packages/sdk/node_modules/@noble/curves/ed25519.js';

if (
  typeof buildInitRootHistoryInstruction !== 'function' ||
  typeof decodeGlobalRootHistory !== 'function' ||
  typeof deriveRootsPdaSync !== 'function' ||
  typeof CU_LIMIT_INIT_ROOT_HISTORY !== 'number' ||
  typeof DEFAULT_ROOT_EPOCH_INTERVAL !== 'bigint' ||
  typeof ROOT_RING_EPOCH !== 'number' ||
  typeof ROOT_RING_SLOT !== 'number' ||
  typeof fetchGlobalRootHistory !== 'function' ||
  typeof selectRootSnapshotForNotes !== 'function' ||
  typeof planAutoOpenPages !== 'function' ||
  typeof buildAutoOpenPageInstructions !== 'function' ||
  typeof AudrenWasmProver !== 'function' ||
  typeof dummyInputWitness !== 'function' ||
  typeof dummyOutputWitness !== 'function' ||
  typeof ed25519?.getPublicKey !== 'function'
) {
  throw new Error('Stale or incomplete @audren/sdk ESM exports for InitRootHistory.');
}
JS
      ); then
        echo "Error: @audren/sdk ESM dist or runtime dependencies are missing/stale for post-deploy Pool #0 InitRootHistory migration." >&2
        echo "Run: pnpm --dir packages/sdk build  (and pnpm --dir packages/sdk install if @noble/curves is missing, or set SKIP_INIT_ROOT_HISTORY=1)." >&2
        exit 1
      fi
    fi

    SOLANA_BIN="$(resolve_solana_cli)"
    SOLANA_KEYGEN_BIN="$(resolve_solana_keygen)"
    TOTAL_STEPS=3
    if [[ "$CLUSTER" == "mainnet" ]]; then
      TOTAL_STEPS=4
    fi
    PRIORITY_FEE="${SOLANA_PRIORITY_FEE_MICROLAMPORTS:-50000}"
    USE_TWO_STEP="${SOLANA_DEPLOY_TWO_STEP:-$([[ "$CLUSTER" == "mainnet" ]] && echo 1 || echo 0)}"
    echo "Step 1/${TOTAL_STEPS}: Upgrading $PROGRAM_ID on $CLUSTER (using $SOLANA_BIN, priority fee ${PRIORITY_FEE} micro-lamports, RPC mode)..."
    if [[ "$USE_TWO_STEP" == "1" ]]; then
      BUF_KEYPAIR="$(mktemp /tmp/audren-buffer-XXXXXX)"
      "$SOLANA_KEYGEN_BIN" new --no-bip39-passphrase --silent --force -o "$BUF_KEYPAIR" >/dev/null
      BUF_PUBKEY="$("$SOLANA_KEYGEN_BIN" pubkey "$BUF_KEYPAIR")"
      echo "  [1a] Writing sBPFv3 ELF to buffer $BUF_PUBKEY via --use-rpc (--commitment confirmed)..."
      BUF_OK=0
      for attempt in 1 2 3; do
        if "$SOLANA_BIN" program write-buffer "$SO_PATH" \
          --buffer "$BUF_KEYPAIR" \
          --buffer-authority "$KEYPAIR" \
          --keypair "$KEYPAIR" \
          --use-rpc \
          --commitment confirmed \
          --max-sign-attempts 10 \
          --with-compute-unit-price "$PRIORITY_FEE" \
          --url "$RPC_URL"; then
          BUF_OK=1
          break
        fi
        echo "  write-buffer attempt ${attempt} hit transient RPC lag; retrying same buffer in 4s..." >&2
        sleep 4
      done
      if [[ "$BUF_OK" != "1" ]]; then
        echo "Error: write-buffer failed after 3 attempts. Buffer keypair preserved at $BUF_KEYPAIR (pubkey: $BUF_PUBKEY)." >&2
        echo "Reclaim rent via: solana program close \"$BUF_PUBKEY\" --authority \"\$AUDREN_KEYPAIR_PATH\" --keypair \"\$AUDREN_KEYPAIR_PATH\" --url \"\$MAINNET_RPC_URL\"" >&2
        exit 1
      fi
      sleep 3
      echo "  [1b] Deploying verified buffer $BUF_PUBKEY to $PROGRAM_ID via --use-rpc..."
      if ! "$SOLANA_BIN" program deploy \
        --buffer "$BUF_PUBKEY" \
        --program-id "$PROGRAM_ID" \
        --upgrade-authority "$KEYPAIR" \
        --keypair "$KEYPAIR" \
        --use-rpc \
        --commitment confirmed \
        --max-sign-attempts 10 \
        --with-compute-unit-price "$PRIORITY_FEE" \
        --url "$RPC_URL"; then
        echo "Error: deploy from buffer $BUF_PUBKEY failed. Buffer keypair preserved at $BUF_KEYPAIR." >&2
        echo "Reclaim rent via: solana program close \"$BUF_PUBKEY\" --authority \"\$AUDREN_KEYPAIR_PATH\" --keypair \"\$AUDREN_KEYPAIR_PATH\" --url \"\$MAINNET_RPC_URL\"" >&2
        exit 1
      fi
      rm -f "$BUF_KEYPAIR"
    else
      "$SOLANA_BIN" program deploy "$SO_PATH" \
        --program-id "$PROGRAM_ID" \
        --upgrade-authority "$KEYPAIR" \
        --keypair "$KEYPAIR" \
        --use-rpc \
        --commitment confirmed \
        --max-sign-attempts 10 \
        --with-compute-unit-price "$PRIORITY_FEE" \
        --url "$RPC_URL"
    fi

    if [[ "${SKIP_INIT_ROOT_HISTORY:-0}" != "1" ]]; then
      echo "  [1c] Immediately ensuring Pool #0 GlobalRootHistory PDA is initialized on $CLUSTER (idempotent Tag 4 InitRootHistory)..."
      INIT_RT_OK=0
      for attempt in 1 2 3; do
        if AUDREN_KEYPAIR_PATH="$KEYPAIR" \
          AUDREN_PROGRAM_ID="$PROGRAM_ID" \
          MAINNET_RPC_URL="$RPC_URL" \
          DEVNET_RPC_URL="$RPC_URL" \
          node "$ROOT/scripts/live-cluster-e2e.mjs" --cluster "$CLUSTER" --init-root-history; then
          INIT_RT_OK=1
          break
        fi
        if [[ "$attempt" -lt 3 ]]; then
          echo "  InitRootHistory attempt ${attempt}/3 hit transient RPC propagation lag after deploy; retrying in 2s..." >&2
          sleep 2
        fi
      done
      if [[ "$INIT_RT_OK" != "1" ]]; then
        echo "Error: automatic post-deploy Pool #0 InitRootHistory failed on $CLUSTER after 3 attempts." >&2
        echo "Run immediately: AUDREN_PROGRAM_ID=$PROGRAM_ID node scripts/live-cluster-e2e.mjs --cluster $CLUSTER --init-root-history" >&2
        exit 1
      fi
    else
      echo "  [1c] Skipping automatic Pool #0 InitRootHistory (SKIP_INIT_ROOT_HISTORY=1)."
    fi

    echo "Step 2/${TOTAL_STEPS}: Syncing canonical Program Metadata (security + idl) on $CLUSTER..."
    publish_security "$CLUSTER" "$RPC_URL"
    publish_idl "$CLUSTER" "$RPC_URL"

    if [[ "$CLUSTER" == "mainnet" && "${ALLOW_UNVERIFIED_DEPLOY:-0}" != "1" ]]; then
      echo "Step 3/${TOTAL_STEPS}: Updating Verified Build PDA & triggering remote attestation on Mainnet..."
      verify_onchain_build "$CLUSTER" "$RPC_URL" "$COMMIT_SHA"
      echo "Step 4/${TOTAL_STEPS}: Tagging & publishing GitHub Release..."
      publish_github_release "$COMMIT_SHA"
      echo ""
      echo "Next: update apps/web/lib/protocol.ts + docs/DEPLOYMENTS.md with the v${EXPECTED_VERSION} commit & ELF SHA-256,"
      echo "run 'python3 idl/verify-idl.py', deploy apps/web, and then run './scripts/upgrade-program.sh check mainnet'."
    elif [[ "$CLUSTER" == "mainnet" ]]; then
      echo "WARNING: ALLOW_UNVERIFIED_DEPLOY=1 skipped Verified Build attestation and GitHub Release. Run './scripts/upgrade-program.sh verify mainnet --commit <sha>' and './scripts/upgrade-program.sh release --commit <sha>' to restore compliance." >&2
    else
      echo "Step 3/${TOTAL_STEPS}: Devnet upgrade + Program Metadata sync complete."
    fi
    exit 0
    ;;
  *)
    usage
    ;;
esac
