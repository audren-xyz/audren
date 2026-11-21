#!/usr/bin/env bash
set -euo pipefail

# Audren release, upgrade, Program Metadata, and Verified Build operator script.
#
# Every program upgrade automatically enforces release compliance:
#   1. Local drift verification (`idl/verify-idl.py`: IDLs, @audren/sdk, security.json,
#      embedded .security.txt, Cargo.toml versions, and pinned Agave/sBPFv3 toolchain).
#   2. sBPFv3 ELF64 header verification (`scripts/build-sbf.py --check-elf`).
#   3. Program deployment (`solana program deploy`).
#   4. Automatic Solana Program Metadata sync (`security` + `idl`) with round-trip verification.
#   5. On Mainnet: automatic Solana Verified Build attestation (Otter Verify PDA update +
#      remote job submission to `verify.osec.io`), requiring a clean pushed commit and a
#      deterministic Docker build (`build-verifiable`) unless `ALLOW_UNVERIFIED_DEPLOY=1`.
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
#   ./scripts/upgrade-program.sh check <devnet|mainnet>

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -f "$ROOT/.credentials/operator.env" ]]; then
  # shellcheck disable=SC1091
  source "$ROOT/.credentials/operator.env"
fi

# Pinned build & verification parameters (cross-checked by `idl/verify-idl.py`).
AGAVE_VERSION="4.3.0"
TOOLS_VERSION="v1.57"
SBF_ARCH="v3"
VERIFY_BASE_IMAGE="solanafoundation/solana-verifiable-build@sha256:12fd4c0a0790f0fc41ef74b0cdb6bccc167ba6137eb1adb749bac649481c86bd"
REPO_OWNER_NAME="audren-xyz/audren"
REPO_URL="https://github.com/${REPO_OWNER_NAME}"
PROGRAM_LIB_NAME="audren"
PROGRAM_WORKSPACE_PATH="program"

PROGRAM_ID="${AUDREN_PROGRAM_ID:-AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3}"
KEYPAIR="${AUDREN_KEYPAIR_PATH:-$ROOT/.credentials/funder.json}"
VERIFIABLE_SO_PATH="$ROOT/program/target/deploy/audren.so"
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
  local fetched
  fetched="$(mktemp "/tmp/audren-fetch-${seed}-XXXXXX.txt")"
  if ! npx --yes @solana-program/program-metadata@latest fetch "$seed" \
    "$PROGRAM_ID" \
    --rpc "$rpc_url" >"$fetched"; then
    rm -f "$fetched"
    echo "Error: failed to fetch on-chain Program Metadata '${seed}' for $PROGRAM_ID" >&2
    exit 1
  fi
  if ! python3 - "$expected_path" "$fetched" "$seed" <<'PY'
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
    rm -f "$fetched"
    exit 1
  fi
  rm -f "$fetched"
}

publish_security() {
  local cluster="$1"
  local rpc_url="$2"
  echo "Publishing canonical security metadata ($SECURITY_PATH) for $PROGRAM_ID on $cluster..."
  npx --yes @solana-program/program-metadata@latest write security \
    "$PROGRAM_ID" \
    "$SECURITY_PATH" \
    --format json \
    --keypair "$KEYPAIR" \
    --rpc "$rpc_url"
  verify_onchain_metadata security "$rpc_url" "$SECURITY_PATH"
}

publish_idl() {
  local cluster="$1"
  local rpc_url="$2"
  local min_idl
  min_idl="$(mktemp /tmp/audren-idl-XXXXXX.json)"
  python3 -c "import json, pathlib, sys; pathlib.Path(sys.argv[2]).write_text(json.dumps(json.loads(pathlib.Path(sys.argv[1]).read_text()), separators=(',',':')))" "$IDL_PATH" "$min_idl"

  echo "Publishing canonical Codama IDL ($IDL_PATH) for $PROGRAM_ID on $cluster..."
  if ! npx --yes @solana-program/program-metadata@latest write idl \
    "$PROGRAM_ID" \
    "$min_idl" \
    --format json \
    --keypair "$KEYPAIR" \
    --rpc "$rpc_url"; then
    rm -f "$min_idl"
    echo "Direct multi-tx upload hit RPC propagation lag; checking for pre-created buffer..." >&2
    npx --yes @solana-program/program-metadata@latest list-buffers \
      --keypair "$KEYPAIR" \
      --rpc "$rpc_url" >&2 || true
    exit 1
  fi
  rm -f "$min_idl"
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

  echo "Building deterministic sBPFv3 binary (Agave ${AGAVE_VERSION}, tools ${TOOLS_VERSION}, arch ${SBF_ARCH})..."
  solana-verify build \
    --workspace-path "$PROGRAM_WORKSPACE_PATH" \
    --library-name "$PROGRAM_LIB_NAME" \
    --base-image "$VERIFY_BASE_IMAGE" \
    --arch "$SBF_ARCH" \
    --cargo-build-sbf-args="--tools-version ${TOOLS_VERSION}"

  echo "Validating sBPFv3 ELF header..."
  python3 "$ROOT/scripts/build-sbf.py" --check-elf "$VERIFIABLE_SO_PATH"
  solana-verify get-executable-hash "$VERIFIABLE_SO_PATH"
}

verify_onchain_build() {
  local cluster="$1"
  local rpc_url="$2"
  local commit="$3"
  require_solana_verify
  require_keypair

  local uploader
  uploader="$(solana-keygen pubkey "$KEYPAIR")"

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

check_compliance() {
  local cluster="$1"
  local rpc_url="$2"
  echo "1. Checking local IDL, security.json, .security.txt, and toolchain parity..."
  python3 "$ROOT/idl/verify-idl.py"

  echo "2. Checking on-chain Program Metadata (${cluster})..."
  verify_onchain_metadata security "$rpc_url" "$SECURITY_PATH"
  verify_onchain_metadata idl "$rpc_url" "$IDL_PATH"

  if [[ "$cluster" == "mainnet" ]]; then
    echo "3. Checking OtterSec Verified Build status (https://verify.osec.io/status/${PROGRAM_ID})..."
    local status_json
    status_json="$(curl -fsS "https://verify.osec.io/status/${PROGRAM_ID}")"
    python3 - "$status_json" <<'PY'
import json, sys
data = json.loads(sys.argv[1])
print(json.dumps(data, indent=2))
if not data.get("is_verified"):
    sys.exit("Compliance check incomplete: Mainnet Verified Build is not yet verified (run build-verifiable + mainnet upgrade).")
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

    if [[ -n "${AUDREN_SO_PATH:-}" ]]; then
      SO_PATH="$AUDREN_SO_PATH"
    elif [[ "$CLUSTER" == "mainnet" ]]; then
      SO_PATH="$VERIFIABLE_SO_PATH"
    elif [[ -f "$VERIFIABLE_SO_PATH" ]]; then
      SO_PATH="$VERIFIABLE_SO_PATH"
    else
      SO_PATH="$LOCAL_SO_PATH"
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

    echo "Pre-flight: verifying sBPFv3 ELF header ($SO_PATH)..."
    python3 "$ROOT/scripts/build-sbf.py" --check-elf "$SO_PATH"

    COMMIT_SHA=""
    if [[ "$CLUSTER" == "mainnet" && "${ALLOW_UNVERIFIED_DEPLOY:-0}" != "1" ]]; then
      if [[ "$SO_PATH" != "$VERIFIABLE_SO_PATH" ]]; then
        echo "Error: Mainnet upgrades require the Docker verifiable ELF at $VERIFIABLE_SO_PATH (set ALLOW_UNVERIFIED_DEPLOY=1 only for emergency overrides)." >&2
        exit 1
      fi
      require_solana_verify
      COMMIT_SHA="$(resolve_verified_commit "$COMMIT_ARG" 1)"
    fi

    echo "Step 1/3: Upgrading $PROGRAM_ID on $CLUSTER..."
    solana program deploy "$SO_PATH" \
      --program-id "$PROGRAM_ID" \
      --upgrade-authority "$KEYPAIR" \
      --keypair "$KEYPAIR" \
      --url "$RPC_URL"

    echo "Step 2/3: Syncing canonical Program Metadata (security + idl) on $CLUSTER..."
    publish_security "$CLUSTER" "$RPC_URL"
    publish_idl "$CLUSTER" "$RPC_URL"

    if [[ "$CLUSTER" == "mainnet" && "${ALLOW_UNVERIFIED_DEPLOY:-0}" != "1" ]]; then
      echo "Step 3/3: Updating Verified Build PDA & triggering remote attestation on Mainnet..."
      verify_onchain_build "$CLUSTER" "$RPC_URL" "$COMMIT_SHA"
    elif [[ "$CLUSTER" == "mainnet" ]]; then
      echo "WARNING: ALLOW_UNVERIFIED_DEPLOY=1 skipped Verified Build attestation. Run './scripts/upgrade-program.sh verify mainnet --commit <sha>' to restore verification." >&2
    else
      echo "Step 3/3: Devnet upgrade + Program Metadata sync complete."
    fi
    exit 0
    ;;
  *)
    usage
    ;;
esac
