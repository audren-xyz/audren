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
#      remote job submission to `verify.osec.io`) AND automatic GitHub tag + Release cutting
#      (`v<version>` with verified ELF, SHA-256, IDLs, and security.json), requiring a clean
#      pushed commit and deterministic Docker build (`build-verifiable`) unless
#      `ALLOW_UNVERIFIED_DEPLOY=1`.
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

list_metadata_buffers() {
  local rpc_url="$1"
  npx --yes @solana-program/program-metadata@latest list-buffers \
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
  local min_idl
  min_idl="$(mktemp /tmp/audren-idl-XXXXXX.json)"
  python3 -c "import json, pathlib, sys; pathlib.Path(sys.argv[2]).write_text(json.dumps(json.loads(pathlib.Path(sys.argv[1]).read_text()), separators=(',',':')))" "$IDL_PATH" "$min_idl"

  local authority
  authority="$(solana-keygen pubkey "$KEYPAIR")"
  local before_buffers
  before_buffers="$(list_metadata_buffers "$rpc_url")"

  echo "Publishing canonical Codama IDL ($IDL_PATH) for $PROGRAM_ID on $cluster..."
  if ! npx --yes @solana-program/program-metadata@latest write idl \
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
      rm -f "$min_idl"
      echo "Error: direct IDL upload failed and no new buffer account was found." >&2
      exit 1
    fi
    echo "Populating buffer $new_buffer and finalizing canonical IDL..." >&2
    if ! npx --yes @solana-program/program-metadata@latest update-buffer \
      "$new_buffer" \
      "$min_idl" \
      --format json \
      --keypair "$KEYPAIR" \
      --rpc "$rpc_url"; then
      rm -f "$min_idl"
      exit 1
    fi
    if ! npx --yes @solana-program/program-metadata@latest write idl \
      "$PROGRAM_ID" \
      --buffer "$new_buffer" \
      --close-buffer \
      --keypair "$KEYPAIR" \
      --rpc "$rpc_url"; then
      rm -f "$min_idl"
      exit 1
    fi
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

  # Verify OtterSec reports verified status matching commit & local ELF hash
  local exec_hash raw_sha elf_bytes status_json
  exec_hash="$(solana-verify get-executable-hash "$VERIFIABLE_SO_PATH" | tail -n 1 | tr -d '[:space:]')"
  raw_sha="$(shasum -a 256 "$VERIFIABLE_SO_PATH" | awk '{print $1}')"
  elf_bytes="$(wc -c < "$VERIFIABLE_SO_PATH" | tr -d '[:space:]')"
  status_json="$(curl -fsS "https://verify.osec.io/status/${PROGRAM_ID}")"

  python3 - "$status_json" "$commit" "$exec_hash" <<'PY'
import json, sys
data = json.loads(sys.argv[1])
commit, exec_hash = sys.argv[2], sys.argv[3]
if not data.get("is_verified"):
    sys.exit("Error: Mainnet Verified Build is not yet verified on verify.osec.io")
if data.get("commit") != commit:
    sys.exit(f"Error: verify.osec.io commit {data.get('commit')} != release commit {commit}")
if data.get("on_chain_hash") != exec_hash or data.get("executable_hash") != exec_hash:
    sys.exit(f"Error: verify.osec.io hash mismatch vs local verifiable ELF {exec_hash}")
PY

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
  trap 'rm -rf "$tmp_dir"' RETURN
  sha_file="${tmp_dir}/audren.so.sha256"
  notes_file="${tmp_dir}/release-notes.md"

  cat >"$sha_file" <<EOF
${raw_sha}  audren.so
# solana-verify executable hash: ${exec_hash}
# elf_bytes: ${elf_bytes}
# commit: ${commit}
# program_id: ${PROGRAM_ID}
EOF

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
- \`audren.codama.json\` — canonical Codama v1.8.0 IDL
- \`audren.anchor.json\` — Anchor v0.30+ compatible IDL
- \`security.json\` — canonical Solana Program Metadata security manifest (\`security@audren.xyz\`)
EOF

  if gh release view "$tag" --repo "$REPO_OWNER_NAME" >/dev/null 2>&1; then
    echo "Updating existing GitHub Release ${tag} on ${REPO_OWNER_NAME}..."
    gh release edit "$tag" \
      --repo "$REPO_OWNER_NAME" \
      --title "Audren ${tag}" \
      --notes-file "$notes_file"
    gh release upload "$tag" \
      --repo "$REPO_OWNER_NAME" \
      --clobber \
      "$VERIFIABLE_SO_PATH" \
      "$sha_file" \
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
    echo "3. Checking OtterSec Verified Build status & apps/web/lib/protocol.ts parity (https://verify.osec.io/status/${PROGRAM_ID})..."
    local status_json
    status_json="$(curl -fsS "https://verify.osec.io/status/${PROGRAM_ID}")"
    python3 - "$status_json" "$ROOT/apps/web/lib/protocol.ts" <<'PY'
import json, pathlib, re, sys
data = json.loads(sys.argv[1])
proto = pathlib.Path(sys.argv[2]).read_text()
print(json.dumps(data, indent=2))
if not data.get("is_verified"):
    sys.exit("Compliance check incomplete: Mainnet Verified Build is not yet verified (run build-verifiable + mainnet upgrade).")
exec_hash = re.search(r"\bexecutableHash:\s*'([0-9a-f]{64})'", proto).group(1)
verified_commit = re.search(r"\bverifiedCommit:\s*'([0-9a-f]{40})'", proto).group(1)
if data.get("on_chain_hash") != exec_hash or data.get("executable_hash") != exec_hash:
    sys.exit(f"Drift detected: apps/web/lib/protocol.ts executableHash ({exec_hash}) != Mainnet verified hash ({data.get('on_chain_hash')})")
if data.get("commit") != verified_commit:
    sys.exit(f"Drift detected: apps/web/lib/protocol.ts verifiedCommit ({verified_commit}) != Mainnet verified commit ({data.get('commit')})")
print("Verified apps/web/lib/protocol.ts matches live Mainnet verified build hash & commit.")
PY

    local version tag
    version="$(read_program_version)"
    tag="v${version}"
    echo "4. Checking GitHub Release ${tag} (${REPO_URL}/releases/tag/${tag})..."
    local release_json
    release_json="$(curl -fsS "https://api.github.com/repos/${REPO_OWNER_NAME}/releases/tags/${tag}")"
    python3 - "$release_json" "$tag" <<'PY'
import json, sys
rel = json.loads(sys.argv[1])
tag = sys.argv[2]
assert rel.get("tag_name") == tag, f"Release tag mismatch: {rel.get('tag_name')} != {tag}"
assets = {a["name"] for a in rel.get("assets", [])}
required = {"audren.so", "audren.so.sha256", "audren.codama.json", "audren.anchor.json", "security.json"}
missing = required - assets
if missing:
    sys.exit(f"GitHub Release {tag} missing required assets: {sorted(missing)}")
print(f"Verified GitHub Release {tag} ({rel.get('html_url')}) with all {len(required)} release assets.")
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
    COMMIT_SHA="$(resolve_verified_commit "$COMMIT_ARG")"
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

    SOLANA_BIN="$(resolve_solana_cli)"
    TOTAL_STEPS=3
    if [[ "$CLUSTER" == "mainnet" ]]; then
      TOTAL_STEPS=4
    fi
    echo "Step 1/${TOTAL_STEPS}: Upgrading $PROGRAM_ID on $CLUSTER (using $SOLANA_BIN)..."
    "$SOLANA_BIN" program deploy "$SO_PATH" \
      --program-id "$PROGRAM_ID" \
      --upgrade-authority "$KEYPAIR" \
      --keypair "$KEYPAIR" \
      --url "$RPC_URL"

    echo "Step 2/${TOTAL_STEPS}: Syncing canonical Program Metadata (security + idl) on $CLUSTER..."
    publish_security "$CLUSTER" "$RPC_URL"
    publish_idl "$CLUSTER" "$RPC_URL"

    if [[ "$CLUSTER" == "mainnet" && "${ALLOW_UNVERIFIED_DEPLOY:-0}" != "1" ]]; then
      echo "Step 3/${TOTAL_STEPS}: Updating Verified Build PDA & triggering remote attestation on Mainnet..."
      verify_onchain_build "$CLUSTER" "$RPC_URL" "$COMMIT_SHA"
      echo "Step 4/${TOTAL_STEPS}: Tagging & publishing GitHub Release..."
      publish_github_release "$COMMIT_SHA"
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
